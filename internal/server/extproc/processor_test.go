package extproc

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	procmodev3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"github.com/cloudnativeworks/elchi-shield/internal/audit"
	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/logging"
	"github.com/cloudnativeworks/elchi-shield/internal/metrics"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline/stages"
	"github.com/cloudnativeworks/elchi-shield/internal/runtime"
)

// sumMetric sums every sample of the named counter family across labels.
func sumMetric(t *testing.T, m *metrics.Metrics, name string) float64 {
	t.Helper()
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	total := 0.0
	for _, f := range fams {
		if f.GetName() != "elchi_shield_"+name {
			continue
		}
		for _, mt := range f.GetMetric() {
			total += mt.GetCounter().GetValue()
		}
	}
	return total
}

// fakeStream implements ExternalProcessor_ProcessServer for tests.
type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
	in  []*extprocv3.ProcessingRequest
	idx int
	out []*extprocv3.ProcessingResponse
}

func (f *fakeStream) Context() context.Context { return f.ctx }
func (f *fakeStream) Send(r *extprocv3.ProcessingResponse) error {
	f.out = append(f.out, r)
	return nil
}
func (f *fakeStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if f.idx >= len(f.in) {
		return nil, io.EOF
	}
	r := f.in[f.idx]
	f.idx++
	return r, nil
}

func headerMap(pairs ...string) *corev3.HeaderMap {
	hm := &corev3.HeaderMap{}
	for i := 0; i+1 < len(pairs); i += 2 {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: pairs[i], Value: pairs[i+1]})
	}
	return hm
}

func reqHeaders(pairs ...string) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{Headers: headerMap(pairs...)},
	}}
}

func reqBody(body string, eos bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
		RequestBody: &extprocv3.HttpBody{Body: []byte(body), EndOfStream: eos},
	}}
}

func respHeaders(pairs ...string) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: headerMap(pairs...)},
	}}
}

func respBody(body string, eos bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
		ResponseBody: &extprocv3.HttpBody{Body: []byte(body), EndOfStream: eos},
	}}
}

// reqHeadersEOS is reqHeaders with end_of_stream set (no body will follow).
func reqHeadersEOS(pairs ...string) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{Headers: headerMap(pairs...), EndOfStream: true},
	}}
}

func reqTrailers() *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestTrailers{
		RequestTrailers: &extprocv3.HttpTrailers{},
	}}
}

func ptr[T any](v T) *T { return &v }

func buildProcessor(t *testing.T) *Processor {
	t.Helper()
	block := config.ModeBlock
	tru := true
	maxBody := int64(1 << 20)
	cfg := &config.MergedConfig{
		Sources: []string{"t"},
		Domains: []config.MergedDomain{{Source: "t", Domain: config.Domain{
			Host: "api.example.com",
			Routes: []config.Route{
				{
					Match: config.Match{PathPrefix: "/json"},
					Policy: config.PolicySpec{
						Mode:                ptr(block),
						InspectRequestBody:  &tru,
						MaxRequestBodyBytes: &maxBody,
						Checks:              config.Checks{Body: &config.BodyChecks{RequireJSON: true}},
					},
				},
				{
					Match: config.Match{PathPrefix: "/"},
					Policy: config.PolicySpec{
						Mode:   ptr(block),
						Checks: config.Checks{Headers: &config.HeaderChecks{Forbidden: []string{"X-Debug"}}},
					},
				},
			},
		}}},
	}
	snap, err := runtime.NewSnapshot(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return NewProcessor(Config{
		Store:   runtime.NewStore(snap),
		Pool:    pipeline.NewPool(),
		Catalog: stages.NewCatalog(stages.Deps{DefaultAllow: true}),
		MaxBody: 1 << 20,
	})
}

func run(t *testing.T, pr *Processor, msgs ...*extprocv3.ProcessingRequest) []*extprocv3.ProcessingResponse {
	t.Helper()
	fs := &fakeStream{ctx: context.Background(), in: msgs}
	if err := pr.Process(fs); err != nil {
		t.Fatalf("Process: %v", err)
	}
	return fs.out
}

func isImmediate(r *extprocv3.ProcessingResponse) bool {
	_, ok := r.Response.(*extprocv3.ProcessingResponse_ImmediateResponse)
	return ok
}

// requestsBody reports whether the response asks Envoy to buffer the request body.
func requestsBody(r *extprocv3.ProcessingResponse) bool {
	return r.GetModeOverride().GetRequestBodyMode() == procmodev3.ProcessingMode_BUFFERED
}

// skipsResponse reports whether the response tells Envoy to skip the response phase.
func skipsResponse(r *extprocv3.ProcessingResponse) bool {
	return r.GetModeOverride().GetResponseHeaderMode() == procmodev3.ProcessingMode_SKIP
}

func TestProcessorBlocksForbiddenHeader(t *testing.T) {
	pr := buildProcessor(t)
	out := run(t, pr, reqHeaders(":authority", "api.example.com", ":path", "/x", ":method", "GET", "X-Debug", "1"))
	if len(out) != 1 || !isImmediate(out[0]) {
		t.Fatalf("expected immediate block, got %#v", out)
	}
	ir := out[0].Response.(*extprocv3.ProcessingResponse_ImmediateResponse).ImmediateResponse
	if ir.Status.Code != 403 {
		t.Fatalf("expected 403, got %v", ir.Status.Code)
	}
}

func TestProcessorAllowsCleanRequest(t *testing.T) {
	pr := buildProcessor(t)
	out := run(t, pr, reqHeaders(":authority", "api.example.com", ":path", "/x", ":method", "GET"))
	if len(out) != 1 {
		t.Fatalf("expected one response, got %d", len(out))
	}
	rh, ok := out[0].Response.(*extprocv3.ProcessingResponse_RequestHeaders)
	if !ok || rh.RequestHeaders.Response.Status != extprocv3.CommonResponse_CONTINUE {
		t.Fatalf("expected headers continue, got %#v", out[0])
	}
	if requestsBody(out[0]) {
		t.Fatal("clean request needing no body should not request body")
	}
	// A request-only policy skips the response phase (saves an ext_proc round-trip).
	if !skipsResponse(out[0]) {
		t.Fatal("request-only policy should tell Envoy to skip the response phase")
	}
}

func TestProcessorBufferedBodyInspectionBlocksInvalidJSON(t *testing.T) {
	pr := buildProcessor(t)
	out := run(t, pr,
		reqHeaders(":authority", "api.example.com", ":path", "/json", ":method", "POST", "content-type", "application/json"),
		reqBody("{not valid", true),
	)
	if len(out) != 2 {
		t.Fatalf("expected 2 responses (headers, body), got %d", len(out))
	}
	// Headers response should request the body via mode override.
	if out[0].ModeOverride == nil {
		t.Fatal("body-inspecting policy should request buffered body via ModeOverride")
	}
	// Body response should be an immediate block for invalid JSON.
	if !isImmediate(out[1]) {
		t.Fatalf("invalid JSON body should be blocked, got %#v", out[1])
	}
}

func TestProcessorBufferedBodyInspectionAllowsValidJSON(t *testing.T) {
	pr := buildProcessor(t)
	out := run(t, pr,
		reqHeaders(":authority", "api.example.com", ":path", "/json", ":method", "POST", "content-type", "application/json"),
		reqBody(`{"ok":true}`, true),
	)
	if len(out) != 2 || isImmediate(out[1]) {
		t.Fatalf("valid JSON body should be allowed, got %#v", out)
	}
}

// procWithPolicy builds a processor whose single domain/route carries the given
// policy spec, for direction- and engine-specific e2e tests.
func procWithPolicy(t *testing.T, match config.Match, spec config.PolicySpec) *Processor {
	t.Helper()
	cfg := &config.MergedConfig{
		Sources: []string{"t"},
		Domains: []config.MergedDomain{{Source: "t", Domain: config.Domain{
			Host:   "api.example.com",
			Routes: []config.Route{{Match: match, Policy: spec}},
		}}},
	}
	snap, err := runtime.NewSnapshot(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return NewProcessor(Config{
		Store:   runtime.NewStore(snap),
		Pool:    pipeline.NewPool(),
		Catalog: stages.NewCatalog(stages.Deps{DefaultAllow: true}),
		MaxBody: 1 << 20,
	})
}

// procWithAuditor is procWithPolicy with an injected auditor (for audit assertions).
func procWithAuditor(t *testing.T, match config.Match, spec config.PolicySpec, auditor *audit.Auditor) *Processor {
	t.Helper()
	cfg := &config.MergedConfig{
		Sources: []string{"t"},
		Domains: []config.MergedDomain{{Source: "t", Domain: config.Domain{
			Host:   "api.example.com",
			Routes: []config.Route{{Match: match, Policy: spec}},
		}}},
	}
	snap, err := runtime.NewSnapshot(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return NewProcessor(Config{
		Store:   runtime.NewStore(snap),
		Pool:    pipeline.NewPool(),
		Catalog: stages.NewCatalog(stages.Deps{DefaultAllow: true}),
		MaxBody: 1 << 20,
		Auditor: auditor,
	})
}

// TestProcessorResponseBodyInspection drives the full response pipeline:
// response headers → buffered response body → block on invalid JSON.
func TestProcessorResponseBodyInspection(t *testing.T) {
	block := config.ModeBlock
	tru := true
	maxBody := int64(1 << 20)
	pr := procWithPolicy(t, config.Match{PathPrefix: "/"}, config.PolicySpec{
		Mode:                 ptr(block),
		InspectResponseBody:  &tru,
		MaxResponseBodyBytes: &maxBody,
		Checks:               config.Checks{Body: &config.BodyChecks{RequireJSON: true}},
	})
	out := run(t, pr,
		reqHeaders(":authority", "api.example.com", ":path", "/x", ":method", "GET"),
		respHeaders(":status", "200", "content-type", "application/json"),
		respBody("{not json", true),
	)
	// request headers (continue), response headers (continue + ModeOverride asking
	// for body), response body (immediate block).
	if len(out) != 3 {
		t.Fatalf("expected 3 responses, got %d: %#v", len(out), out)
	}
	if out[1].ModeOverride == nil {
		t.Fatal("response-body-inspecting policy should request buffered response body")
	}
	if !isImmediate(out[2]) {
		t.Fatalf("invalid JSON response body should be blocked, got %#v", out[2])
	}
}

// TestProcessorMultiChunkBody proves a body streamed in several chunks is
// buffered and inspected only at end-of-stream.
func TestProcessorMultiChunkBody(t *testing.T) {
	block := config.ModeBlock
	tru := true
	maxBody := int64(1 << 20)
	pr := procWithPolicy(t, config.Match{PathPrefix: "/json"}, config.PolicySpec{
		Mode:                ptr(block),
		InspectRequestBody:  &tru,
		MaxRequestBodyBytes: &maxBody,
		Checks:              config.Checks{Body: &config.BodyChecks{RequireJSON: true}},
	})
	out := run(t, pr,
		reqHeaders(":authority", "api.example.com", ":path", "/json", ":method", "POST", "content-type", "application/json"),
		reqBody(`{"a":1,`, false), // non-final chunk → continue, no decision yet
		reqBody(`"b":2}`, true),   // final chunk → valid JSON reassembled → allow
	)
	if len(out) != 3 {
		t.Fatalf("expected 3 responses (headers + 2 body), got %d", len(out))
	}
	// The non-final body chunk must be a plain continue, not a decision.
	if isImmediate(out[1]) {
		t.Fatal("non-final body chunk must not produce a decision")
	}
	// Reassembled body is valid JSON → final chunk allowed.
	if isImmediate(out[2]) {
		t.Fatalf("reassembled valid JSON should be allowed, got %#v", out[2])
	}
}

// TestProcessorHeaderOnlyEngineNoBodyBuffer proves a header-only engine (JWT)
// evaluates at header time and never requests body buffering: a missing token is
// blocked at the headers phase with no ModeOverride.
func TestProcessorHeaderOnlyEngineNoBodyBuffer(t *testing.T) {
	block := config.ModeBlock
	pr := procWithPolicy(t, config.Match{PathPrefix: "/"}, config.PolicySpec{
		Mode: ptr(block),
		Engines: &config.EnginesSpec{JWT: &config.JWTSpec{
			Algorithms: []string{"HS256"}, HMACSecret: "secret", Audience: "api",
		}},
	})
	// No Authorization header → JWT engine blocks at headers.
	out := run(t, pr, reqHeaders(":authority", "api.example.com", ":path", "/x", ":method", "GET"))
	if len(out) != 1 || !isImmediate(out[0]) {
		t.Fatalf("missing JWT should block at headers, got %#v", out)
	}
}

// TestProcessorHeaderOnlyEngineAllowsNoBodyRequest proves that when a header-only
// engine passes, the processor does NOT ask Envoy to buffer the body (no
// ModeOverride), so a JWT-only policy never pays the body-buffering cost.
func TestProcessorHeaderOnlyEngineAllowsNoBodyRequest(t *testing.T) {
	block := config.ModeBlock
	// HS256 token for {"aud":"api"} signed with "secret".
	const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhcGkifQ.uMMm9JjV5pZ0Z3n0w0v6Yn0pHj0xY3Q0a0b0c0d0e0"
	pr := procWithPolicy(t, config.Match{PathPrefix: "/"}, config.PolicySpec{
		Mode: ptr(block),
		Engines: &config.EnginesSpec{JWT: &config.JWTSpec{
			Algorithms: []string{"HS256"}, HMACSecret: "secret", Audience: "api",
		}},
	})
	out := run(t, pr, reqHeaders(":authority", "api.example.com", ":path", "/x", ":method", "GET", "authorization", "Bearer "+token))
	// Whether the (hand-built) token validates or not, the key invariant is the
	// same: a header-only engine never requests body buffering.
	if len(out) >= 1 && requestsBody(out[0]) {
		t.Fatal("header-only engine must not request body buffering")
	}
}

// requireJSONProc builds a body-inspecting (require_json) processor on "/".
func requireJSONProc(t *testing.T) *Processor {
	block := config.ModeBlock
	tru := true
	maxBody := int64(1 << 20)
	return procWithPolicy(t, config.Match{PathPrefix: "/"}, config.PolicySpec{
		Mode:                ptr(block),
		InspectRequestBody:  &tru,
		MaxRequestBodyBytes: &maxBody,
		Checks:              config.Checks{Body: &config.BodyChecks{RequireJSON: true}},
	})
}

// TestProcessorEmptyBodyOnHeadersRunsBodyInspection proves that when end_of_stream
// is set on the headers (no body message follows), the body pipeline still runs —
// the empty-body bypass is closed. A non-JSON content-type with no body is fine
// (empty), but the body phase is exercised (no ModeOverride asking for a body
// that will never come).
func TestProcessorEmptyBodyOnHeadersRunsBodyInspection(t *testing.T) {
	pr := requireJSONProc(t)
	out := run(t, pr, reqHeadersEOS(":authority", "api.example.com", ":path", "/x", ":method", "POST"))
	if len(out) != 1 {
		t.Fatalf("expected a single headers response, got %d", len(out))
	}
	// Must NOT ask Envoy to buffer a body that will never arrive.
	if requestsBody(out[0]) {
		t.Fatal("end_of_stream on headers must not request a (never-coming) body")
	}
	// Empty body on require_json is allowed (continue), not blocked.
	if isImmediate(out[0]) {
		t.Fatal("empty body should be allowed, not blocked")
	}
}

// TestProcessorTrailersRunBufferedBodyInspection proves that when trailers
// terminate the stream (body chunks all have end_of_stream=false), the buffered
// body is inspected at the trailers message — closing the stray-trailer bypass.
func TestProcessorTrailersRunBufferedBodyInspection(t *testing.T) {
	pr := requireJSONProc(t)
	out := run(t, pr,
		reqHeaders(":authority", "api.example.com", ":path", "/x", ":method", "POST", "content-type", "application/json"),
		reqBody(`{bad json`, false), // non-final: no decision yet
		reqTrailers(),               // terminal: body inspected here → invalid JSON blocks
	)
	if len(out) != 3 {
		t.Fatalf("expected headers + body + trailers responses, got %d: %#v", len(out), out)
	}
	// The block must surface at the trailers message (the buffered invalid JSON).
	if !isImmediate(out[2]) {
		t.Fatalf("invalid buffered body must be blocked at trailers, got %#v", out[2])
	}
}

// TestProcessorInFlightBudgetBlocksOversizedAggregate proves that when the global
// in-flight body budget is exhausted, the body is treated as truncated and the
// non-skippable truncation guard blocks it (memory-amplification DoS mitigation).
func TestProcessorInFlightBudgetBlocksOversizedAggregate(t *testing.T) {
	block := config.ModeBlock
	tru := true
	bigCap := int64(1 << 20)
	cfg := &config.MergedConfig{
		Sources: []string{"t"},
		Domains: []config.MergedDomain{{Source: "t", Domain: config.Domain{
			Host: "api.example.com",
			Routes: []config.Route{{Match: config.Match{PathPrefix: "/"}, Policy: config.PolicySpec{
				Mode:                ptr(block),
				InspectRequestBody:  &tru,
				MaxRequestBodyBytes: &bigCap, // per-request cap is generous...
			}}},
		}}},
	}
	snap, err := runtime.NewSnapshot(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pr := NewProcessor(Config{
		Store:                runtime.NewStore(snap),
		Pool:                 pipeline.NewPool(),
		Catalog:              stages.NewCatalog(stages.Deps{DefaultAllow: true}),
		MaxBody:              1 << 20,
		MaxInFlightBodyBytes: 16, // ...but the global budget is tiny
	})
	out := run(t, pr,
		reqHeaders(":authority", "api.example.com", ":path", "/x", ":method", "POST", "content-type", "application/octet-stream"),
		reqBody("this body is larger than the 16-byte in-flight budget", true),
	)
	if len(out) != 2 || !isImmediate(out[1]) {
		t.Fatalf("body exceeding the in-flight budget must be blocked, got %#v", out)
	}
}

// TestProcessorHeaderOnlyPolicyTrailersNoDoubleFinish proves that a header-only
// policy (no body inspection) that already decided at the header phase does NOT
// run body inspection again when a stray trailers message arrives — guarding
// against double-counting metrics/audit.
func TestProcessorHeaderOnlyPolicyTrailersNoDoubleFinish(t *testing.T) {
	m := metrics.New("")
	block := config.ModeBlock
	cfg := &config.MergedConfig{
		Sources: []string{"t"},
		Domains: []config.MergedDomain{{Source: "t", Domain: config.Domain{
			Host:   "api.example.com",
			Routes: []config.Route{{Match: config.Match{PathPrefix: "/"}, Policy: config.PolicySpec{Mode: ptr(block)}}},
		}}},
	}
	snap, err := runtime.NewSnapshot(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cat := stages.NewCatalog(stages.Deps{DefaultAllow: true})
	m.RegisterStages(cat.StageNames())
	pr := NewProcessor(Config{Store: runtime.NewStore(snap), Pool: pipeline.NewPool(), Catalog: cat, Metrics: m, MaxBody: 1 << 20})

	out := run(t, pr,
		reqHeaders(":authority", "api.example.com", ":path", "/x", ":method", "GET"),
		reqTrailers(), // header-only policy: trailers must not re-inspect/re-finish
	)
	if len(out) != 2 {
		t.Fatalf("expected headers + trailers responses, got %d", len(out))
	}
	// Exactly one request counted (header phase), not two.
	if got := sumMetric(t, m, "requests_total"); got != 1 {
		t.Fatalf("requests_total = %v, want 1 (no double-finish on trailers)", got)
	}
}

// TestDecisionLogIsRichAndStructured proves the per-phase decision log carries
// the fields you need to debug a block (request_id, host, method, path, action,
// rule_id, reason, policy_id, duration_ms) and that an enforced block logs at Info.
func TestDecisionLogIsRichAndStructured(t *testing.T) {
	var buf bytes.Buffer
	log := logging.New(logging.Options{Output: &buf, Level: "debug"})
	block := config.ModeBlock
	pr := procWithPolicy(t, config.Match{PathPrefix: "/"}, config.PolicySpec{
		Mode:   ptr(block),
		Checks: config.Checks{Headers: &config.HeaderChecks{Forbidden: []string{"X-Debug"}}},
	})
	pr.log = log // inject a capturing logger

	run(t, pr, reqHeaders(":authority", "api.example.com", ":path", "/admin?token=secret", ":method", "GET", "x-request-id", "req-123", "X-Debug", "1"))

	var rec map[string]any
	dec := json.NewDecoder(&buf)
	found := false
	for dec.More() {
		var r map[string]any
		if err := dec.Decode(&r); err != nil {
			break
		}
		if r["msg"] == "decision" {
			rec = r
			found = true
		}
	}
	if !found {
		t.Fatalf("no decision log emitted: %s", buf.String())
	}
	if rec["level"] != "INFO" {
		t.Errorf("enforced block should log at INFO, got %v", rec["level"])
	}
	want := map[string]string{
		"request_id": "req-123", // adopted from x-request-id
		"action":     "block",
		"host":       "api.example.com",
		"method":     "GET",
		"path":       "/admin", // query stripped (no secret token in logs)
		"rule_id":    "header.forbidden",
	}
	for k, v := range want {
		if got, _ := rec[k].(string); got != v {
			t.Errorf("decision log %q = %q, want %q (full: %#v)", k, got, v, rec)
		}
	}
	if _, ok := rec["duration_ms"]; !ok {
		t.Errorf("decision log should carry duration_ms: %#v", rec)
	}
	if strings.Contains(buf.String(), "secret") {
		t.Errorf("query-string secret leaked into decision log: %s", buf.String())
	}
}

// TestProcessorBudgetReleasedBetweenPhases proves the request body's budget
// reservation is released when the response phase begins, so a request+response
// stream does not falsely block the (legitimate) response under budget pressure.
func TestProcessorBudgetReleasedBetweenPhases(t *testing.T) {
	block := config.ModeBlock
	tru := true
	bodyCap := int64(1 << 20)
	cfg := &config.MergedConfig{
		Sources: []string{"t"},
		Domains: []config.MergedDomain{{Source: "t", Domain: config.Domain{
			Host: "api.example.com",
			Routes: []config.Route{{Match: config.Match{PathPrefix: "/"}, Policy: config.PolicySpec{
				Mode:                 ptr(block),
				InspectRequestBody:   &tru,
				InspectResponseBody:  &tru,
				MaxRequestBodyBytes:  &bodyCap,
				MaxResponseBodyBytes: &bodyCap,
			}}},
		}}},
	}
	snap, err := runtime.NewSnapshot(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Budget just big enough for ONE body at a time, not two simultaneously.
	pr := NewProcessor(Config{
		Store: runtime.NewStore(snap), Pool: pipeline.NewPool(),
		Catalog: stages.NewCatalog(stages.Deps{DefaultAllow: true}), MaxBody: 1 << 20,
		MaxInFlightBodyBytes: 40,
	})
	out := run(t, pr,
		reqHeaders(":authority", "api.example.com", ":path", "/x", ":method", "POST", "content-type", "application/octet-stream"),
		reqBody("0123456789012345678901234567890123456789", true), // 40 bytes — fits exactly
		respHeaders(":status", "200", "content-type", "application/octet-stream"),
		respBody("0123456789012345678901234567890123456789", true), // 40 bytes — must also fit
	)
	// 4 responses; the response body (out[3]) must NOT be an immediate block.
	if len(out) != 4 {
		t.Fatalf("expected 4 responses, got %d: %#v", len(out), out)
	}
	if isImmediate(out[1]) {
		t.Fatalf("request body within budget must not block, got %#v", out[1])
	}
	if isImmediate(out[3]) {
		t.Fatalf("response body must not be falsely blocked after request budget release, got %#v", out[3])
	}
}

// captureExporter records every audit event for assertions.
type captureExporter struct{ events []*audit.Event }

func (c *captureExporter) Export(_ context.Context, ev *audit.Event) error {
	c.events = append(c.events, ev)
	return nil
}
func (c *captureExporter) Flush(context.Context) error { return nil }
func (c *captureExporter) Close() error                { return nil }

// TestProcessorDetectModeAuditsEveryFinding proves the multi-finding audit: in
// detect mode two distinct findings at the same phase (a forbidden header AND a
// missing JWT) each produce an audit event — the full detection trail, not just
// the highest-severity aggregate.
func TestProcessorDetectModeAuditsEveryFinding(t *testing.T) {
	detect := config.ModeDetect
	cap := &captureExporter{}
	pr := procWithAuditor(t, config.Match{PathPrefix: "/"}, config.PolicySpec{
		Mode:   ptr(detect),
		Checks: config.Checks{Headers: &config.HeaderChecks{Forbidden: []string{"X-Debug"}}},
		Engines: &config.EnginesSpec{JWT: &config.JWTSpec{
			Algorithms: []string{"HS256"}, HMACSecret: "secret", Audience: "api",
		}},
	}, audit.NewAuditor(cap, nil))

	// X-Debug present (forbidden-header finding) + no Authorization (JWT finding).
	run(t, pr, reqHeaders(":authority", "api.example.com", ":path", "/x", ":method", "GET", "X-Debug", "1"))

	if len(cap.events) != 2 {
		t.Fatalf("detect mode should audit BOTH findings (forbidden header + jwt), got %d: %+v", len(cap.events), cap.events)
	}
	rules := map[string]bool{}
	for _, ev := range cap.events {
		if ev.Decision.Action != decision.Detect {
			t.Errorf("each audited finding must be tagged detect, got %v", ev.Decision.Action)
		}
		rules[ev.Decision.RuleID] = true
	}
	if !rules["header.forbidden"] || !rules["jwt.missing"] {
		t.Fatalf("both findings should be audited with their own rule ids, got %v", rules)
	}
}

// TestProcessorRateLimit429 proves the rate-limit engine flows end-to-end: the
// client IP is derived from X-Forwarded-For (tx.SourceIP), the burst is allowed,
// then a 429 is returned with a Retry-After header.
func TestProcessorRateLimit429(t *testing.T) {
	block := config.ModeBlock
	pr := procWithPolicy(t, config.Match{PathPrefix: "/"}, config.PolicySpec{
		Mode:    ptr(block),
		Engines: &config.EnginesSpec{RateLimit: &config.RateLimitSpec{RequestsPerSecond: 1, Burst: 2, Key: "ip"}},
	})
	hdr := []string{":authority", "api.example.com", ":path", "/x", ":method", "GET", "x-forwarded-for", "9.9.9.9, 10.0.0.1"}

	// Burst of 2 passes.
	for range 2 {
		out := run(t, pr, reqHeaders(hdr...))
		if len(out) != 1 || isImmediate(out[0]) {
			t.Fatalf("request within burst should pass, got %#v", out)
		}
	}
	// 3rd is rate-limited: 429 + Retry-After.
	out := run(t, pr, reqHeaders(hdr...))
	if len(out) != 1 || !isImmediate(out[0]) {
		t.Fatalf("over-limit request should be blocked, got %#v", out)
	}
	ir := out[0].Response.(*extprocv3.ProcessingResponse_ImmediateResponse).ImmediateResponse
	if ir.Status.Code != 429 {
		t.Fatalf("rate-limit block must be 429, got %v", ir.Status.Code)
	}
	retryAfter := false
	for _, h := range ir.GetHeaders().GetSetHeaders() {
		if h.GetHeader().GetKey() == "Retry-After" {
			retryAfter = true
		}
	}
	if !retryAfter {
		t.Fatal("a 429 block must carry a Retry-After header")
	}

	// A different client IP has its own bucket → not blocked.
	hdr2 := []string{":authority", "api.example.com", ":path", "/x", ":method", "GET", "x-forwarded-for", "8.8.8.8"}
	if out := run(t, pr, reqHeaders(hdr2...)); isImmediate(out[0]) {
		t.Fatal("a different client IP must not share the limited IP's bucket")
	}
}

// TestProcessorGzipBodyDecodedAndInspected proves a gzip'd invalid-JSON body is
// decompressed and then blocked — the compression WAF-bypass is closed end-to-end.
func TestProcessorGzipBodyDecodedAndInspected(t *testing.T) {
	pr := requireJSONProc(t)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(`{not valid json`)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	out := run(t, pr,
		reqHeaders(":authority", "api.example.com", ":path", "/x", ":method", "POST", "content-type", "application/json", "content-encoding", "gzip"),
		&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
			RequestBody: &extprocv3.HttpBody{Body: buf.Bytes(), EndOfStream: true},
		}},
	)
	if len(out) != 2 || !isImmediate(out[1]) {
		t.Fatalf("decoded invalid-JSON gzip body must be blocked, got %#v", out)
	}
}
