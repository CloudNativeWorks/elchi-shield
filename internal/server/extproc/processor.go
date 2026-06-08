package extproc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	procmodev3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cloudnativeworks/elchi-shield/internal/audit"
	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/logging"
	"github.com/cloudnativeworks/elchi-shield/internal/metrics"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline/stages"
	"github.com/cloudnativeworks/elchi-shield/internal/policy"
	"github.com/cloudnativeworks/elchi-shield/internal/runtime"
)

// Config configures a Processor.
type Config struct {
	Store      *runtime.Store
	Pool       *pipeline.Pool
	Catalog    *stages.Catalog
	Logger     *slog.Logger
	Metrics    *metrics.Metrics // nil-safe; observability off when nil
	Auditor    *audit.Auditor   // nil → no audit emission
	InstanceID string           // identity stamped on audit events (e.g. host-shield)
	ListenerID string           // Envoy listener this instance serves (optional)
	MaxBody    int64            // fallback body cap when policy has none (>0)
	// MaxInFlightBodyBytes caps total body bytes buffered across all concurrent
	// streams (0 = unbounded). Use NewManager to share one budget across listeners.
	MaxInFlightBodyBytes int64
	// budget is the shared in-flight body-byte budget. When nil, NewProcessor
	// builds one from MaxInFlightBodyBytes; NewManager injects a shared instance.
	budget *bodyBudget
	// streams is the shared in-flight stream counter (set by NewManager) for the
	// streams_in_flight gauge. May be nil (single-processor/test path).
	streams *atomic.Int64
}

// Processor implements the Envoy ext_proc ExternalProcessor service. One stream
// corresponds to one HTTP transaction; the active runtime snapshot is pinned at
// stream start so a mid-stream config reload never tears a decision.
type Processor struct {
	extprocv3.UnimplementedExternalProcessorServer

	store      *runtime.Store
	pool       *pipeline.Pool
	catalog    *stages.Catalog
	log        *slog.Logger
	metrics    *metrics.Metrics
	lm         *metrics.ListenerMetrics
	auditor    *audit.Auditor
	instanceID string
	listenerID string
	maxBody    int64
	budget     *bodyBudget
	streams    *atomic.Int64
}

// NewProcessor builds a Processor from cfg. MaxBody defaults to 1 MiB when unset.
func NewProcessor(cfg Config) *Processor {
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 1 << 20
	}
	budget := cfg.budget
	if budget == nil {
		budget = newBodyBudget(cfg.MaxInFlightBodyBytes)
	}
	return &Processor{
		store:      cfg.Store,
		pool:       cfg.Pool,
		catalog:    cfg.Catalog,
		log:        cfg.Logger,
		metrics:    cfg.Metrics,
		lm:         cfg.Metrics.ForListener(cfg.ListenerID),
		auditor:    cfg.Auditor,
		instanceID: cfg.InstanceID,
		listenerID: cfg.ListenerID,
		maxBody:    cfg.MaxBody,
		budget:     budget,
		streams:    cfg.streams,
	}
}

// Process is the bidirectional ext_proc stream handler. It recovers any panic
// (in our code or a third-party engine like Coraza/JWT) so a single bad stream
// can never crash the process or take down the other listeners.
func (pr *Processor) Process(stream extprocv3.ExternalProcessor_ProcessServer) (err error) {
	defer func() {
		if r := recover(); r != nil {
			pr.metrics.RecordExtprocError("panic")
			if pr.log != nil {
				pr.log.Error("panic recovered in ext_proc stream",
					logging.KeyListener, pr.listenerID,
					"panic", r,
					"stack", string(debug.Stack()))
			}
			err = status.Errorf(codes.Internal, "internal error")
		}
	}()

	ctx := stream.Context()

	if pr.streams != nil {
		pr.streams.Add(1)
		defer pr.streams.Add(-1)
	}

	tx := pr.pool.Acquire()
	defer pr.pool.Release(tx)
	// Release this stream's body-budget reservation before the Transaction is
	// reset (defers run LIFO, so this runs before pool.Release).
	defer func() { pr.budget.Release(tx.BodyReserved()) }()
	tx.SetBudget(pr.budget)       // lets the decode stage charge decoded bytes
	tx.Snapshot = pr.store.Load() // pin for the whole stream
	tx.RequestID = newRequestID()
	tx.ListenerID = pr.listenerID

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			pr.metrics.RecordExtprocError("transport")
			return err
		}

		resp := pr.handle(ctx, tx, req)
		if resp == nil {
			continue
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// handle dispatches one ProcessingRequest to the right phase handler.
func (pr *Processor) handle(ctx context.Context, tx *pipeline.Transaction, req *extprocv3.ProcessingRequest) *extprocv3.ProcessingResponse {
	switch v := req.Request.(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		return pr.onRequestHeaders(ctx, tx, v.RequestHeaders)
	case *extprocv3.ProcessingRequest_RequestBody:
		return pr.onRequestBody(ctx, tx, v.RequestBody)
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		return pr.onResponseHeaders(ctx, tx, v.ResponseHeaders)
	case *extprocv3.ProcessingRequest_ResponseBody:
		return pr.onResponseBody(ctx, tx, v.ResponseBody)
	case *extprocv3.ProcessingRequest_RequestTrailers:
		return pr.onRequestTrailers(ctx, tx)
	case *extprocv3.ProcessingRequest_ResponseTrailers:
		return pr.onResponseTrailers(ctx, tx)
	default:
		return nil
	}
}

func (pr *Processor) onRequestHeaders(ctx context.Context, tx *pipeline.Transaction, h *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	start := time.Now()
	tx.Direction = pipeline.DirectionRequest
	loadHeaders(tx, h.GetHeaders())

	// Adopt Envoy's x-request-id so a block in our logs/audit can be pivoted to
	// Envoy's access log and the upstream trace; fall back to the random id minted
	// at stream start when absent.
	if rid, ok := tx.Header("x-request-id"); ok && rid != "" {
		tx.RequestID = rid
	}

	// Fixed prelude: context init → policy resolve → early decision.
	d := pr.catalog.RequestPrelude().Run(ctx, tx)
	if d.IsBlock() {
		pr.finish(ctx, tx, d, "request_headers", start)
		return immediateResponse(d)
	}
	// No policy matched (default allow) or mode off → terminal allow.
	if tx.Policy == nil || !tx.Policy.Enforcing() {
		pr.finish(ctx, tx, d, "request_headers", start)
		return requestHeadersContinue(nil)
	}

	pp, perr := pr.policyPipelines(tx.Policy)
	if perr != nil {
		return pr.failBuild(ctx, tx, perr, "request_headers", start)
	}
	d = pr.runInspect(ctx, tx, pp.RequestHeader)
	if d.IsBlock() {
		pr.finish(ctx, tx, d, "request_headers", start)
		return immediateResponse(d)
	}
	if tx.BodyRequired() || tx.WAFEnabled() {
		// When end_of_stream is set on the headers message there is no body and
		// Envoy will send no body message (a GET, or Content-Length: 0). Run the
		// body pipeline now with the empty buffer so body-phase inspection (e.g.
		// Coraza request-body phase, truncation guard) is not silently skipped.
		if h.GetEndOfStream() {
			if bd := pr.inspectBufferedBody(ctx, tx, start); bd != nil && bd.IsBlock() {
				return immediateResponse(bd)
			}
			return requestHeadersContinue(nil)
		}
		return requestHeadersContinue(&procmodev3.ProcessingMode{RequestBodyMode: procmodev3.ProcessingMode_BUFFERED})
	}
	pr.finish(ctx, tx, d, "request_headers", start) // terminal allow at headers
	return requestHeadersContinue(nil)
}

// appendBody buffers chunk for inspection, charging the shared in-flight body
// budget first so total resident body memory stays bounded across all streams.
// A short budget grant (or hitting the per-request cap) marks the body truncated,
// so the non-skippable truncation guard blocks it rather than inspecting a
// partial body as clean.
func (pr *Processor) appendBody(tx *pipeline.Transaction, dir pipeline.Direction, chunk []byte) {
	if len(chunk) == 0 {
		return
	}
	grant := pr.budget.Acquire(int64(len(chunk)))
	if grant > 0 {
		stored, truncated := tx.AppendBody(chunk[:grant], pr.bodyLimit(tx, dir))
		tx.AddBodyReserved(int64(stored))
		if int64(stored) < grant { // per-request cap rejected some of the grant
			pr.budget.Release(grant - int64(stored))
		}
		if truncated {
			tx.SetBodyTruncated(true)
		}
	}
	if grant < int64(len(chunk)) { // global budget exhausted → treat as over-limit
		tx.SetBodyTruncated(true)
	}
}

func (pr *Processor) onRequestBody(ctx context.Context, tx *pipeline.Transaction, b *extprocv3.HttpBody) *extprocv3.ProcessingResponse {
	start := time.Now()
	pr.appendBody(tx, pipeline.DirectionRequest, b.GetBody())
	// Inspect only at the terminal chunk. When trailers terminate the stream the
	// final body chunk carries end_of_stream=false and onRequestTrailers runs the
	// inspection instead.
	if !b.GetEndOfStream() {
		return requestBodyContinue()
	}
	if bd := pr.inspectBufferedBody(ctx, tx, start); bd != nil && bd.IsBlock() {
		return immediateResponse(bd)
	}
	return requestBodyContinue()
}

func (pr *Processor) onRequestTrailers(ctx context.Context, tx *pipeline.Transaction) *extprocv3.ProcessingResponse {
	// Trailers carry end-of-stream when the request has HTTP trailers: the body
	// chunks all arrived with end_of_stream=false, so the buffered body must be
	// inspected here (otherwise a stray trailer bypasses body/WAF inspection).
	if bd := pr.inspectBufferedBody(ctx, tx, time.Now()); bd != nil && bd.IsBlock() {
		return immediateResponse(bd)
	}
	return requestTrailersContinue()
}

func (pr *Processor) onResponseHeaders(ctx context.Context, tx *pipeline.Transaction, h *extprocv3.HttpHeaders) *extprocv3.ProcessingResponse {
	start := time.Now()
	tx.BeginResponse()
	loadHeaders(tx, h.GetHeaders())

	d := pr.catalog.ResponsePrelude().Run(ctx, tx) // context init (derive content-type)
	if tx.Policy == nil || !tx.Policy.Enforcing() {
		pr.finish(ctx, tx, d, "response_headers", start)
		return responseHeadersContinue(nil)
	}

	pp, perr := pr.policyPipelines(tx.Policy)
	if perr != nil {
		return pr.failBuild(ctx, tx, perr, "response_headers", start)
	}
	d = pr.runInspect(ctx, tx, pp.ResponseHeader)
	if d.IsBlock() {
		pr.finish(ctx, tx, d, "response_headers", start)
		return immediateResponse(d)
	}
	if tx.BodyRequired() || tx.WAFEnabled() {
		if h.GetEndOfStream() { // no response body will follow
			if bd := pr.inspectBufferedBody(ctx, tx, start); bd != nil && bd.IsBlock() {
				return immediateResponse(bd)
			}
			return responseHeadersContinue(nil)
		}
		return responseHeadersContinue(&procmodev3.ProcessingMode{ResponseBodyMode: procmodev3.ProcessingMode_BUFFERED})
	}
	pr.finish(ctx, tx, d, "response_headers", start)
	return responseHeadersContinue(nil)
}

func (pr *Processor) onResponseBody(ctx context.Context, tx *pipeline.Transaction, b *extprocv3.HttpBody) *extprocv3.ProcessingResponse {
	start := time.Now()
	pr.appendBody(tx, pipeline.DirectionResponse, b.GetBody())
	if !b.GetEndOfStream() {
		return responseBodyContinue()
	}
	if bd := pr.inspectBufferedBody(ctx, tx, start); bd != nil && bd.IsBlock() {
		return immediateResponse(bd)
	}
	return responseBodyContinue()
}

func (pr *Processor) onResponseTrailers(ctx context.Context, tx *pipeline.Transaction) *extprocv3.ProcessingResponse {
	if bd := pr.inspectBufferedBody(ctx, tx, time.Now()); bd != nil && bd.IsBlock() {
		return immediateResponse(bd)
	}
	return responseTrailersContinue()
}

// runInspect runs an inspect pipeline, applying the policy's per-request timeout
// when set. The deadline is enforced at stage boundaries (the executor) and at
// engine boundaries (engine.Set.Inspect), where exceeding it triggers the fail
// posture (timeouts_total + fail-open/close). A single synchronous engine call
// is not preempted mid-flight — Go cannot interrupt CPU-bound work, and
// detaching it into a goroutine would let goroutines accumulate under load — so
// it runs to completion and backpressures the stream by design. Bodies are
// size-capped (MaxBodyBytes) and the bundled engines use linear-time (RE2)
// matching, so a single call is bounded in practice.
func (pr *Processor) runInspect(ctx context.Context, tx *pipeline.Transaction, p *pipeline.Pipeline) *decision.Decision {
	if tx.Policy != nil && tx.Policy.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, tx.Policy.Timeout)
		defer cancel()
	}
	return p.Run(ctx, tx)
}

// policyPipelines returns the per-policy inspect pipelines, building them once
// (lazily, cached on the policy) on first use.
func (pr *Processor) policyPipelines(p *policy.CompiledPolicy) (*stages.PolicyPipelines, error) {
	v, err := p.Compiled(func() (any, error) { return pr.catalog.BuildPolicyPipelines(p) })
	if err != nil {
		return nil, err
	}
	return v.(*stages.PolicyPipelines), nil
}

// failBuild handles the (config-validated-away, defensive) case where building a
// policy's pipelines fails: it applies the policy fail posture, shaping the
// response for the phase.
func (pr *Processor) failBuild(ctx context.Context, tx *pipeline.Transaction, err error, phase string, start time.Time) *extprocv3.ProcessingResponse {
	d := pr.failBuildDecision(ctx, tx, err, phase, start)
	if d.IsBlock() {
		return immediateResponse(d)
	}
	return continueFor(tx.Direction, phase)
}

// failBuildDecision records the fail-posture decision for a pipeline-build
// failure and returns it, leaving response shaping to the caller (so the same
// logic serves the headers, body, and trailers entry points).
func (pr *Processor) failBuildDecision(ctx context.Context, tx *pipeline.Transaction, err error, phase string, start time.Time) *decision.Decision {
	if pr.log != nil {
		pr.log.LogAttrs(ctx, slog.LevelError, "policy pipeline build failed",
			slog.String(logging.KeyPolicyID, tx.PolicyID()),
			slog.String(logging.KeyPhase, phase),
			logging.Err(err))
	}
	pr.metrics.RecordExtprocError("build")
	if tx.Policy != nil && !tx.Policy.FailOpen() {
		d := &decision.Decision{Action: decision.Block, Reason: "pipeline_build_failed", PolicyID: tx.PolicyID(), StatusCode: decision.DefaultBlockStatus}
		pr.finish(ctx, tx, d, phase, start)
		return d
	}
	allow := decision.Allowed(tx.PolicyID())
	pr.finish(ctx, tx, &allow, phase, start)
	return &allow
}

// inspectBufferedBody runs the body inspect pipeline for tx's current direction
// at most once (guarded by tx.BodyInspected), regardless of whether the terminal
// end-of-stream arrived on the headers, a body chunk, or the trailers message.
// It returns the decision, or nil when there is nothing to inspect. It is a no-op
// unless the body phase was actually requested (BodyRequired/WAFEnabled): a
// header-only policy already finished at the header phase, so a stray body or
// trailers message must NOT trigger a second finish (double-counting metrics/
// audit). A build failure is mapped to the fail posture.
func (pr *Processor) inspectBufferedBody(ctx context.Context, tx *pipeline.Transaction, start time.Time) *decision.Decision {
	if tx.Policy == nil || !tx.Policy.Enforcing() || tx.BodyInspected() {
		return nil
	}
	if !tx.BodyRequired() && !tx.WAFEnabled() {
		return nil // body phase not requested; header phase already recorded the decision
	}
	tx.SetBodyInspected(true)
	phase := "request_body"
	pipe := func(pp *stages.PolicyPipelines) *pipeline.Pipeline { return pp.RequestBody }
	if tx.Direction == pipeline.DirectionResponse {
		phase = "response_body"
		pipe = func(pp *stages.PolicyPipelines) *pipeline.Pipeline { return pp.ResponseBody }
	}
	pp, perr := pr.policyPipelines(tx.Policy)
	if perr != nil {
		return pr.failBuildDecision(ctx, tx, perr, phase, start)
	}
	d := pr.runInspect(ctx, tx, pipe(pp))
	pr.finish(ctx, tx, d, phase, start)
	return d
}

// continueFor returns the appropriate CONTINUE response for the phase.
func continueFor(dir pipeline.Direction, phase string) *extprocv3.ProcessingResponse {
	switch phase {
	case "request_headers":
		return requestHeadersContinue(nil)
	case "request_body":
		return requestBodyContinue()
	case "response_headers":
		return responseHeadersContinue(nil)
	default:
		return responseBodyContinue()
	}
}

// finish records the terminal decision for a phase: structured log, metrics, and
// a (sampled, redacted-by-construction) audit event.
func (pr *Processor) finish(ctx context.Context, tx *pipeline.Transaction, d *decision.Decision, phase string, start time.Time) {
	latency := time.Since(start)
	pr.logDecision(ctx, tx, d, phase, latency)
	pr.lm.RecordDecision(d, phase, latency)
	if tx.BodyRequired() {
		pr.lm.RecordBodyBytes(len(tx.Body()))
	}
	pr.emitAudit(ctx, tx, d, phase)
}

// emitAudit emits the phase's audit event(s). In detect/shadow mode the pipeline
// records every individual finding (tx.Findings); each is audited (always, no
// sampling) so the full detection trail is captured, not just the aggregate. A
// block (single short-circuited finding) and an allow (sampled) emit one event
// from the terminal decision.
func (pr *Processor) emitAudit(ctx context.Context, tx *pipeline.Transaction, d *decision.Decision, phase string) {
	if pr.auditor == nil || d == nil {
		return
	}
	// Detect/shadow: one event per recorded finding (findings are always audited).
	if findings := tx.Findings(); len(findings) > 0 {
		for i := range findings {
			pr.emitEvent(ctx, tx, &findings[i], phase)
		}
		return
	}
	// Block (a finding → always audit) or allow (per-policy sampled).
	finding := d.Action != decision.Allow && d.Action != decision.Continue
	if !finding {
		rate := 1.0
		if tx.Policy != nil {
			rate = tx.Policy.SamplingRate
		}
		if !audit.Sample(rate) {
			return
		}
	}
	pr.emitEvent(ctx, tx, d, phase)
}

// emitEvent builds and enqueues one audit event from a decision + tx context.
func (pr *Processor) emitEvent(ctx context.Context, tx *pipeline.Transaction, d *decision.Decision, phase string) {
	pr.auditor.Emit(ctx, &audit.Event{
		Timestamp:     time.Now(),
		Instance:      pr.instanceID,
		RequestID:     tx.RequestID,
		Phase:         phase,
		Direction:     tx.Direction.String(),
		Decision:      *d,
		Host:          tx.Host,
		Path:          stripQuery(tx.Path), // never audit query-string (may carry secrets)
		Method:        tx.Method,
		ConfigVersion: tx.Snapshot.Version(),
	})
}

// bodyLimit returns the byte cap for buffering in the given direction, preferring
// the policy limit and falling back to the server-wide cap.
func (pr *Processor) bodyLimit(tx *pipeline.Transaction, dir pipeline.Direction) int64 {
	if tx.Policy != nil {
		if dir == pipeline.DirectionRequest && tx.Policy.MaxRequestBodyBytes > 0 {
			return tx.Policy.MaxRequestBodyBytes
		}
		if dir == pipeline.DirectionResponse && tx.Policy.MaxResponseBodyBytes > 0 {
			return tx.Policy.MaxResponseBodyBytes
		}
	}
	return pr.maxBody
}

// logDecision emits the structured per-phase decision log — the line you read
// first when debugging "why did this request get this verdict?". Enforced blocks
// log at Info; allow/detect/shadow at Debug (so production at Info stays quiet).
// Reasons/rule-ids carry no request payload (the path is query-stripped), so this
// is safe without body redaction. Finding attribution (rule/engine/severity/
// status) is only attached when present, keeping plain allow lines clean.
func (pr *Processor) logDecision(ctx context.Context, tx *pipeline.Transaction, d *decision.Decision, phase string, latency time.Duration) {
	if pr.log == nil || d == nil {
		return
	}
	level := slog.LevelDebug
	if d.IsBlock() {
		level = slog.LevelInfo
	}
	// Skip building attrs entirely when the level is filtered (the common
	// allowed-at-Debug case in production), keeping the happy path cheap.
	if !pr.log.Enabled(ctx, level) {
		return
	}
	attrs := []slog.Attr{
		slog.String(logging.KeyRequestID, tx.RequestID),
		slog.String(logging.KeyListener, tx.ListenerID),
		slog.String(logging.KeyPhase, phase),
		slog.String(logging.KeyAction, d.Action.String()),
		slog.String(logging.KeyHost, tx.Host),
		slog.String(logging.KeyMethod, tx.Method),
		slog.String(logging.KeyPath, stripQuery(tx.Path)),
		slog.String(logging.KeyPolicyID, d.PolicyID),
		slog.Float64(logging.KeyDurationMs, float64(latency.Microseconds())/1000.0),
		slog.String(logging.KeyConfigVersion, tx.Snapshot.Version()),
	}
	if tx.ContentType != "" {
		attrs = append(attrs, slog.String("content_type", tx.ContentType))
	}
	if d.RuleID != "" {
		attrs = append(attrs, slog.String(logging.KeyRuleID, d.RuleID))
	}
	if d.Engine != "" {
		attrs = append(attrs, slog.String(logging.KeyEngine, d.Engine))
	}
	if d.Reason != "" {
		attrs = append(attrs, slog.String(logging.KeyReason, d.Reason))
	}
	if d.Severity != decision.SeverityNone {
		attrs = append(attrs, slog.String(logging.KeySeverity, d.Severity.String()))
	}
	if d.IsBlock() {
		code := d.StatusCode
		if code == 0 {
			code = decision.DefaultBlockStatus
		}
		attrs = append(attrs, slog.Int(logging.KeyStatusCode, code))
	}
	pr.log.LogAttrs(ctx, level, "decision", attrs...)
}

// stripQuery removes the query string from a path so secrets carried in query
// parameters (tokens, presigned URLs) never reach audit output.
func stripQuery(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

// loadHeaders copies an Envoy HeaderMap into the transaction's header slice,
// preferring Value and falling back to RawValue.
func loadHeaders(tx *pipeline.Transaction, hm *corev3.HeaderMap) {
	// Reset first so this is idempotent: a stream that (against protocol) delivers
	// a headers message twice replaces the header set rather than accumulating
	// duplicates.
	tx.Headers = tx.Headers[:0]
	if hm == nil {
		return
	}
	for _, h := range hm.GetHeaders() {
		val := h.GetValue()
		if val == "" && len(h.GetRawValue()) > 0 {
			val = string(h.GetRawValue())
		}
		tx.Headers = append(tx.Headers, pipeline.Header{Name: h.GetKey(), Value: val})
	}
}

// newRequestID returns a random 16-hex-char request id.
func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// immediateResponse builds a block (ImmediateResponse) from a decision.
func immediateResponse(d *decision.Decision) *extprocv3.ProcessingResponse {
	code := d.StatusCode
	if code == 0 {
		code = decision.DefaultBlockStatus
	}
	ir := &extprocv3.ImmediateResponse{
		Status:  &typev3.HttpStatus{Code: typev3.StatusCode(code)},
		Body:    []byte("blocked by elchi-shield\n"),
		Details: d.Reason,
		Headers: blockHeaders(code),
	}
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ImmediateResponse{ImmediateResponse: ir},
	}
}

// blockHeaders sets response headers on a block: a marker so the block is
// attributable downstream, and Retry-After on a 429 so rate-limited clients back
// off. No request payload is echoed (no info leak).
func blockHeaders(code int) *extprocv3.HeaderMutation {
	headers := []*corev3.HeaderValueOption{{
		Header: &corev3.HeaderValue{Key: "x-elchi-shield", Value: "blocked"},
	}}
	if code == 429 {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{Key: "Retry-After", Value: "1"},
		})
	}
	return &extprocv3.HeaderMutation{SetHeaders: headers}
}

func requestHeadersContinue(mode *procmodev3.ProcessingMode) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE}},
		},
		ModeOverride: mode,
	}
}

func responseHeadersContinue(mode *procmodev3.ProcessingMode) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE}},
		},
		ModeOverride: mode,
	}
}

func requestBodyContinue() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE}},
		},
	}
}

func responseBodyContinue() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE}},
		},
	}
}

func requestTrailersContinue() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestTrailers{RequestTrailers: &extprocv3.TrailersResponse{}},
	}
}

func responseTrailersContinue() *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_ResponseTrailers{ResponseTrailers: &extprocv3.TrailersResponse{}},
	}
}
