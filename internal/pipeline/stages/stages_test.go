package stages

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/policy"
	"github.com/cloudnativeworks/elchi-shield/internal/runtime"
	"github.com/cloudnativeworks/elchi-shield/internal/sensitive"
)

func hdrs(pairs ...string) []pipeline.Header {
	out := make([]pipeline.Header, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, pipeline.Header{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

func compiled(mode config.Mode, checks config.Checks) *policy.CompiledPolicy {
	r := config.DefaultPolicy()
	r.Mode = mode
	r.Checks = checks
	return policy.FromResolved("test", r)
}

func bg() context.Context { return context.Background() }

func TestContextInitDerivesAttributes(t *testing.T) {
	tx := &pipeline.Transaction{Headers: hdrs(
		":authority", "api.example.com",
		":path", "/v1/x",
		":method", "POST",
		"content-type", "application/json",
	)}
	ContextInit(0).Process(bg(), tx)
	if tx.Host != "api.example.com" || tx.Path != "/v1/x" || tx.Method != "POST" || tx.ContentType != "application/json" {
		t.Fatalf("derivation failed: %+v", tx)
	}
}

func TestFastPreChecksForbiddenHeader(t *testing.T) {
	tx := &pipeline.Transaction{
		Policy:  compiled(config.ModeBlock, config.Checks{Headers: &config.HeaderChecks{Forbidden: []string{"X-Debug"}}}),
		Headers: hdrs("X-Debug", "1"),
	}
	res := FastPreChecks().Process(bg(), tx)
	if res.Action != pipeline.ActionDeny || res.Decision.RuleID != "header.forbidden" {
		t.Fatalf("forbidden header should deny: %+v", res)
	}
}

func TestFastPreChecksRequiredAndOversizedAndHost(t *testing.T) {
	// required missing
	tx := &pipeline.Transaction{Policy: compiled(config.ModeBlock, config.Checks{Headers: &config.HeaderChecks{Required: []string{"X-Request-Id"}}})}
	if FastPreChecks().Process(bg(), tx).Action != pipeline.ActionDeny {
		t.Fatal("missing required header should deny")
	}
	// oversized
	tx = &pipeline.Transaction{
		Policy:  compiled(config.ModeBlock, config.Checks{Headers: &config.HeaderChecks{MaxHeaderValueBytes: 3}}),
		Headers: hdrs("X-Big", "toolong"),
	}
	if FastPreChecks().Process(bg(), tx).Action != pipeline.ActionDeny {
		t.Fatal("oversized header should deny")
	}
	// invalid host
	tx = &pipeline.Transaction{
		Direction: pipeline.DirectionRequest,
		Policy:    compiled(config.ModeBlock, config.Checks{Headers: &config.HeaderChecks{EnforceValidHost: true}}),
	}
	if FastPreChecks().Process(bg(), tx).Action != pipeline.ActionDeny {
		t.Fatal("missing host should deny when enforced")
	}
}

func TestFastPreChecksSkipHonored(t *testing.T) {
	r := config.DefaultPolicy()
	r.Mode = config.ModeBlock
	r.Checks = config.Checks{Headers: &config.HeaderChecks{Forbidden: []string{"X-Debug"}}}
	r.SkipChecks = []string{CheckForbiddenHeaders}
	tx := &pipeline.Transaction{Policy: policy.FromResolved("t", r), Headers: hdrs("X-Debug", "1")}
	if FastPreChecks().Process(bg(), tx).Action != pipeline.ActionContinue {
		t.Fatal("skip_checks should bypass forbidden-header check")
	}
}

func TestEarlyDecisionPostures(t *testing.T) {
	// no policy + default allow → skip remaining
	if EarlyDecision(true).Process(bg(), &pipeline.Transaction{}).Action != pipeline.ActionSkipRemaining {
		t.Fatal("default-allow should skip remaining when no policy")
	}
	// no policy + default deny → deny (and assigns blocking policy)
	tx := &pipeline.Transaction{}
	res := EarlyDecision(false).Process(bg(), tx)
	if res.Action != pipeline.ActionDeny || tx.Policy == nil || !tx.Policy.Blocking() {
		t.Fatalf("default-deny should deny with blocking policy: %+v", res)
	}
	// mode off → skip remaining
	off := &pipeline.Transaction{Policy: compiled(config.ModeOff, config.Checks{})}
	if EarlyDecision(true).Process(bg(), off).Action != pipeline.ActionSkipRemaining {
		t.Fatal("mode off should skip remaining")
	}
}

func TestBodyGateSetsFlags(t *testing.T) {
	r := config.DefaultPolicy()
	r.Mode = config.ModeBlock
	r.InspectRequestBody = true
	tx := &pipeline.Transaction{Policy: policy.FromResolved("t", r), Direction: pipeline.DirectionRequest}
	BodyGate().Process(bg(), tx)
	if !tx.BodyRequired() {
		t.Fatal("policy InspectRequestBody should gate body on")
	}
	if tx.WAFEnabled() {
		t.Fatal("no engines → WAF should be off")
	}
}

func TestBodyChecksJSON(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{Body: &config.BodyChecks{RequireJSON: true}})

	// invalid JSON
	tx := &pipeline.Transaction{Policy: pol, ContentType: "application/json"}
	tx.AppendBody([]byte("{bad"), 100)
	if BodyChecks(nil).Process(bg(), tx).Action != pipeline.ActionDeny {
		t.Fatal("invalid JSON should deny")
	}
	// valid JSON
	tx = &pipeline.Transaction{Policy: pol, ContentType: "application/json"}
	tx.AppendBody([]byte(`{"a":1}`), 100)
	if BodyChecks(nil).Process(bg(), tx).Action != pipeline.ActionContinue {
		t.Fatal("valid JSON should continue")
	}
}

func TestBodyTruncationGuard(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{})
	// truncated body → deny (non-skippable structural guard)
	tx := &pipeline.Transaction{Policy: pol}
	tx.SetBodyTruncated(true)
	res := BodyTruncationGuard().Process(bg(), tx)
	if res.Action != pipeline.ActionDeny || res.Decision.RuleID != "body.too_large" {
		t.Fatalf("truncated body should deny: %+v", res)
	}
	// non-truncated → continue
	tx2 := &pipeline.Transaction{Policy: pol}
	if BodyTruncationGuard().Process(bg(), tx2).Action != pipeline.ActionContinue {
		t.Fatal("non-truncated body should continue")
	}
}

// TestCatalogPerPolicyOrdering proves a policy can reorder body-phase inspectors
// (and that omitting one disables it).
func TestCatalogPerPolicyOrdering(t *testing.T) {
	cat := NewCatalog(Deps{DefaultAllow: true})

	// Order WAF before body checks; omit nothing.
	r := config.DefaultPolicy()
	r.RequestOrder = []string{config.StageWAFEngine, config.StageBodyChecks}
	cp := policy.FromResolved("t", r)
	pp, err := cat.BuildPolicyPipelines(cp)
	if err != nil {
		t.Fatal(err)
	}
	// Body pipeline = 2 structural guards (truncation + content-decode) + the 2 inspectors.
	if pp.RequestBody.Len() != 4 {
		t.Fatalf("expected 2 guards + 2 body-phase inspectors, got %d", pp.RequestBody.Len())
	}

	// Omitting body_checks disables it: body pipeline is just the structural guards.
	r2 := config.DefaultPolicy()
	r2.RequestOrder = []string{config.StageFastPreChecks}
	pp2, err := cat.BuildPolicyPipelines(policy.FromResolved("t2", r2))
	if err != nil {
		t.Fatal(err)
	}
	if pp2.RequestBody.Len() != 2 { // truncation guard + content-decode
		t.Fatalf("omitted body inspectors should leave only the structural guards, got %d", pp2.RequestBody.Len())
	}
	if pp2.RequestHeader.Len() != 2 { // fast_pre_checks + body_gate
		t.Fatalf("header pipeline should be fast_pre_checks + body_gate, got %d", pp2.RequestHeader.Len())
	}
}

// orderObserver records the order stages execute in.
type orderObserver struct{ names []string }

func (o *orderObserver) StageObserved(name string, _ pipeline.Phase, _ time.Duration, _ pipeline.StageAction) {
	o.names = append(o.names, name)
}

// TestPerPolicyExecutionOrder proves the WAF engine runs BEFORE body checks when
// a policy orders it that way — true per-policy ordering, not just config.
func TestPerPolicyExecutionOrder(t *testing.T) {
	obs := &orderObserver{}
	cat := NewCatalog(Deps{DefaultAllow: true, Observer: obs})

	r := config.DefaultPolicy()
	r.Mode = config.ModeBlock
	r.Checks = config.Checks{Body: &config.BodyChecks{RequireJSON: true}}
	r.RequestOrder = []string{config.StageWAFEngine, config.StageBodyChecks}
	cp := policy.FromResolved("t", r)
	cp.Engines = engine.NewSet(fakeEngine{verdict: decision.Verdict{Action: decision.Continue}})

	pp, err := cat.BuildPolicyPipelines(cp)
	if err != nil {
		t.Fatal(err)
	}
	tx := &pipeline.Transaction{Policy: cp, Direction: pipeline.DirectionRequest, ContentType: "application/json"}
	tx.SetBodyRequired(true)
	tx.SetWAFEnabled(true)
	tx.AppendBody([]byte(`{"ok":true}`), 100)

	pp.RequestBody.Run(bg(), tx)

	// Structural guards run first (truncation, content-decode), then the
	// policy-ordered inspectors.
	if len(obs.names) != 4 || obs.names[0] != "body_truncation_guard" || obs.names[1] != "body_content_decode" ||
		obs.names[2] != config.StageWAFEngine || obs.names[3] != config.StageBodyChecks {
		t.Fatalf("expected guard, decode, waf_engine, body_checks, got %v", obs.names)
	}
}

func TestMatchPathNormalization(t *testing.T) {
	cases := map[string]string{
		"/admin":             "/admin",
		"/admin?x=1":         "/admin",
		"/admin#frag":        "/admin",
		"/%61dmin":           "/admin", // percent-decoded
		"/foo/../admin":      "/admin", // dot-segment
		"//admin":            "/admin", // duplicate slash
		"/v1/":               "/v1/",   // trailing slash preserved for prefix
		"/a/./b":             "/a/b",
		"/v1/users/../admin": "/v1/admin",
	}
	for in, want := range cases {
		if got := matchPath(in); got != want {
			t.Errorf("matchPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFastPreChecksHostAuthorityMismatch(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{})
	// :authority and host disagree → host-smuggling → deny.
	tx := &pipeline.Transaction{
		Policy:    pol,
		Direction: pipeline.DirectionRequest,
		Headers:   hdrs(":authority", "api.example.com", "host", "evil.com"),
	}
	if res := FastPreChecks().Process(bg(), tx); res.Action != pipeline.ActionDeny || res.Decision.RuleID != "header.host_mismatch" {
		t.Fatalf("host/:authority mismatch must deny, got %+v", res)
	}
	// Agreement (port/case differences ignored) → continue.
	tx2 := &pipeline.Transaction{
		Policy:    pol,
		Direction: pipeline.DirectionRequest,
		Headers:   hdrs(":authority", "API.example.com:443", "host", "api.example.com"),
	}
	if res := FastPreChecks().Process(bg(), tx2); res.Action != pipeline.ActionContinue {
		t.Fatalf("matching host/:authority should continue, got %+v", res)
	}
}

func TestIsJSONContentTypeRobust(t *testing.T) {
	json := []string{"application/json", "application/json; charset=utf-8",
		"application/vnd.api+json", "APPLICATION/JSON", "application/json;charset=utf-8;x=y"}
	for _, ct := range json {
		if !isJSONContentType(ct) {
			t.Errorf("expected JSON for %q", ct)
		}
	}
	notJSON := []string{"text/plain", "application/xml", "", "application/x-www-form-urlencoded"}
	for _, ct := range notJSON {
		if isJSONContentType(ct) {
			t.Errorf("expected non-JSON for %q", ct)
		}
	}
}

type fakeDetector struct {
	found bool
	ms    []sensitive.Match
}

func (f fakeDetector) Scan(context.Context, string, []byte) (bool, string) {
	return f.found, "credit_card"
}

func (f fakeDetector) Matches([]byte) []sensitive.Match { return f.ms }

func TestBodyChecksSensitiveData(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{Body: &config.BodyChecks{DetectSensitiveData: true}})
	tx := &pipeline.Transaction{Policy: pol}
	tx.AppendBody([]byte("4111 1111 1111 1111"), 100)
	if BodyChecks(fakeDetector{found: true}).Process(bg(), tx).Action != pipeline.ActionDeny {
		t.Fatal("sensitive data should deny")
	}
	if BodyChecks(fakeDetector{found: false}).Process(bg(), tx).Action != pipeline.ActionContinue {
		t.Fatal("no sensitive data should continue")
	}
}

type fakeEngine struct {
	verdict     decision.Verdict
	err         error
	requireBody bool
}

func (f fakeEngine) Name() string       { return "fake" }
func (f fakeEngine) RequiresBody() bool { return f.requireBody }
func (f fakeEngine) Close() error       { return nil }
func (f fakeEngine) Inspect(context.Context, *engine.Request) (decision.Verdict, error) {
	return f.verdict, f.err
}

// TestHeaderOnlyEngineDoesNotRequireBody proves a header-only engine (e.g. JWT)
// never forces the body to be buffered, while a body engine (e.g. Coraza) does.
func TestHeaderOnlyEngineDoesNotRequireBody(t *testing.T) {
	hdrPol := compiled(config.ModeBlock, config.Checks{})
	hdrPol.Engines = engine.NewSet(fakeEngine{requireBody: false})
	tx := &pipeline.Transaction{Policy: hdrPol, Direction: pipeline.DirectionRequest}
	BodyGate().Process(bg(), tx)
	if tx.BodyRequired() {
		t.Fatal("header-only engine must not require body buffering")
	}
	if tx.WAFEnabled() {
		t.Fatal("body-phase WAF must be gated off when only header engines exist")
	}

	bodyPol := compiled(config.ModeBlock, config.Checks{})
	bodyPol.Engines = engine.NewSet(fakeEngine{requireBody: true})
	tx2 := &pipeline.Transaction{Policy: bodyPol, Direction: pipeline.DirectionRequest}
	BodyGate().Process(bg(), tx2)
	if !tx2.BodyRequired() || !tx2.WAFEnabled() {
		t.Fatalf("body engine must require body and enable body WAF: body=%v waf=%v", tx2.BodyRequired(), tx2.WAFEnabled())
	}
}

// TestHeaderEngineRunsAtHeaderPhase proves the header-phase WAF stage runs the
// header-only engines and denies on a block, with no body present.
func TestHeaderEngineRunsAtHeaderPhase(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{})
	pol.Engines = engine.NewSet(fakeEngine{requireBody: false, verdict: decision.Verdict{Action: decision.Block, Severity: decision.SeverityHigh}})
	res := WAFHeaderEngine().Process(bg(), &pipeline.Transaction{Policy: pol})
	if res.Action != pipeline.ActionDeny {
		t.Fatalf("header engine block should deny at header phase: %+v", res)
	}
	// The body-phase WAF stage must skip header-only engines (no double-run).
	if WAFEngine().Process(bg(), &pipeline.Transaction{Policy: pol}).Action != pipeline.ActionContinue {
		t.Fatal("body-phase WAF must not run header-only engines")
	}
}

// TestSplitPlacesWAFByPhase proves the single waf_engine order word expands into
// a header-phase stage (header pipeline) and a body-phase stage (body pipeline).
func TestSplitPlacesWAFByPhase(t *testing.T) {
	cat := NewCatalog(Deps{DefaultAllow: true})
	r := config.DefaultPolicy()
	r.Mode = config.ModeBlock
	r.RequestOrder = []string{config.StageWAFEngine}
	cp := policy.FromResolved("t", r)
	cp.Engines = engine.NewSet(fakeEngine{requireBody: false})
	pp, err := cat.BuildPolicyPipelines(cp)
	if err != nil {
		t.Fatal(err)
	}
	// header: waf_engine_headers + body_gate
	if pp.RequestHeader.Len() != 2 {
		t.Fatalf("header pipeline should hold waf header stage + body_gate, got %d", pp.RequestHeader.Len())
	}
	// body: truncation guard + content-decode + waf_engine
	if pp.RequestBody.Len() != 3 {
		t.Fatalf("body pipeline should hold 2 guards + waf body stage, got %d", pp.RequestBody.Len())
	}
}

func TestWAFEngineBlockAndError(t *testing.T) {
	blockPol := compiled(config.ModeBlock, config.Checks{})
	blockPol.Engines = engine.NewSet(fakeEngine{requireBody: true, verdict: decision.Verdict{Action: decision.Block, Severity: decision.SeverityHigh}})
	if WAFEngine().Process(bg(), &pipeline.Transaction{Policy: blockPol}).Action != pipeline.ActionDeny {
		t.Fatal("engine block should deny")
	}

	errPol := compiled(config.ModeBlock, config.Checks{})
	errPol.Engines = engine.NewSet(fakeEngine{requireBody: true, err: errors.New("waf boom")})
	if WAFEngine().Process(bg(), &pipeline.Transaction{Policy: errPol}).Action != pipeline.ActionError {
		t.Fatal("engine error should yield ActionError")
	}
}

// End-to-end: build a real snapshot + default request pipeline and confirm mode
// behavior.
func TestDefaultRequestPipelineEndToEnd(t *testing.T) {
	mode := config.ModeBlock
	forbidden := config.HeaderChecks{Forbidden: []string{"X-Debug"}}
	dom := func(m config.Mode) config.Domain {
		return config.Domain{Hosts: []string{"api.example.com"}, Routes: []config.Route{{
			Match:  config.Match{PathPrefix: "/"},
			Policy: config.PolicySpec{Mode: &m, Checks: config.Checks{Headers: &forbidden}},
		}}}
	}
	_ = mode

	build := func(m config.Mode) (*pipeline.Pipeline, *runtime.Snapshot) {
		cfg := &config.MergedConfig{
			Domains: []config.MergedDomain{{Domain: dom(m), Source: "t"}},
			Sources: []string{"t"},
		}
		snap, err := runtime.NewSnapshot(cfg, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		p, err := DefaultRequestPipeline(Deps{DefaultAllow: true})
		if err != nil {
			t.Fatal(err)
		}
		return p, snap
	}

	mkTx := func(snap *runtime.Snapshot) *pipeline.Transaction {
		return &pipeline.Transaction{
			Snapshot: snap,
			Headers:  hdrs(":authority", "api.example.com", ":path", "/v1/x", ":method", "GET", "X-Debug", "1"),
		}
	}

	// block mode → forbidden header is enforced.
	p, snap := build(config.ModeBlock)
	if d := p.Run(bg(), mkTx(snap)); !d.IsBlock() {
		t.Fatalf("block mode should block forbidden header, got %v", d.Action)
	}

	// detect mode → recorded but allowed.
	p, snap = build(config.ModeDetect)
	if d := p.Run(bg(), mkTx(snap)); d.IsBlock() || d.Action != decision.Detect {
		t.Fatalf("detect mode should allow+record, got %v block=%v", d.Action, d.IsBlock())
	}
}

func txWithHeaders(pairs ...string) *pipeline.Transaction {
	return &pipeline.Transaction{Headers: hdrs(pairs...)}
}

func TestClientIPTrustedHops(t *testing.T) {
	// XFF = "spoofed, realclient" (Envoy appends the real client on the right).
	tx := txWithHeaders("X-Forwarded-For", "203.0.113.9, 198.51.100.7")
	// trustedHops=0 → rightmost (the address Envoy appended) — secure default.
	if got := clientIP(tx, 0); got != "198.51.100.7" {
		t.Fatalf("hops=0 should pick the rightmost, got %q", got)
	}
	// trustedHops=1 → one in from the right = the spoofable leftmost here.
	if got := clientIP(tx, 1); got != "203.0.113.9" {
		t.Fatalf("hops=1 should pick one-from-right, got %q", got)
	}
	// hops larger than the list clamps to the leftmost.
	if got := clientIP(tx, 9); got != "203.0.113.9" {
		t.Fatalf("over-large hops should clamp to leftmost, got %q", got)
	}
}

func TestClientIPCanonicalization(t *testing.T) {
	cases := map[string]string{
		"::ffff:1.2.3.4":    "1.2.3.4",     // IPv4-in-IPv6 unmapped
		"1.2.3.4:5678":      "1.2.3.4",     // ip:port stripped
		"[2001:db8::1]:443": "2001:db8::1", // ipv6:port stripped
		"1.2.3.4":           "1.2.3.4",
		"not-an-ip":         "",
	}
	for in, want := range cases {
		tx := txWithHeaders("X-Real-IP", in)
		if got := clientIP(tx, 0); got != want {
			t.Errorf("canonIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientIPFallbackToRealIP(t *testing.T) {
	tx := txWithHeaders("X-Real-IP", "203.0.113.5")
	if got := clientIP(tx, 0); got != "203.0.113.5" {
		t.Fatalf("should fall back to X-Real-IP, got %q", got)
	}
}
