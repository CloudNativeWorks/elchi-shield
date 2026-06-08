package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/policy"
)

// pol builds a CompiledPolicy with the given mode/fail posture for tests.
func pol(mode config.Mode, fail config.FailMode) *policy.CompiledPolicy {
	r := config.DefaultPolicy()
	r.Mode = mode
	r.FailMode = fail
	return policy.FromResolved("p1", r)
}

// recorder builds stages that append their name to a shared slice when run, so
// tests can assert exactly which stages executed and in what order.
type recorder struct{ ran []string }

func (rec *recorder) stage(name string, phase Phase, res StageResult) Stage {
	return NewStageFunc(name, phase, func(_ context.Context, _ *Transaction) StageResult {
		rec.ran = append(rec.ran, name)
		return res
	})
}

func mustPipeline(t *testing.T, stages ...Stage) *Pipeline {
	t.Helper()
	p, err := New("test", stages, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestDenyShortCircuitsInBlockMode(t *testing.T) {
	rec := &recorder{}
	d := decision.Decision{Action: decision.Block, Reason: "bad", Severity: decision.SeverityHigh}
	p := mustPipeline(t,
		rec.stage("a", PhasePreCheck, Continue()),
		rec.stage("deny", PhasePreCheck, Deny(&d)),
		rec.stage("never", PhaseFinal, Continue()),
	)
	tx := &Transaction{Policy: pol(config.ModeBlock, config.FailOpen)}
	got := p.Run(context.Background(), tx)

	if !got.IsBlock() {
		t.Fatalf("want block, got %v", got.Action)
	}
	if got.StatusCode != decision.DefaultBlockStatus {
		t.Fatalf("want default block status, got %d", got.StatusCode)
	}
	if len(rec.ran) != 2 || rec.ran[1] != "deny" {
		t.Fatalf("stage after deny should not run: %v", rec.ran)
	}
}

func TestDenyRecordsButAllowsInDetectMode(t *testing.T) {
	rec := &recorder{}
	d := decision.Decision{Action: decision.Block, Reason: "suspicious", Severity: decision.SeverityMedium}
	p := mustPipeline(t,
		rec.stage("deny", PhasePreCheck, Deny(&d)),
		rec.stage("after", PhaseFinal, Continue()),
	)
	tx := &Transaction{Policy: pol(config.ModeDetect, config.FailOpen)}
	got := p.Run(context.Background(), tx)

	if got.IsBlock() {
		t.Fatal("detect mode must not block")
	}
	if got.Action != decision.Detect {
		t.Fatalf("want detect action, got %v", got.Action)
	}
	if len(rec.ran) != 2 {
		t.Fatalf("detect should continue to later stages: %v", rec.ran)
	}
	if got.Reason != "suspicious" || got.Severity != decision.SeverityMedium {
		t.Fatalf("attribution not recorded: %+v", got)
	}
}

// TestResetShrinksOversizedBody proves Reset drops a large body buffer so the
// pool does not retain MiB-scale allocations, but keeps small buffers to avoid
// hot-path churn.
func TestResetShrinksOversizedBody(t *testing.T) {
	tx := &Transaction{}
	// A small body buffer is retained (capacity preserved).
	tx.AppendBody(make([]byte, 1024), 1<<20)
	tx.Reset()
	if cap(tx.body) == 0 {
		t.Fatal("small body buffer should be retained for reuse")
	}
	// An oversized body buffer is dropped.
	big := int64(retainedBodyCap) + 1
	tx.AppendBody(make([]byte, big), big*2)
	if int64(cap(tx.body)) <= retainedBodyCap {
		t.Fatalf("precondition: buffer should exceed cap, got %d", cap(tx.body))
	}
	tx.Reset()
	if cap(tx.body) != 0 {
		t.Fatalf("oversized body buffer should be dropped, got cap %d", cap(tx.body))
	}
}

// TestDetectAttributionMovesAsUnit proves that when several detect-mode findings
// are recorded, the running decision's Reason/RuleID/Engine/Severity all come
// from the SAME (highest-severity) finding — never a Reason from one mixed with
// a RuleID from another.
func TestDetectAttributionMovesAsUnit(t *testing.T) {
	low := decision.Decision{Action: decision.Block, Reason: "low-reason", RuleID: "R-low", Engine: "e-low", Severity: decision.SeverityLow}
	high := decision.Decision{Action: decision.Block, Reason: "high-reason", RuleID: "R-high", Engine: "e-high", Severity: decision.SeverityHigh}
	p := mustPipeline(t,
		NewStageFunc("low", PhasePreCheck, func(_ context.Context, _ *Transaction) StageResult { return Deny(&low) }),
		NewStageFunc("high", PhasePreCheck, func(_ context.Context, _ *Transaction) StageResult { return Deny(&high) }),
	)
	tx := &Transaction{Policy: pol(config.ModeDetect, config.FailOpen)}
	got := p.Run(context.Background(), tx)

	if got.Severity != decision.SeverityHigh {
		t.Fatalf("want high severity, got %v", got.Severity)
	}
	// The whole attribution unit must be the high finding's, not a mix.
	if got.Reason != "high-reason" || got.RuleID != "R-high" || got.Engine != "e-high" {
		t.Fatalf("attribution must move as a unit from the high finding: %+v", got)
	}
}

// TestDetectAccumulatesAllFindings proves that in detect mode every recorded
// finding is accumulated on tx (each tagged with the mode), not just the
// highest-severity aggregate — the basis for the multi-finding audit trail.
func TestDetectAccumulatesAllFindings(t *testing.T) {
	d1 := decision.Decision{Action: decision.Block, Reason: "r1", RuleID: "R1", Severity: decision.SeverityLow}
	d2 := decision.Decision{Action: decision.Block, Reason: "r2", RuleID: "R2", Severity: decision.SeverityHigh}
	p := mustPipeline(t,
		NewStageFunc("s1", PhasePreCheck, func(_ context.Context, _ *Transaction) StageResult { return Deny(&d1) }),
		NewStageFunc("s2", PhasePreCheck, func(_ context.Context, _ *Transaction) StageResult { return Deny(&d2) }),
	)
	tx := &Transaction{Policy: pol(config.ModeDetect, config.FailOpen)}
	got := p.Run(context.Background(), tx)

	if got.IsBlock() {
		t.Fatal("detect mode must not block")
	}
	f := tx.Findings()
	if len(f) != 2 {
		t.Fatalf("expected 2 accumulated findings, got %d", len(f))
	}
	if f[0].RuleID != "R1" || f[1].RuleID != "R2" {
		t.Fatalf("findings out of order: %+v", f)
	}
	for _, fd := range f {
		if fd.Action != decision.Detect {
			t.Fatalf("each finding must be tagged with the mode (detect), got %v", fd.Action)
		}
	}
	// A second Run resets the per-phase findings.
	tx.SetBodyRequired(false)
	_ = p.Run(context.Background(), tx)
	if len(tx.Findings()) != 2 {
		// (re-run produces the same 2 findings; what matters is it doesn't accumulate to 4)
		t.Fatalf("findings must reset per Run, got %d", len(tx.Findings()))
	}
}

func TestDenyShadowMode(t *testing.T) {
	d := decision.Decision{Action: decision.Block, Severity: decision.SeverityLow}
	p := mustPipeline(t, NewStageFunc("deny", PhasePreCheck, func(_ context.Context, _ *Transaction) StageResult {
		return Deny(&d)
	}))
	tx := &Transaction{Policy: pol(config.ModeShadow, config.FailOpen)}
	got := p.Run(context.Background(), tx)
	if got.IsBlock() || got.Action != decision.Shadow {
		t.Fatalf("shadow mode: want shadow+allow, got %v block=%v", got.Action, got.IsBlock())
	}
}

func TestTerminalAllowStops(t *testing.T) {
	rec := &recorder{}
	p := mustPipeline(t,
		rec.stage("allow", PhasePreCheck, Allow(nil)),
		rec.stage("never", PhaseFinal, Continue()),
	)
	tx := &Transaction{Policy: pol(config.ModeBlock, config.FailOpen)}
	got := p.Run(context.Background(), tx)
	if got.Action != decision.Allow {
		t.Fatalf("want allow, got %v", got.Action)
	}
	if len(rec.ran) != 1 {
		t.Fatalf("terminal allow must short-circuit: %v", rec.ran)
	}
}

func TestSkipBodyGatesBodyAndWAFStages(t *testing.T) {
	rec := &recorder{}
	p := mustPipeline(t,
		rec.stage("gate", PhaseBodyGate, SkipBody()),
		rec.stage("body", PhaseBody, Continue()),
		rec.stage("waf", PhaseWAF, Continue()),
		rec.stage("final", PhaseFinal, Continue()),
	)
	tx := &Transaction{Policy: pol(config.ModeBlock, config.FailOpen)}
	// Even though something could enable body, the gate returns SkipBody.
	tx.SetBodyRequired(true)
	tx.SetWAFEnabled(true)
	p.Run(context.Background(), tx)

	for _, name := range rec.ran {
		if name == "body" || name == "waf" {
			t.Fatalf("body/waf stages must be skipped after SkipBody: %v", rec.ran)
		}
	}
	if len(rec.ran) != 2 { // gate + final
		t.Fatalf("want gate+final only: %v", rec.ran)
	}
}

func TestBodyStagesSkippedByDefault(t *testing.T) {
	rec := &recorder{}
	p := mustPipeline(t,
		rec.stage("pre", PhasePreCheck, Continue()),
		rec.stage("body", PhaseBody, Continue()),
	)
	tx := &Transaction{Policy: pol(config.ModeBlock, config.FailOpen)} // bodyRequired=false
	p.Run(context.Background(), tx)
	if len(rec.ran) != 1 || rec.ran[0] != "pre" {
		t.Fatalf("body stage should be gated off by default: %v", rec.ran)
	}
}

func TestErrorFailOpenVsFailClose(t *testing.T) {
	mk := func() *Pipeline {
		return mustPipeline(t, NewStageFunc("boom", PhasePreCheck, func(_ context.Context, _ *Transaction) StageResult {
			return Fail(context.DeadlineExceeded)
		}))
	}
	open := mk().Run(context.Background(), &Transaction{Policy: pol(config.ModeBlock, config.FailOpen)})
	if open.IsBlock() {
		t.Fatal("fail-open must allow on stage error")
	}
	closed := mk().Run(context.Background(), &Transaction{Policy: pol(config.ModeBlock, config.FailClose)})
	if !closed.IsBlock() {
		t.Fatal("fail-close must block on stage error")
	}
}

func TestPanicRecoveryAppliesFailPosture(t *testing.T) {
	p := mustPipeline(t, NewStageFunc("panic", PhasePreCheck, func(_ context.Context, _ *Transaction) StageResult {
		panic("boom")
	}))
	// fail-close → panic becomes a block, not a process crash.
	got := p.Run(context.Background(), &Transaction{Policy: pol(config.ModeBlock, config.FailClose)})
	if !got.IsBlock() {
		t.Fatalf("panic under fail-close should block, got %v", got.Action)
	}
}

func TestDeadlineAppliesFailPosture(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done
	rec := &recorder{}
	p := mustPipeline(t, rec.stage("never", PhasePreCheck, Continue()))
	got := p.Run(ctx, &Transaction{Policy: pol(config.ModeBlock, config.FailClose)})
	if !got.IsBlock() {
		t.Fatal("expired deadline under fail-close should block")
	}
	if len(rec.ran) != 0 {
		t.Fatalf("no stage should run past an expired deadline: %v", rec.ran)
	}
}

func TestNilPolicyDefaultsFailOpen(t *testing.T) {
	p := mustPipeline(t, NewStageFunc("err", PhasePreCheck, func(_ context.Context, _ *Transaction) StageResult {
		return Fail(context.DeadlineExceeded)
	}))
	got := p.Run(context.Background(), &Transaction{}) // no policy
	if got.IsBlock() {
		t.Fatal("nil policy must default to fail-open")
	}
}

func TestSkipRemainingStops(t *testing.T) {
	rec := &recorder{}
	p := mustPipeline(t,
		rec.stage("a", PhasePreCheck, SkipRemaining()),
		rec.stage("never", PhaseFinal, Continue()),
	)
	got := p.Run(context.Background(), &Transaction{Policy: pol(config.ModeBlock, config.FailOpen)})
	if got.Action != decision.Allow || len(rec.ran) != 1 {
		t.Fatalf("skip-remaining should stop with allow: action=%v ran=%v", got.Action, rec.ran)
	}
}

func TestNewRejectsOutOfOrderStages(t *testing.T) {
	rec := &recorder{}
	_, err := New("bad", []Stage{
		rec.stage("final", PhaseFinal, Continue()),
		rec.stage("pre", PhasePreCheck, Continue()),
	}, nil)
	if err == nil {
		t.Fatal("expected ordering error")
	}
}

type capObserver struct{ calls []string }

func (o *capObserver) StageObserved(name string, _ Phase, _ time.Duration, _ StageAction) {
	o.calls = append(o.calls, name)
}

func TestObserverSeesEveryRunStage(t *testing.T) {
	obs := &capObserver{}
	rec := &recorder{}
	p, err := New("obs", []Stage{
		rec.stage("a", PhasePreCheck, Continue()),
		rec.stage("b", PhaseFinal, Continue()),
	}, obs)
	if err != nil {
		t.Fatal(err)
	}
	p.Run(context.Background(), &Transaction{Policy: pol(config.ModeBlock, config.FailOpen)})
	if len(obs.calls) != 2 {
		t.Fatalf("observer should see both stages: %v", obs.calls)
	}
}

func TestPoolReuseAndReset(t *testing.T) {
	pool := NewPool()
	tx := pool.Acquire()
	tx.RequestID = "r1"
	tx.Host = "a.com"
	tx.SourceIP = "1.2.3.4"
	tx.Headers = append(tx.Headers, Header{Name: "X", Value: "1"})
	tx.SetBodyRequired(true)
	pool.Release(tx)

	tx2 := pool.Acquire()
	if tx2.RequestID != "" || tx2.Host != "" || tx2.SourceIP != "" ||
		len(tx2.Headers) != 0 || tx2.BodyRequired() {
		t.Fatalf("Reset left state behind: %+v", tx2)
	}
}

func TestRequestResponseReuseDirection(t *testing.T) {
	tx := &Transaction{Policy: pol(config.ModeBlock, config.FailOpen), Direction: DirectionRequest}
	reqP := mustPipeline(t, NewStageFunc("req", PhasePreCheck, func(_ context.Context, tx *Transaction) StageResult {
		if tx.Direction != DirectionRequest {
			t.Error("expected request direction")
		}
		return Continue()
	}))
	reqP.Run(context.Background(), tx)

	// Flip direction; policy stays pinned. Same tx instance reused.
	tx.Direction = DirectionResponse
	respP := mustPipeline(t, NewStageFunc("resp", PhasePreCheck, func(_ context.Context, tx *Transaction) StageResult {
		if tx.Direction != DirectionResponse {
			t.Error("expected response direction")
		}
		if tx.Policy == nil {
			t.Error("pinned policy lost on response")
		}
		return Continue()
	}))
	respP.Run(context.Background(), tx)
}

func TestAppendBodyBounded(t *testing.T) {
	tx := &Transaction{}
	n, trunc := tx.AppendBody([]byte("hello"), 3)
	if n != 3 || !trunc {
		t.Fatalf("want stored=3 truncated=true, got %d %v", n, trunc)
	}
	if string(tx.Body()) != "hel" {
		t.Fatalf("body not bounded: %q", tx.Body())
	}
	n, trunc = tx.AppendBody([]byte("x"), 3)
	if n != 0 || !trunc {
		t.Fatalf("further appends past cap must be rejected: %d %v", n, trunc)
	}
}
