package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
)

// Observer receives a callback for every stage the executor runs, enabling
// per-stage metrics and latency without coupling the executor to Prometheus.
// The default is a no-op; Phase 7 wires a metrics-backed implementation.
type Observer interface {
	StageObserved(name string, phase Phase, dur time.Duration, action StageAction)
}

// PostureObserver is an optional interface an Observer may also implement to be
// notified of executor-level fail-posture and timeout events (which are not tied
// to a single stage). The executor type-asserts for it.
type PostureObserver interface {
	FailOpen()
	FailClose()
	Timeout()
}

// NopObserver discards all observations.
type NopObserver struct{}

// StageObserved implements Observer.
func (NopObserver) StageObserved(string, Phase, time.Duration, StageAction) {}

// Pipeline is an immutable, ordered chain of Stages plus an Observer. It is
// assembled once (cold path) and run for every request (hot path). A Pipeline
// is safe for concurrent use: it holds no mutable state — all per-request state
// is in the Transaction.
type Pipeline struct {
	name     string
	stages   []Stage
	observer Observer
}

// New builds a Pipeline from an ordered slice of stages. Stages must be in
// non-decreasing Phase order (cheap → expensive); otherwise New returns an
// error so misordered chains fail at assembly time, not in production.
func New(name string, stages []Stage, obs Observer) (*Pipeline, error) {
	if obs == nil {
		obs = NopObserver{}
	}
	prev := Phase(0)
	for i, s := range stages {
		if s == nil {
			return nil, fmt.Errorf("pipeline %q: nil stage at index %d", name, i)
		}
		if s.Phase() < prev {
			return nil, fmt.Errorf("pipeline %q: stage %q (phase %s) is out of order after phase %s",
				name, s.Name(), s.Phase(), prev)
		}
		prev = s.Phase()
	}
	cp := make([]Stage, len(stages))
	copy(cp, stages)
	return &Pipeline{name: name, stages: cp, observer: obs}, nil
}

// NewUnordered builds a Pipeline without the phase-monotonic ordering check. It
// is used for per-policy pipelines where the operator has explicitly chosen the
// order of same-group inspectors (e.g. running waf_engine before body_checks —
// both body-group). Callers that assemble across phase groups must still respect
// physical constraints (a body inspector needs the buffered body); the ext_proc
// server enforces that by splitting header- and body-phase stages.
func NewUnordered(name string, stages []Stage, obs Observer) *Pipeline {
	if obs == nil {
		obs = NopObserver{}
	}
	cp := make([]Stage, len(stages))
	copy(cp, stages)
	return &Pipeline{name: name, stages: cp, observer: obs}
}

// Name returns the pipeline's identifier (e.g. "request" / "response").
func (p *Pipeline) Name() string { return p.name }

// Len returns the number of stages.
func (p *Pipeline) Len() int { return len(p.stages) }

// StageNames returns the ordered names of the stages in this pipeline. It is used
// for introspection/explainability (e.g. the /policyz endpoint), not the hot path.
func (p *Pipeline) StageNames() []string {
	names := make([]string, len(p.stages))
	for i, s := range p.stages {
		names[i] = s.Name()
	}
	return names
}

// Run executes the chain against tx and returns a non-nil aggregate Decision.
// It owns every cross-cutting concern: short-circuit, phase gating, panic
// recovery, deadline enforcement, fail-open/close, and mode→action mapping so
// that detect/shadow modes never actually block.
func (p *Pipeline) Run(ctx context.Context, tx *Transaction) *decision.Decision {
	// The running decision lives on the pooled Transaction so the common allow
	// path returns a pointer into already-heap-resident memory (no per-phase
	// Decision allocation). It is consumed synchronously before the next Run.
	tx.result = decision.Allowed(tx.PolicyID())
	tx.findings = tx.findings[:0] // per-phase detect/shadow findings
	final := &tx.result

	for _, s := range p.stages {
		if p.gated(s.Phase(), tx) {
			continue
		}
		// Enforce the request deadline before doing stage work.
		if err := ctx.Err(); err != nil {
			return p.failPosture(tx, fmt.Errorf("deadline: %w", err), final, true)
		}

		res := p.runStage(ctx, s, tx)

		switch res.Action {
		case ActionContinue:
			// next stage

		case ActionAllow:
			// Terminal allow: stop and return allow.
			if res.Decision != nil {
				return res.Decision
			}
			return final

		case ActionDeny:
			if d := p.applyDeny(tx, res, final); d != nil {
				return d // enforced block
			}
			// detect/shadow: recorded as would-block, keep going.

		case ActionShadowDetect:
			p.record(tx, res, final, decision.Shadow)

		case ActionSkipBody:
			tx.SetBodyRequired(false)
			tx.SetWAFEnabled(false)

		case ActionSkipRemaining:
			return final

		case ActionError:
			return p.failPosture(tx, res.Err, final, false)
		}
	}

	return final
}

// gated reports whether a stage's phase is disabled for this request.
func (p *Pipeline) gated(ph Phase, tx *Transaction) bool {
	switch ph {
	case PhaseBody:
		return !tx.BodyRequired()
	case PhaseWAF:
		return !tx.WAFEnabled()
	default:
		return false
	}
}

// runStage executes one stage with panic recovery and timing/observation.
func (p *Pipeline) runStage(ctx context.Context, s Stage, tx *Transaction) (res StageResult) {
	start := time.Now()
	defer func() {
		if r := recover(); r != nil {
			res = StageResult{Action: ActionError, Err: fmt.Errorf("panic in stage %q: %v", s.Name(), r)}
		}
		p.observer.StageObserved(s.Name(), s.Phase(), time.Since(start), res.Action)
	}()
	return s.Process(ctx, tx)
}

// applyDeny maps a deny through the policy mode. In block mode it returns the
// enforced block decision; in detect/shadow it records a would-block event and
// returns nil so the pipeline continues (the request is allowed).
func (p *Pipeline) applyDeny(tx *Transaction, res StageResult, final *decision.Decision) *decision.Decision {
	if tx.Policy != nil && tx.Policy.Blocking() {
		if res.Decision != nil {
			if res.Decision.StatusCode == 0 {
				res.Decision.StatusCode = decision.DefaultBlockStatus
			}
			return res.Decision
		}
		d := decision.Decision{Action: decision.Block, PolicyID: tx.PolicyID(), StatusCode: decision.DefaultBlockStatus}
		return &d
	}
	// Non-blocking modes: record but do not block.
	mode := decision.Detect
	if tx.Policy != nil && tx.Policy.Shadowing() {
		mode = decision.Shadow
	}
	p.record(tx, res, final, mode)
	return nil
}

// record annotates the running decision and tracks attribution from a recorded
// (non-enforced) finding without blocking the request. Attribution moves as a
// coherent unit: when a finding outranks the current one (higher severity, or
// the first finding seen) the Reason, RuleID, Engine and Severity are all taken
// from that same finding so the recorded decision never mixes one finding's
// reason with another's rule id.
func (p *Pipeline) record(tx *Transaction, res StageResult, final *decision.Decision, mode decision.Action) {
	if final.Action == decision.Allow {
		final.Action = mode
	}
	if res.Decision == nil {
		return
	}
	// Accumulate this individual finding (tagged with the mode) so the server can
	// audit EVERY detection in detect/shadow mode, not just the aggregate below.
	f := *res.Decision
	f.Action = mode
	tx.findings = append(tx.findings, f)
	// Take the first finding outright; thereafter only a strictly higher
	// severity replaces the attribution (as a unit).
	if final.Reason == "" || res.Decision.Severity > final.Severity {
		final.Reason = res.Decision.Reason
		final.RuleID = res.Decision.RuleID
		final.Engine = res.Decision.Engine
		final.Severity = res.Decision.Severity
	}
}

// failPosture applies the policy fail mode on stage error or deadline: fail-open
// allows (the running decision), fail-close blocks. The default when no policy
// is resolved is fail-open, so a bug never blackholes traffic.
func (p *Pipeline) failPosture(tx *Transaction, err error, final *decision.Decision, timedOut bool) *decision.Decision {
	failOpen := tx.Policy == nil || tx.Policy.FailOpen()
	if po, ok := p.observer.(PostureObserver); ok {
		if timedOut {
			po.Timeout()
		}
		if failOpen {
			po.FailOpen()
		} else {
			po.FailClose()
		}
	}
	if failOpen {
		return final
	}
	// Keep the auditable reason a fixed constant: never fold the underlying engine/
	// stage error string into the decision (it flows to audit, and a future engine
	// could embed request data in its error). timedOut distinguishes the cause.
	reason := "fail_close_error"
	if timedOut {
		reason = "fail_close_timeout"
	}
	return &decision.Decision{
		Action:     decision.Block,
		Reason:     reason,
		PolicyID:   tx.PolicyID(),
		StatusCode: decision.DefaultBlockStatus,
	}
}
