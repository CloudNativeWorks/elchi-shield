package pipeline

import (
	"context"
	"strconv"
)

// Phase groups stages so the executor can gate whole groups per request without
// each stage re-checking. Phases also define the canonical execution order: a
// Pipeline's stages must be in non-decreasing Phase order (validated at build
// time), encoding "cheap checks before expensive ones".
type Phase uint8

const (
	// PhasePreCheck is context init, policy resolution, header/method/IP checks,
	// and early decision. It never reads the body.
	PhasePreCheck Phase = iota
	// PhaseBodyGate decides whether the body is needed and enforces size caps
	// before any buffering.
	PhaseBodyGate
	// PhaseBody is body inspection (JSON, schema, sensitive data), gated by
	// tx.BodyRequired.
	PhaseBody
	// PhaseWAF is the pluggable WAF/security engines, gated by tx.WAFEnabled.
	PhaseWAF
	// PhaseFinal aggregates verdicts and emits the decision.
	PhaseFinal
	// PhaseAudit is audit/metrics; it should not block the request path.
	PhaseAudit
)

// String renders the phase for logs/metrics.
func (p Phase) String() string {
	switch p {
	case PhasePreCheck:
		return "precheck"
	case PhaseBodyGate:
		return "body_gate"
	case PhaseBody:
		return "body"
	case PhaseWAF:
		return "waf"
	case PhaseFinal:
		return "final"
	case PhaseAudit:
		return "audit"
	default:
		return "phase(" + strconv.Itoa(int(p)) + ")"
	}
}

// Stage is one composable, stateless unit of the filter chain. Implementations
// must keep all per-request state in tx (never in the Stage), must be safe for
// concurrent use across requests, and must be precompiled (no per-request regex
// compilation or config parsing). A Stage may be reused across the request and
// response pipelines via tx.Direction.
type Stage interface {
	// Name identifies the stage in logs/metrics; must be stable and unique.
	Name() string
	// Phase determines ordering and gating.
	Phase() Phase
	// Process inspects tx and returns a control-flow result. It must respect
	// ctx cancellation/deadline and must not panic intentionally (the executor
	// recovers panics, but stages should return ActionError instead).
	Process(ctx context.Context, tx *Transaction) StageResult
}
