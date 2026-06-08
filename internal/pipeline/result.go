package pipeline

import "github.com/cloudnativeworks/elchi-shield/internal/decision"

// StageResult is the value a Stage returns. It is intentionally tiny and
// returned by value: a plain ActionContinue allocates nothing. Audit events are
// NOT carried here — stages append them to the Transaction so the hot-path
// result stays allocation-free.
type StageResult struct {
	// Action is the control-flow signal (required).
	Action StageAction
	// Decision carries attribution for terminal/recorded outcomes (Deny, Allow,
	// ShadowDetect). Optional; nil for plain Continue.
	Decision *decision.Decision
	// Err is set only with ActionError.
	Err error
}

// Continue is the common zero-cost result: run the next stage.
func Continue() StageResult { return StageResult{Action: ActionContinue} }

// Allow terminally allows the request.
func Allow(d *decision.Decision) StageResult {
	return StageResult{Action: ActionAllow, Decision: d}
}

// Deny signals a block with attribution; the executor applies mode mapping.
func Deny(d *decision.Decision) StageResult {
	return StageResult{Action: ActionDeny, Decision: d}
}

// ShadowDetect records a finding and continues regardless of mode.
func ShadowDetect(d *decision.Decision) StageResult {
	return StageResult{Action: ActionShadowDetect, Decision: d}
}

// SkipBody disables body-gated stages for this request.
func SkipBody() StageResult { return StageResult{Action: ActionSkipBody} }

// SkipRemaining stops the pipeline and proceeds with the accumulated decision.
func SkipRemaining() StageResult { return StageResult{Action: ActionSkipRemaining} }

// Fail reports a stage error; the executor applies the policy fail posture.
func Fail(err error) StageResult { return StageResult{Action: ActionError, Err: err} }
