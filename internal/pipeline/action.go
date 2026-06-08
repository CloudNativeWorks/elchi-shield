// Package pipeline implements an Envoy-style security filter chain. A request
// (or response) flows through an ordered list of small, precompiled, stateless
// Stages that short-circuit as early as possible. All per-request state lives in
// a pooled Transaction; the executor owns the cross-cutting concerns
// (short-circuit, phase gating, panic recovery, deadlines, fail-open/close, and
// per-stage metrics) so stages stay trivial and testable.
//
// The hot path never constructs stages, compiles regexes, or parses config: a
// Pipeline is assembled once from immutable Stages and reused for every request.
package pipeline

import "strconv"

// StageAction is the control-flow signal a Stage returns to the executor. It is
// a small value type to keep StageResult allocation-free.
type StageAction uint8

const (
	// ActionContinue runs the next stage.
	ActionContinue StageAction = iota
	// ActionAllow terminally allows the request and stops the pipeline.
	ActionAllow
	// ActionDeny signals a block. The executor maps it through the policy mode:
	// in block mode it terminally denies; in detect/shadow it records a
	// would-block event and continues (never actually blocks).
	ActionDeny
	// ActionShadowDetect always records a finding and continues, regardless of
	// mode (an explicit shadow signal).
	ActionShadowDetect
	// ActionSkipBody disables body-gated stages (Body, WAF) for this request.
	ActionSkipBody
	// ActionSkipRemaining stops the pipeline and proceeds (allow) with whatever
	// has been accumulated so far.
	ActionSkipRemaining
	// ActionError reports a stage failure. The executor applies the policy fail
	// posture: fail-open continues, fail-close denies.
	ActionError
)

// String renders the action for logs/metrics.
func (a StageAction) String() string {
	switch a {
	case ActionContinue:
		return "continue"
	case ActionAllow:
		return "allow"
	case ActionDeny:
		return "deny"
	case ActionShadowDetect:
		return "shadow_detect"
	case ActionSkipBody:
		return "skip_body"
	case ActionSkipRemaining:
		return "skip_remaining"
	case ActionError:
		return "error"
	default:
		return "action(" + strconv.Itoa(int(a)) + ")"
	}
}
