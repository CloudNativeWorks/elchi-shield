// Package decision defines the small value types describing the outcome of
// request/response inspection. These are deliberately allocation-friendly value
// types (no interfaces) so they can flow through the hot path cheaply. A
// Decision is the aggregate outcome carried out of the pipeline; a Verdict is a
// lighter, per-stage or per-engine finding that the final stage aggregates.
package decision

import (
	"encoding/json"
	"strconv"
)

// Action is the enforcement outcome.
type Action uint8

const (
	// Continue means no terminal decision was reached (pass to next stage).
	Continue Action = iota
	// Allow explicitly permits the request.
	Allow
	// Block denies the request (enforced).
	Block
	// Detect records a finding but allows the request (monitor mode).
	Detect
	// Shadow records a would-block finding but allows the request.
	Shadow
)

// String renders the action for logs/metrics.
func (a Action) String() string {
	switch a {
	case Continue:
		return "continue"
	case Allow:
		return "allow"
	case Block:
		return "block"
	case Detect:
		return "detect"
	case Shadow:
		return "shadow"
	default:
		return "action(" + strconv.Itoa(int(a)) + ")"
	}
}

// Blocking reports whether the action enforces a block.
func (a Action) Blocking() bool { return a == Block }

// MarshalJSON emits the action as its string name for readable audit output.
func (a Action) MarshalJSON() ([]byte, error) { return json.Marshal(a.String()) }

// Severity ranks the seriousness of a finding. Higher is worse; the final stage
// keeps the maximum severity seen.
type Severity uint8

// Severity levels, ordered from least to most serious.
const (
	SeverityNone Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String renders the severity for logs/metrics.
func (s Severity) String() string {
	switch s {
	case SeverityNone:
		return "none"
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "severity(" + strconv.Itoa(int(s)) + ")"
	}
}

// MarshalJSON emits the severity as its string name for readable audit output.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// DefaultBlockStatus is the HTTP status returned for an enforced block.
const DefaultBlockStatus = 403

// Decision is the aggregate outcome of a pipeline run. It is always non-nil at
// the pipeline boundary and carries attribution for observability and audit.
type Decision struct {
	Action     Action
	Reason     string
	RuleID     string
	PolicyID   string
	Engine     string
	Severity   Severity
	StatusCode int // HTTP status for Block; defaults to DefaultBlockStatus
}

// Verdict is a per-stage / per-engine finding. The final stage folds verdicts
// into a Decision via "most severe wins".
type Verdict struct {
	Action   Action
	Reason   string
	RuleID   string
	Engine   string
	Severity Severity
	// StatusCode optionally overrides the HTTP status for a Block (e.g. 429 from
	// the rate-limit engine). 0 means use DefaultBlockStatus (403).
	StatusCode int
}

// IsBlock reports whether this decision enforces a block.
func (d *Decision) IsBlock() bool { return d != nil && d.Action == Block }

// Allowed returns an allow Decision attributed to policyID.
func Allowed(policyID string) Decision {
	return Decision{Action: Allow, PolicyID: policyID}
}

// Blocked returns an enforced block Decision from a verdict's attribution. The
// verdict may override the HTTP status (e.g. 429); otherwise DefaultBlockStatus.
func Blocked(policyID string, v Verdict) Decision {
	status := v.StatusCode
	if status == 0 {
		status = DefaultBlockStatus
	}
	return Decision{
		Action:     Block,
		Reason:     v.Reason,
		RuleID:     v.RuleID,
		PolicyID:   policyID,
		Engine:     v.Engine,
		Severity:   v.Severity,
		StatusCode: status,
	}
}
