package audit

import (
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
)

// Event is a single structured audit record produced during request/response
// inspection. It is redacted by construction: it carries only the decision,
// attribution, and non-sensitive request metadata (host/path/method) — never
// header values or body content. Per-finding events accumulate on the
// Transaction; the terminal event is emitted at the ext_proc boundary.
type Event struct {
	Timestamp     time.Time         `json:"timestamp"`
	Instance      string            `json:"instance,omitempty"`
	NodeID        string            `json:"node_id,omitempty"`    // raw Envoy node id (ext_proc attribute)
	ProjectID     string            `json:"project_id,omitempty"` // parsed from node id (listener::project::ip)
	Listener      string            `json:"listener,omitempty"`   // parsed listener name from node id
	RequestID     string            `json:"request_id,omitempty"`
	Phase         string            `json:"phase,omitempty"`
	Direction     string            `json:"direction,omitempty"`
	Decision      decision.Decision `json:"decision"`
	Host          string            `json:"host,omitempty"`
	Path          string            `json:"path,omitempty"`
	Method        string            `json:"method,omitempty"`
	ConfigVersion string            `json:"config_version,omitempty"`
}

// Severity returns the event's severity (from its decision), used for
// worst-severity tracking on the Transaction.
func (e Event) Severity() decision.Severity { return e.Decision.Severity }

// isFinding reports whether the event records an actual finding (block/detect/
// shadow) rather than a plain allow. Findings are always exported; the allow
// stream is rate-limited.
func isFinding(ev *Event) bool {
	a := ev.Decision.Action
	return a != decision.Allow && a != decision.Continue
}
