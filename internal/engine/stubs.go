package engine

// CorazaConfig holds the Coraza ruleset configuration. The actual Coraza adapter
// lives in internal/engine/coraza and registers itself via RegisterCoraza in its
// init(), triggered by a blank import in cmd/elchi-shield that is always compiled.
// This registry indirection avoids an engine→coraza import cycle.
type CorazaConfig struct {
	Directives     string   // inline SecLang directives
	IncludeOWASP   bool     // load the embedded OWASP CRS (adapter-provided)
	ExcludeRuleIDs []string // rule IDs to disable

	// CRS collaborative-scoring tuning. Only applied when IncludeOWASP is true; a
	// zero value leaves the CRS default in place (PL1, inbound 5, outbound 4).
	ParanoiaLevel            int // blocking paranoia level 1..4
	DetectionParanoiaLevel   int // detection paranoia level (>= blocking); 0 = same as blocking
	InboundAnomalyThreshold  int // request-side anomaly score that blocks
	OutboundAnomalyThreshold int // response-side anomaly score that blocks
}

// corazaFactory is set by the adapter package's init().
var corazaFactory func(CorazaConfig) (SecurityEngine, error)

// RegisterCoraza installs the Coraza constructor. Called from the adapter
// package's init().
func RegisterCoraza(f func(CorazaConfig) (SecurityEngine, error)) {
	corazaFactory = f
}

// NewCoraza builds a Coraza engine via the registered adapter factory. The
// factory is always registered in the normal binary; the nil check is a
// defensive fallback (e.g. a unit test that builds the engine without importing
// the adapter), returning ErrNotImplemented rather than panicking.
func NewCoraza(cfg CorazaConfig) (SecurityEngine, error) {
	if corazaFactory == nil {
		return nil, ErrNotImplemented
	}
	return corazaFactory(cfg)
}
