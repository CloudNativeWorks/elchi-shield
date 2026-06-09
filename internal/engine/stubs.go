package engine

// CorazaConfig holds the Coraza ruleset configuration. The actual Coraza adapter
// lives in internal/engine/coraza behind the `coraza` build tag and registers
// itself via RegisterCoraza in its init(); this keeps the heavy dependency out
// of the default build.
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

// corazaFactory is set by the build-tagged adapter's init().
var corazaFactory func(CorazaConfig) (SecurityEngine, error)

// RegisterCoraza installs the Coraza constructor. Called from the build-tagged
// adapter package's init().
func RegisterCoraza(f func(CorazaConfig) (SecurityEngine, error)) {
	corazaFactory = f
}

// NewCoraza builds a Coraza engine if the adapter was compiled in (via the
// `coraza` build tag); otherwise it returns ErrNotImplemented so a config that
// requests Coraza fails clearly on a binary without it.
func NewCoraza(cfg CorazaConfig) (SecurityEngine, error) {
	if corazaFactory == nil {
		return nil, ErrNotImplemented
	}
	return corazaFactory(cfg)
}
