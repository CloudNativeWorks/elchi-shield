package engine

// CorazaConfig holds the Coraza ruleset configuration. The actual Coraza adapter
// lives in internal/engine/coraza behind the `coraza` build tag and registers
// itself via RegisterCoraza in its init(); this keeps the heavy dependency out
// of the default build.
type CorazaConfig struct {
	Directives     string   // inline SecLang directives
	IncludeOWASP   bool     // load the OWASP CRS (adapter-provided)
	ExcludeRuleIDs []string // rule IDs to disable
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
