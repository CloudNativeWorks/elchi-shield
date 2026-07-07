package runtime

import (
	"sync/atomic"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/policy"
)

// emptyVersion is the version id reported by an empty snapshot (no config yet).
const emptyVersion = "empty"

// Snapshot is an immutable, point-in-time view of the active configuration. Once
// built it is never mutated; reloads create a new Snapshot and atomically swap
// it into the Store. Because it is read-only, every request on the hot path can
// read it without locks. Phase 2 enriches it with the compiled policy resolver
// built from cfg; the public accessors stay stable.
type Snapshot struct {
	version  string
	hash     string
	builtAt  time.Time
	sources  []string
	cfg      *config.MergedConfig
	resolver *policy.Resolver
	// refs counts streams that have pinned this snapshot (Acquire) and not yet
	// released it. The retirer waits for this to hit zero before Close() frees the
	// engines, so a stream still holding the snapshot never sees a use-after-close.
	refs atomic.Int64
}

// NewSnapshot compiles a validated MergedConfig into an immutable Snapshot:
// it computes the content hash/version and compiles the policy resolver (all
// matchers/regexes built here, off the hot path). The supplied config must
// already be validated; NewSnapshot does not re-validate. The cfg pointer must
// not be mutated by the caller afterwards (Snapshot assumes exclusive ownership).
func NewSnapshot(cfg *config.MergedConfig, builtAt time.Time) (*Snapshot, error) {
	hash, err := computeHash(cfg)
	if err != nil {
		return nil, err
	}
	resolver, err := policy.Compile(cfg)
	if err != nil {
		return nil, err
	}
	sources := append([]string(nil), cfg.Sources...)
	return &Snapshot{
		version:  shortVersion(hash),
		hash:     hash,
		builtAt:  builtAt,
		sources:  sources,
		cfg:      cfg,
		resolver: resolver,
	}, nil
}

// EmptySnapshot returns a valid, empty Snapshot used before any config is loaded
// (safe startup with no config). It matches nothing; the caller's default
// posture decides what happens to traffic in this state.
func EmptySnapshot(builtAt time.Time) *Snapshot {
	return &Snapshot{
		version: emptyVersion,
		hash:    emptyVersion,
		builtAt: builtAt,
		cfg:     &config.MergedConfig{},
	}
}

// Version returns the short, human-friendly version id (active config version).
func (s *Snapshot) Version() string { return s.version }

// Hash returns the full content hash.
func (s *Snapshot) Hash() string { return s.hash }

// BuiltAt returns when this snapshot was compiled.
func (s *Snapshot) BuiltAt() time.Time { return s.builtAt }

// Sources returns the config files that contributed to this snapshot.
func (s *Snapshot) Sources() []string { return s.sources }

// Config returns the immutable merged config backing this snapshot. Callers
// must treat it as read-only.
func (s *Snapshot) Config() *config.MergedConfig { return s.cfg }

// Resolver returns the compiled policy resolver for hot-path policy lookup. It
// is nil for the empty snapshot (no config yet); callers must treat a nil
// resolver as "no policy matched" and apply their default posture.
func (s *Snapshot) Resolver() *policy.Resolver { return s.resolver }

// DomainCount reports how many domains the snapshot serves.
func (s *Snapshot) DomainCount() int {
	if s.cfg == nil {
		return 0
	}
	return len(s.cfg.Domains)
}

// IsEmpty reports whether this is the empty (no-config) snapshot.
func (s *Snapshot) IsEmpty() bool { return s.version == emptyVersion }

// Close releases resources held by the snapshot's compiled policies (engines).
// Call it on a retired snapshot once no in-flight request can still reference it.
func (s *Snapshot) Close() error {
	if s == nil {
		return nil
	}
	return s.resolver.Close()
}

// Acquire marks one in-flight holder (a stream that pinned this snapshot). Nil-safe.
func (s *Snapshot) Acquire() {
	if s != nil {
		s.refs.Add(1)
	}
}

// Release drops one holder. Nil-safe.
func (s *Snapshot) Release() {
	if s != nil {
		s.refs.Add(-1)
	}
}

// Refs reports how many streams currently hold this snapshot pinned.
func (s *Snapshot) Refs() int64 {
	if s == nil {
		return 0
	}
	return s.refs.Load()
}
