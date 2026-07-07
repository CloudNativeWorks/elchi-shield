package runtime

import (
	"errors"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
)

// Outcome describes the result of a reload attempt.
type Outcome int

const (
	// OutcomeApplied: a new, different snapshot was swapped in.
	OutcomeApplied Outcome = iota
	// OutcomeUnchanged: config parsed but is identical to the active snapshot.
	OutcomeUnchanged
	// OutcomeEmpty: the config dir has no files; the current snapshot is kept.
	OutcomeEmpty
	// OutcomeFailed: parse/validate/compile failed; the current snapshot is kept.
	OutcomeFailed
)

// String renders the outcome for logs/metrics.
func (o Outcome) String() string {
	switch o {
	case OutcomeApplied:
		return "applied"
	case OutcomeUnchanged:
		return "unchanged"
	case OutcomeEmpty:
		return "empty"
	case OutcomeFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Reloader loads the config directory, compiles a snapshot, and atomically swaps
// it into the Store. It embodies the keep-last-good contract: on any
// parse/validate/compile failure (or an emptied directory) the currently-active
// snapshot is left untouched. It holds no mutable state beyond the injected
// Store, so it is safe to call Reload from a single watcher goroutine.
type Reloader struct {
	store  *Store
	dir    string
	now    func() time.Time
	retire func(*Snapshot)
}

// NewReloader builds a Reloader for dir. now supplies the snapshot build time
// (inject time.Now in production); if nil, time.Now is used.
func NewReloader(store *Store, dir string, now func() time.Time) *Reloader {
	if now == nil {
		now = time.Now
	}
	return &Reloader{store: store, dir: dir, now: now}
}

// OnRetire registers a callback invoked with the previously-active snapshot when
// a new one is applied. The caller typically closes it after a grace period so
// in-flight requests finish first. It is not called for the empty snapshot.
func (r *Reloader) OnRetire(f func(*Snapshot)) { r.retire = f }

// Dir returns the watched config directory.
func (r *Reloader) Dir() string { return r.dir }

// Reload reads and compiles the config directory and swaps in a new snapshot if
// it differs from the active one. It returns the outcome, the snapshot that is
// active after the call (always non-nil once the store is seeded), and any
// error. On OutcomeFailed/OutcomeEmpty the active snapshot is unchanged.
func (r *Reloader) Reload() (Outcome, *Snapshot, error) {
	cfg, err := config.Load(r.dir)
	if errors.Is(err, config.ErrEmptyConfigDir) {
		// Keep the last-good snapshot rather than wiping active protection when
		// all files are (perhaps accidentally) removed.
		return OutcomeEmpty, r.store.Load(), nil
	}
	if err != nil {
		return OutcomeFailed, r.store.Load(), err
	}

	// Hash BEFORE compiling the snapshot: an unchanged config short-circuits here
	// without building the engine set. Compiling first and discarding on "unchanged"
	// leaked a jwks background-refresher goroutine (never Close()d) and re-ran the
	// CRS compile on every re-push of identical config — the common case under a
	// management-plane reconcile.
	snapHash, err := computeHash(cfg)
	if err != nil {
		return OutcomeFailed, r.store.Load(), err
	}
	prev := r.store.Load()
	if prev != nil && prev.Hash() == snapHash {
		return OutcomeUnchanged, prev, nil
	}

	snap, err := NewSnapshot(cfg, r.now())
	if err != nil {
		return OutcomeFailed, r.store.Load(), err
	}

	r.store.Set(snap)
	if r.retire != nil && prev != nil && !prev.IsEmpty() {
		r.retire(prev)
	}
	return OutcomeApplied, snap, nil
}
