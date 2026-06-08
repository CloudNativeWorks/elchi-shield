package runtime

import (
	"sync/atomic"
	"time"
)

// Store holds the active Snapshot behind an atomic pointer. Reads on the hot
// path are lock-free (a single atomic load); reloads swap in a new Snapshot
// atomically. The previously-active Snapshot keeps serving any in-flight
// requests that already loaded it and is reclaimed by the GC once they finish.
//
// Store has no other mutable state, satisfying the "no global mutable state"
// constraint: the only shared state in the system is the immutable Snapshot
// referenced here, replaced wholesale rather than mutated in place.
type Store struct {
	ptr atomic.Pointer[Snapshot]
}

// NewStore returns a Store seeded with initial. If initial is nil it is seeded
// with an empty snapshot so Load never returns nil.
func NewStore(initial *Snapshot) *Store {
	s := &Store{}
	if initial == nil {
		initial = EmptySnapshot(time.Time{})
	}
	s.ptr.Store(initial)
	return s
}

// Load returns the currently-active Snapshot. It is safe for concurrent use and
// allocation-free; this is the hot-path entry point. The returned pointer is
// stable for the caller's use even if a reload swaps in a new snapshot
// meanwhile.
func (s *Store) Load() *Snapshot {
	return s.ptr.Load()
}

// Set atomically installs snap as the active Snapshot. It is a no-op for a nil
// snapshot to preserve the invariant that an active snapshot always exists.
func (s *Store) Set(snap *Snapshot) {
	if snap == nil {
		return
	}
	s.ptr.Store(snap)
}
