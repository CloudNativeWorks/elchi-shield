package runtime

import (
	"sync/atomic"
	"time"
)

// reloadState is an immutable snapshot of the most recent reload health, swapped
// atomically. It records the last FAILED reload's attributed config error so an
// operator — and the elchi-client confirmation probe reading /configz — can see
// WHY a config was rejected, not just that the failure counter advanced.
type reloadState struct {
	lastError string
	failures  uint64
	failedAt  time.Time
}

// ReloadStatus holds the last-reload health. It is written by the single reload
// goroutine (via doReload) and read lock-free by the /configz handler. Cold path
// only — never touched on the request hot path. The zero value is ready to use
// (reports no failures).
type ReloadStatus struct {
	p atomic.Pointer[reloadState]
}

// NewReloadStatus returns an empty status (no failures recorded).
func NewReloadStatus() *ReloadStatus { return &ReloadStatus{} }

// RecordFailure stores the attributed reason of a rejected reload and advances the
// cumulative failure count. at is the time the failure was observed.
func (s *ReloadStatus) RecordFailure(reason string, at time.Time) {
	var n uint64
	if prev := s.p.Load(); prev != nil {
		n = prev.failures
	}
	s.p.Store(&reloadState{lastError: reason, failures: n + 1, failedAt: at})
}

// RecordSuccess clears the last error after a config successfully loaded. The
// cumulative failure count is preserved as history.
func (s *ReloadStatus) RecordSuccess() {
	prev := s.p.Load()
	if prev == nil || prev.lastError == "" {
		return // already clean — avoid a needless swap/alloc
	}
	s.p.Store(&reloadState{lastError: "", failures: prev.failures, failedAt: prev.failedAt})
}

// Snapshot returns the last reload error (empty when the last reload succeeded),
// the cumulative failure count, and the time of the last failure.
func (s *ReloadStatus) Snapshot() (lastError string, failures uint64, failedAt time.Time) {
	if st := s.p.Load(); st != nil {
		return st.lastError, st.failures, st.failedAt
	}
	return "", 0, time.Time{}
}
