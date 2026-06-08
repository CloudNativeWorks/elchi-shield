package extproc

import "sync/atomic"

// bodyBudget bounds the total request/response body bytes buffered across ALL
// concurrent streams. Without it, a per-request body cap still permits
// MaxConcurrentStreams × cap of resident memory (e.g. 8192 × 1 MiB), so a burst
// of concurrent large BUFFERED bodies could exhaust host memory — the classic
// ext_proc memory-amplification DoS. It is a single shared, lock-free atomic
// counter; reservations are made as body chunks arrive and released when the
// stream ends. A non-positive limit disables it.
type bodyBudget struct {
	limit int64
	inUse atomic.Int64
}

// newBodyBudget returns a budget capping total buffered body bytes at limit
// (≤0 disables enforcement).
func newBodyBudget(limit int64) *bodyBudget {
	return &bodyBudget{limit: limit}
}

// Acquire reserves up to n bytes and returns the amount actually granted (0..n).
// A short grant means the global budget is exhausted and the caller must treat
// the body as truncated (so the non-skippable truncation guard blocks it rather
// than inspecting a partial body as clean). A nil/disabled budget grants n. It
// satisfies pipeline.BodyBudget so the decode stage can charge decoded bytes.
func (b *bodyBudget) Acquire(n int64) int64 {
	if b == nil || b.limit <= 0 || n <= 0 {
		return n
	}
	for {
		cur := b.inUse.Load()
		avail := b.limit - cur
		if avail <= 0 {
			return 0
		}
		grant := n
		if grant > avail {
			grant = avail
		}
		if b.inUse.CompareAndSwap(cur, cur+grant) {
			return grant
		}
	}
}

// Release returns n previously-acquired bytes to the budget.
func (b *bodyBudget) Release(n int64) {
	if b == nil || b.limit <= 0 || n <= 0 {
		return
	}
	b.inUse.Add(-n)
}

// InUseBytes reports the bytes currently reserved (for the metrics gauge).
func (b *bodyBudget) InUseBytes() int64 {
	if b == nil {
		return 0
	}
	return b.inUse.Load()
}
