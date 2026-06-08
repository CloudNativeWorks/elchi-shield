package audit

import (
	"sync"
	"time"
)

// RateLimiter is a token-bucket limiter used for dynamic (adaptive) audit
// sampling: it caps the number of admitted events per second regardless of
// per-policy sampling rates, so a traffic spike can't overwhelm the audit sink.
// Findings (blocks) should bypass it; it governs the high-volume "allow" stream.
// A non-positive rate disables limiting (Allow always true).
type RateLimiter struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
	now      func() time.Time
}

// NewRateLimiter builds a limiter admitting up to perSec events/second with a
// burst capacity of perSec. perSec <= 0 means unlimited.
func NewRateLimiter(perSec float64) *RateLimiter {
	return newRateLimiter(perSec, time.Now)
}

// newRateLimiter allows injecting a clock for tests.
func newRateLimiter(perSec float64, now func() time.Time) *RateLimiter {
	capacity := perSec
	if capacity < 1 {
		capacity = 1
	}
	return &RateLimiter{
		rate:     perSec,
		capacity: capacity,
		tokens:   capacity,
		last:     now(),
		now:      now,
	}
}

// Allow reports whether one event may be admitted now, consuming a token.
func (r *RateLimiter) Allow() bool {
	if r == nil || r.rate <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	elapsed := now.Sub(r.last).Seconds()
	if elapsed > 0 {
		r.tokens += elapsed * r.rate
		if r.tokens > r.capacity {
			r.tokens = r.capacity
		}
		r.last = now
	}
	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}
