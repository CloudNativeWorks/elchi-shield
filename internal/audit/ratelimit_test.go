package audit

import (
	"testing"
	"time"
)

func TestRateLimiterCapsBurst(t *testing.T) {
	now := time.Unix(0, 0)
	rl := newRateLimiter(10, func() time.Time { return now })

	admitted := 0
	for range 100 {
		if rl.Allow() {
			admitted++
		}
	}
	// With a full bucket of capacity 10 and no time advancing, ~10 are admitted.
	if admitted != 10 {
		t.Fatalf("burst should be capped at capacity 10, got %d", admitted)
	}
}

func TestRateLimiterRefills(t *testing.T) {
	now := time.Unix(0, 0)
	rl := newRateLimiter(10, func() time.Time { return now })

	for range 10 { // drain
		rl.Allow()
	}
	if rl.Allow() {
		t.Fatal("bucket should be empty")
	}
	// Advance 1s → 10 tokens refilled.
	now = now.Add(time.Second)
	admitted := 0
	for range 20 {
		if rl.Allow() {
			admitted++
		}
	}
	if admitted != 10 {
		t.Fatalf("1s should refill 10 tokens, got %d", admitted)
	}
}

func TestRateLimiterUnlimited(t *testing.T) {
	var rl *RateLimiter // nil → unlimited
	if !rl.Allow() {
		t.Fatal("nil limiter should allow")
	}
	rl2 := NewRateLimiter(0)
	for range 1000 {
		if !rl2.Allow() {
			t.Fatal("zero rate should be unlimited")
		}
	}
}
