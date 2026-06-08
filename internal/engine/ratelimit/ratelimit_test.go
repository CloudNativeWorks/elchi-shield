package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

type hdrs map[string]string

func (h hdrs) Header(name string) (string, bool) {
	for k, v := range h {
		if equalFold(k, name) {
			return v, true
		}
	}
	return "", false
}
func (h hdrs) RangeHeaders(fn func(string, string) bool) {
	for k, v := range h {
		if !fn(k, v) {
			return
		}
	}
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func req(h hdrs) *engine.Request {
	return &engine.Request{Direction: engine.DirectionRequest, Host: "api.example.com", Headers: h}
}

func TestRateLimitBurstThenBlock(t *testing.T) {
	now := time.Unix(0, 0)
	e, err := New(Config{RequestsPerSecond: 1, Burst: 3, Key: KeyIP, now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	r := req(hdrs{"X-Forwarded-For": "1.2.3.4, 10.0.0.1"})

	// Burst of 3 allowed, then blocked (clock frozen → no refill).
	for range 3 {
		if v, _ := e.Inspect(context.Background(), r); v.Action == decision.Block {
			t.Fatal("request within burst should pass")
		}
	}
	v, _ := e.Inspect(context.Background(), r)
	if v.Action != decision.Block || v.StatusCode != 429 || v.RuleID != "ratelimit.exceeded" {
		t.Fatalf("4th request should be blocked with 429: %+v", v)
	}

	// After 1 second, one token refills → one request allowed again.
	now = now.Add(time.Second)
	if v, _ := e.Inspect(context.Background(), r); v.Action == decision.Block {
		t.Fatal("a token should have refilled after 1s")
	}
	if v, _ := e.Inspect(context.Background(), r); v.Action != decision.Block {
		t.Fatal("only one token refilled; second request should block")
	}
}

func TestRateLimitPerKeyIsolation(t *testing.T) {
	now := time.Unix(0, 0)
	e, _ := New(Config{RequestsPerSecond: 1, Burst: 1, Key: KeyIP, now: func() time.Time { return now }})
	// Different IPs have independent buckets.
	if v, _ := e.Inspect(context.Background(), req(hdrs{"X-Forwarded-For": "1.1.1.1"})); v.Action == decision.Block {
		t.Fatal("first IP should pass")
	}
	if v, _ := e.Inspect(context.Background(), req(hdrs{"X-Forwarded-For": "2.2.2.2"})); v.Action == decision.Block {
		t.Fatal("a different IP must not share the first IP's bucket")
	}
	if v, _ := e.Inspect(context.Background(), req(hdrs{"X-Forwarded-For": "1.1.1.1"})); v.Action != decision.Block {
		t.Fatal("first IP's second request should block")
	}
}

func TestRateLimitNoKeyDoesNotBlock(t *testing.T) {
	e, _ := New(Config{RequestsPerSecond: 1, Burst: 1, Key: KeyIP})
	// No X-Forwarded-For → no key → never block (don't fail-closed on missing IP).
	for range 5 {
		if v, _ := e.Inspect(context.Background(), req(hdrs{})); v.Action == decision.Block {
			t.Fatal("missing key must not block")
		}
	}
}

func TestRateLimitResponseDirectionPasses(t *testing.T) {
	e, _ := New(Config{RequestsPerSecond: 1, Burst: 0, Key: KeyHost})
	r := &engine.Request{Direction: engine.DirectionResponse, Host: "api.example.com", Headers: hdrs{}}
	if v, _ := e.Inspect(context.Background(), r); v.Action == decision.Block {
		t.Fatal("response direction must pass through")
	}
}

func TestRateLimitConfigValidation(t *testing.T) {
	if _, err := New(Config{RequestsPerSecond: 0}); err == nil {
		t.Fatal("rps <= 0 must error")
	}
}

// BenchmarkRateLimitContended measures the worst case: every goroutine hits the
// SAME key (so the same shard lock) at a very high limit (never blocks). It
// quantifies the per-request cost of the engine's one contained lock.
func BenchmarkRateLimitContended(b *testing.B) {
	e, _ := New(Config{RequestsPerSecond: 1e12, Burst: 1e12, Key: KeyHost})
	r := req(hdrs{})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = e.Inspect(context.Background(), r)
		}
	})
}
