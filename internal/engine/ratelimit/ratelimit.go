// Package ratelimit provides a SecurityEngine that enforces a per-key token-bucket
// rate limit (per client IP, host, or a header value). It is a light,
// always-available engine built into the default binary and runs at the header
// phase (it never needs the body).
//
// Rate limiting inherently needs shared mutable state, so this engine keeps a
// sharded map of buckets guarded by per-shard mutexes — a deliberate, contained
// exception to the otherwise lock-free request path, taken only when a policy
// opts in. Sharding (by key hash) keeps lock contention low.
package ratelimit

import (
	"context"
	"errors"
	"hash/maphash"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

// KeySource selects what a request is rate-limited by.
type KeySource uint8

const (
	// KeyIP limits by the trusted, pre-derived client IP (req.SourceIP).
	KeyIP KeySource = iota
	// KeyHost limits by request authority/host.
	KeyHost
	// KeyHeader limits by the value of a named header.
	KeyHeader
)

// Config configures the rate-limit engine.
type Config struct {
	// RequestsPerSecond is the sustained allowed rate per key (> 0).
	RequestsPerSecond float64
	// Burst is the bucket capacity (max instantaneous burst). Defaults to
	// ceil(RequestsPerSecond) when <= 0.
	Burst int
	// Key selects the rate-limit dimension.
	Key KeySource
	// Header is the header read for KeyHeader. (KeyIP keys on the trusted,
	// pre-derived SourceIP and never reads a raw header.)
	Header string
	// now is injectable for tests; defaults to time.Now.
	now func() time.Time
}

const (
	numShards       = 64    // power of two; mask with numShards-1
	maxKeysPerShard = 16384 // coarse memory bound; a full shard is reset
	// unkeyedBucket is the shared bucket for requests that lack the configured
	// selector (absent keyed header / empty source IP). The NUL prefix cannot
	// collide with a real IP or header value.
	unkeyedBucket = "\x00__unkeyed__"
)

// Engine enforces a token-bucket rate limit. It is safe for concurrent use.
type Engine struct {
	cfg    Config
	rps    float64
	burst  float64
	now    func() time.Time
	seed   maphash.Seed
	shards [numShards]shard
}

type shard struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New builds a rate-limit engine.
func New(cfg Config) (*Engine, error) {
	if cfg.RequestsPerSecond <= 0 {
		return nil, errors.New("ratelimit: requests_per_second must be > 0")
	}
	burst := float64(cfg.Burst)
	if burst <= 0 {
		burst = cfg.RequestsPerSecond
		if burst < 1 {
			burst = 1
		}
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	e := &Engine{cfg: cfg, rps: cfg.RequestsPerSecond, burst: burst, now: now, seed: maphash.MakeSeed()}
	for i := range e.shards {
		e.shards[i].buckets = make(map[string]*bucket)
	}
	return e, nil
}

// Name implements engine.SecurityEngine.
func (e *Engine) Name() string { return "ratelimit" }

// RequiresBody implements engine.SecurityEngine. Rate limiting reads only headers.
func (e *Engine) RequiresBody() bool { return false }

// Close implements engine.SecurityEngine.
func (e *Engine) Close() error { return nil }

// Inspect consumes one token for the request's key and blocks (429) when the
// bucket is empty. Responses pass through (limiting is a request-side control).
func (e *Engine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	if req.Direction != engine.DirectionRequest {
		return decision.Verdict{}, nil
	}
	key := e.key(req)
	if key == "" {
		// A request lacking the configured selector (an absent keyed header, or an
		// empty source IP) shares ONE "unkeyed" bucket rather than being exempt —
		// otherwise dropping the header/IP would be a complete rate-limit bypass.
		key = unkeyedBucket
	}
	if e.allow(key) {
		return decision.Verdict{}, nil
	}
	return decision.Verdict{
		Action:     decision.Block,
		Reason:     "rate limit exceeded",
		RuleID:     "ratelimit.exceeded",
		Engine:     "ratelimit",
		Severity:   decision.SeverityLow,
		StatusCode: 429,
	}, nil
}

// key derives the rate-limit key from the request per the configured source.
func (e *Engine) key(req *engine.Request) string {
	switch e.cfg.Key {
	case KeyHost:
		return canonHost(req.Host)
	case KeyHeader:
		if v, ok := req.Headers.Header(e.cfg.Header); ok {
			return v
		}
		return ""
	default: // KeyIP
		// Key ONLY on the trusted, pre-derived client IP (tx.SourceIP, the single
		// source of truth — derived from the rightmost trusted X-Forwarded-For hop).
		// Never read a raw XFF token here: the leftmost is client-settable, so an
		// attacker could rotate it to mint unlimited fresh buckets and evade the
		// limit entirely. An empty SourceIP yields no key → the caller routes it to
		// the shared unkeyed bucket (not exempt).
		return req.SourceIP
	}
}

// canonHost normalizes a host key: trailing :port stripped, IPv6 brackets
// removed, lowercased — so an attacker can't split a host's bucket by varying the
// port or letter case of the authority.
func canonHost(h string) string {
	h = strings.TrimSpace(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.Trim(h, "[]"))
}

// allow refills the key's bucket by elapsed time and consumes one token,
// returning whether the request is within the limit.
func (e *Engine) allow(key string) bool {
	s := &e.shards[e.shardIndex(key)]
	now := e.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	b := s.buckets[key]
	if b == nil {
		if len(s.buckets) >= maxKeysPerShard {
			// Memory bound under a key-flood. Evict ONLY idle (fully-refilled) buckets —
			// dropping a full bucket is a no-op, since it would be recreated at full
			// tokens anyway. Unlike the old whole-shard wipe, this never resets an
			// ACTIVE/limited key that co-hashes to this shard (which handed collateral
			// victims a fresh full bucket, a transient rate-limit bypass).
			fullAt := e.burst / e.rps // seconds for an empty bucket to refill to burst
			for k, bk := range s.buckets {
				if now.Sub(bk.last).Seconds() >= fullAt {
					delete(s.buckets, k)
				}
			}
			if len(s.buckets) >= maxKeysPerShard {
				// Still saturated: a genuine flood of distinct ACTIVE keys. Serve this one
				// a fresh bucket WITHOUT storing it — a key seen once needs no state — so
				// memory stays bounded without disturbing any other key's bucket.
				return true
			}
		}
		s.buckets[key] = &bucket{tokens: e.burst - 1, last: now}
		return true
	}
	// Refill: tokens accrue at rps per second, capped at burst.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * e.rps
		if b.tokens > e.burst {
			b.tokens = e.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (e *Engine) shardIndex(key string) uint64 {
	return maphash.String(e.seed, key) & (numShards - 1)
}
