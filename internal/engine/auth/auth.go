// Package auth provides shared primitives for the authentication engines
// (API-key, HMAC request signing): timing-safe comparison and a sharded,
// bounded replay/nonce cache. The cache's per-shard mutex is the SECOND
// sanctioned lock in the codebase (after rate-limit), contained to these opt-in
// engines — it never sits on a policy-evaluation path that doesn't use them.
package auth

import (
	"crypto/subtle"
	"hash/maphash"
	"sync"
	"time"
)

// ConstantTimeEqual reports whether a and b are equal without leaking their
// contents through timing.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

const (
	numShards       = 64    // power of two; mask with numShards-1
	maxKeysPerShard = 16384 // coarse memory bound; a saturated shard is reset
)

// ReplayCache records recently-seen nonces so a captured request signature
// cannot be replayed within its validity window. It is safe for concurrent use.
type ReplayCache struct {
	ttl    time.Duration
	now    func() time.Time
	seed   maphash.Seed
	shards [numShards]replayShard
}

type replayShard struct {
	mu   sync.Mutex
	seen map[string]time.Time // nonce → expiry
}

// NewReplayCache builds a replay cache whose entries live for ttl. now is
// injectable for tests (nil → time.Now).
func NewReplayCache(ttl time.Duration, now func() time.Time) *ReplayCache {
	if now == nil {
		now = time.Now
	}
	c := &ReplayCache{ttl: ttl, now: now, seed: maphash.MakeSeed()}
	for i := range c.shards {
		c.shards[i].seen = make(map[string]time.Time)
	}
	return c
}

// SeenBefore reports whether nonce was already presented within the TTL. A fresh
// nonce is recorded and returns false; a repeat returns true (a replay). An empty
// nonce is never treated as a replay (callers requiring a nonce check presence
// separately).
func (c *ReplayCache) SeenBefore(nonce string) bool {
	if c == nil || nonce == "" {
		return false
	}
	now := c.now()
	s := &c.shards[maphash.String(c.seed, nonce)&(numShards-1)]

	s.mu.Lock()
	defer s.mu.Unlock()

	if exp, ok := s.seen[nonce]; ok && now.Before(exp) {
		return true
	}
	if len(s.seen) >= maxKeysPerShard {
		s.seen = make(map[string]time.Time, maxKeysPerShard/2)
	}
	s.seen[nonce] = now.Add(c.ttl)
	return false
}
