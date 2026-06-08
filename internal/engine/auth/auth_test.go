package auth

import (
	"testing"
	"time"
)

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("abc", "abc") {
		t.Error("equal strings should compare equal")
	}
	if ConstantTimeEqual("abc", "abd") {
		t.Error("different strings should not compare equal")
	}
	if ConstantTimeEqual("abc", "abcd") {
		t.Error("different-length strings should not compare equal")
	}
}

func TestReplayCache(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewReplayCache(time.Minute, func() time.Time { return now })

	if c.SeenBefore("nonce-1") {
		t.Fatal("first sighting must not be a replay")
	}
	if !c.SeenBefore("nonce-1") {
		t.Fatal("second sighting within TTL must be a replay")
	}
	if c.SeenBefore("nonce-2") {
		t.Fatal("a different nonce must not be a replay")
	}
	// An empty nonce is never a replay, even repeated.
	for range 2 {
		if c.SeenBefore("") {
			t.Fatal("empty nonce must never be a replay")
		}
	}
}

func TestReplayCacheExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewReplayCache(time.Minute, func() time.Time { return now })
	if c.SeenBefore("n") {
		t.Fatal("first sighting")
	}
	now = now.Add(2 * time.Minute) // past TTL
	if c.SeenBefore("n") {
		t.Fatal("an expired nonce must be accepted again")
	}
}
