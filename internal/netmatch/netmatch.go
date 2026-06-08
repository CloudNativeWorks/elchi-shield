// Package netmatch provides an immutable longest-prefix-match container over
// CIDR prefixes, used by the IP-reputation engine (and, later, the bot engine's
// good-bot IP verification). It wraps a BART (balanced-routing-table) trie so the
// hot path does allocation-free, lock-free O(prefix) lookups; all inserts happen
// once on the cold path (config load), after which the table is immutable and
// published via the runtime snapshot pointer.
package netmatch

import (
	"net/netip"

	"github.com/gaissmai/bart"
)

// Set is an immutable longest-prefix matcher mapping each inserted CIDR prefix to
// a value of type V. Build it on the cold path (Insert), then only Lookup on the
// hot path. Lookups are safe for concurrent use; Insert is not (single-threaded
// build only).
type Set[V any] struct {
	table *bart.Table[V]
	size  int
}

// New returns an empty Set.
func New[V any]() *Set[V] { return &Set[V]{table: &bart.Table[V]{}} }

// Insert adds a prefix→value mapping. A later insert of the same prefix overwrites
// the value. Invalid (zero) prefixes are ignored.
func (s *Set[V]) Insert(p netip.Prefix, v V) {
	if !p.IsValid() {
		return
	}
	s.table.Insert(p.Masked(), v)
	s.size++
}

// Lookup returns the value of the most specific prefix containing ip, if any.
func (s *Set[V]) Lookup(ip netip.Addr) (V, bool) {
	if !ip.IsValid() {
		var zero V
		return zero, false
	}
	return s.table.Lookup(ip)
}

// Contains reports whether any inserted prefix contains ip.
func (s *Set[V]) Contains(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	return s.table.Contains(ip)
}

// Len reports the number of prefixes inserted.
func (s *Set[V]) Len() int { return s.size }
