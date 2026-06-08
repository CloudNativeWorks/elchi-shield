package netmatch

import (
	"net/netip"
	"testing"
)

func mustPfx(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix %q: %v", s, err)
	}
	return p
}

func TestLongestPrefixWins(t *testing.T) {
	s := New[string]()
	s.Insert(mustPfx(t, "10.0.0.0/8"), "eight")
	s.Insert(mustPfx(t, "10.1.0.0/16"), "sixteen")

	v, ok := s.Lookup(netip.MustParseAddr("10.1.2.3"))
	if !ok || v != "sixteen" {
		t.Fatalf("want sixteen, got %q ok=%v", v, ok)
	}
	v, ok = s.Lookup(netip.MustParseAddr("10.2.2.3"))
	if !ok || v != "eight" {
		t.Fatalf("want eight, got %q ok=%v", v, ok)
	}
	if _, ok := s.Lookup(netip.MustParseAddr("11.0.0.1")); ok {
		t.Fatal("11.0.0.1 should not match")
	}
}

func TestContainsV4AndV6(t *testing.T) {
	s := New[struct{}]()
	s.Insert(mustPfx(t, "192.0.2.0/24"), struct{}{})
	s.Insert(mustPfx(t, "2001:db8::/32"), struct{}{})

	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"192.0.2.7", true},
		{"192.0.3.7", false},
		{"2001:db8::1", true},
		{"2001:dead::1", false},
	} {
		if got := s.Contains(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("Contains(%s)=%v want %v", tc.ip, got, tc.want)
		}
	}
}

func TestInsertIgnoresInvalidAndMasks(t *testing.T) {
	s := New[struct{}]()
	s.Insert(netip.Prefix{}, struct{}{}) // invalid, ignored
	if s.Len() != 0 {
		t.Fatalf("invalid prefix should be ignored, len=%d", s.Len())
	}
	// A host inside an unmasked prefix still matches (Insert masks).
	s.Insert(netip.MustParsePrefix("10.1.2.3/24"), struct{}{})
	if !s.Contains(netip.MustParseAddr("10.1.2.99")) {
		t.Fatal("masked /24 should contain .99")
	}
}

func TestLookupInvalidAddr(t *testing.T) {
	s := New[int]()
	s.Insert(mustPfx(t, "0.0.0.0/0"), 1)
	if _, ok := s.Lookup(netip.Addr{}); ok {
		t.Fatal("invalid addr must not match")
	}
}

func BenchmarkContains(b *testing.B) {
	s := New[struct{}]()
	s.Insert(netip.MustParsePrefix("10.0.0.0/8"), struct{}{})
	s.Insert(netip.MustParsePrefix("192.0.2.0/24"), struct{}{})
	ip := netip.MustParseAddr("10.1.2.3")
	b.ReportAllocs()
	for b.Loop() {
		if !s.Contains(ip) {
			b.Fatal("miss")
		}
	}
}
