package ipreputation

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/geoip"
)

type hdrs map[string]string

func (h hdrs) Header(name string) (string, bool) {
	for k, v := range h {
		if len(k) == len(name) && equalFold(k, name) {
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

func reqFrom(ip string) *engine.Request {
	return &engine.Request{Direction: engine.DirectionRequest, SourceIP: ip, Headers: hdrs{}}
}

func mustInspect(t *testing.T, e *Engine, ip string) decision.Verdict {
	t.Helper()
	v, err := e.Inspect(context.Background(), reqFrom(ip))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return v
}

func TestDenyCIDR(t *testing.T) {
	e, err := New(Config{DenyCIDRs: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if v := mustInspect(t, e, "192.0.2.50"); v.Action != decision.Block {
		t.Fatal("expected block for denied IP")
	}
	if v := mustInspect(t, e, "203.0.113.1"); v.Action == decision.Block {
		t.Fatal("non-denied IP should pass")
	}
}

func TestAllowListDefaultDeny(t *testing.T) {
	e, err := New(Config{AllowCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	if v := mustInspect(t, e, "10.1.2.3"); v.Action == decision.Block {
		t.Fatal("allowlisted IP should pass")
	}
	if v := mustInspect(t, e, "8.8.8.8"); v.Action != decision.Block {
		t.Fatal("non-allowlisted IP should be blocked (default-deny)")
	}
	// An unidentifiable client cannot be on the allowlist → blocked.
	if v := mustInspect(t, e, ""); v.Action != decision.Block {
		t.Fatal("empty source IP must be blocked under default-deny")
	}
}

func TestNoAllowListEmptyIPPasses(t *testing.T) {
	e, err := New(Config{DenyCIDRs: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if v := mustInspect(t, e, ""); v.Action == decision.Block {
		t.Fatal("empty source IP must pass when no allowlist is configured")
	}
}

func TestFeedMatch(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "drop.txt")
	if err := os.WriteFile(fp, []byte("198.51.100.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(Config{Feeds: []FeedConfig{{
		Name: "spamhaus", File: fp, Format: "cidr_lines", Severity: decision.SeverityHigh,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	v := mustInspect(t, e, "198.51.100.42")
	if v.Action != decision.Block || v.Severity != decision.SeverityHigh {
		t.Fatalf("expected high-severity block, got %+v", v)
	}
	if v.RuleID != "ipreputation.feed:spamhaus" {
		t.Errorf("rule id = %q", v.RuleID)
	}
	if v := mustInspect(t, e, "8.8.8.8"); v.Action == decision.Block {
		t.Fatal("IP not in feed should pass")
	}
}

func TestDenyBeatsAllow(t *testing.T) {
	// An IP inside the allow range but also explicitly denied is blocked.
	e, err := New(Config{
		AllowCIDRs: []string{"10.0.0.0/8"},
		DenyCIDRs:  []string{"10.6.6.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := mustInspect(t, e, "10.6.6.6"); v.Action != decision.Block || v.RuleID != "ipreputation.deny_cidr" {
		t.Fatalf("deny must win over allow, got %+v", v)
	}
}

func TestResponseDirectionPasses(t *testing.T) {
	e, err := New(Config{DenyCIDRs: []string{"0.0.0.0/0"}})
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.Inspect(context.Background(), &engine.Request{Direction: engine.DirectionResponse, SourceIP: "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Action == decision.Block {
		t.Fatal("reputation must not run on the response direction")
	}
}

func TestInvalidConfig(t *testing.T) {
	if _, err := New(Config{DenyCIDRs: []string{"not-a-cidr"}}); err == nil {
		t.Fatal("expected error for invalid deny CIDR")
	}
	if _, err := New(Config{Feeds: []FeedConfig{{Name: "x", File: "/nonexistent", Format: "cidr_lines"}}}); err == nil {
		t.Fatal("expected error for missing feed file")
	}
}

const (
	countryDB = "../../geoip/testdata/GeoLite2-Country-Test.mmdb"
	asnDB     = "../../geoip/testdata/GeoLite2-ASN-Test.mmdb"
)

func TestGeoBlockCountry(t *testing.T) {
	e, err := New(Config{Geo: &GeoConfig{CountryDBFile: countryDB, BlockCountries: []string{"gb"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()                                                        //nolint:errcheck
	if v := mustInspect(t, e, "81.2.69.142"); v.Action != decision.Block { // GB
		t.Fatal("GB source should be blocked")
	}
	if v := mustInspect(t, e, "89.160.20.128"); v.Action == decision.Block { // SE
		t.Fatal("SE source should pass")
	}
}

func TestGeoAllowCountryDefaultDeny(t *testing.T) {
	e, err := New(Config{Geo: &GeoConfig{CountryDBFile: countryDB, AllowCountries: []string{"SE"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()                                                          //nolint:errcheck
	if v := mustInspect(t, e, "89.160.20.128"); v.Action == decision.Block { // SE allowed
		t.Fatal("SE source should pass (allowlisted)")
	}
	if v := mustInspect(t, e, "81.2.69.142"); v.Action != decision.Block { // GB not allowed
		t.Fatal("GB source should be blocked (not in allow list)")
	}
}

func TestGeoAllowCountryUnknownDenied(t *testing.T) {
	// A country allow-list is configured but only the ASN DB is present, so a
	// lookup resolves an ASN with no country. The unknown-country IP must NOT
	// bypass the allow-list (it used to fall through to allow).
	e, err := New(Config{Geo: &GeoConfig{ASNDBFile: asnDB, AllowCountries: []string{"SE"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close() //nolint:errcheck
	if v := mustInspect(t, e, "1.128.0.1"); v.RuleID != "ipreputation.geo_country:unknown" {
		t.Fatalf("unknown-country IP must be denied under a country allow-list, got %+v", v)
	}
}

func TestGeoBlockASN(t *testing.T) {
	e, err := New(Config{Geo: &GeoConfig{ASNDBFile: asnDB, BlockASNs: []uint{1221}}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()                                                      //nolint:errcheck
	if v := mustInspect(t, e, "1.128.0.1"); v.Action != decision.Block { // AS1221
		t.Fatal("AS1221 source should be blocked")
	}
	if v := mustInspect(t, e, "12.81.92.1"); v.Action == decision.Block { // AS7018
		t.Fatal("AS7018 source should pass")
	}
}

func TestGeoOnMissing(t *testing.T) {
	// Default: a source absent from the DB passes.
	e, err := New(Config{Geo: &GeoConfig{CountryDBFile: countryDB, BlockCountries: []string{"GB"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close() //nolint:errcheck
	if v := mustInspect(t, e, "8.8.8.8"); v.Action == decision.Block {
		t.Fatal("IP absent from DB should pass by default")
	}
	// on_missing=block: absent source is blocked.
	e2, err := New(Config{Geo: &GeoConfig{CountryDBFile: countryDB, BlockOnMissing: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer e2.Close() //nolint:errcheck
	if v := mustInspect(t, e2, "8.8.8.8"); v.Action != decision.Block {
		t.Fatal("IP absent from DB should be blocked when on_missing=block")
	}
}

func TestGeoBadDatabase(t *testing.T) {
	if _, err := New(Config{Geo: &GeoConfig{CountryDBFile: "/nonexistent.mmdb", BlockCountries: []string{"GB"}}}); err == nil {
		t.Fatal("expected error for missing GeoIP database")
	}
}

// errReader is a geoLookuper whose Lookup always fails, simulating a corrupt
// DB record or read error on an otherwise-open database.
type errReader struct{ err error }

func (r errReader) Lookup(netip.Addr) (geoip.Record, error) { return geoip.Record{}, r.err }
func (r errReader) Close() error                            { return nil }

// A GeoIP lookup error must PROPAGATE (so the executor applies the policy fail
// posture), not silently fail-open — especially under a country allow-list,
// which is a default-deny positive control.
func TestGeoLookupErrorPropagates(t *testing.T) {
	wantErr := errors.New("corrupt mmdb record")
	e := &Engine{geo: &geoMatch{
		reader:         errReader{err: wantErr},
		hasAllow:       true,
		allowCountries: map[string]struct{}{"GB": {}},
	}}
	_, err := e.Inspect(context.Background(), reqFrom("81.2.69.142"))
	if err == nil {
		t.Fatal("expected geo lookup error to propagate (fail-close), got nil (fail-open)")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error should wrap the lookup failure, got %v", err)
	}
}

func TestDenyBeatsGeo(t *testing.T) {
	// CIDR deny is evaluated before GeoIP.
	e, err := New(Config{
		DenyCIDRs: []string{"81.2.69.0/24"},
		Geo:       &GeoConfig{CountryDBFile: countryDB, AllowCountries: []string{"GB"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close() //nolint:errcheck
	if v := mustInspect(t, e, "81.2.69.142"); v.RuleID != "ipreputation.deny_cidr" {
		t.Fatalf("deny CIDR should win over geo-allow, got %+v", v)
	}
}

func TestMetadata(t *testing.T) {
	e, _ := New(Config{DenyCIDRs: []string{"10.0.0.0/8"}})
	if e.Name() != "ipreputation" {
		t.Errorf("name = %q", e.Name())
	}
	if e.RequiresBody() {
		t.Error("ipreputation must be header-phase (RequiresBody=false)")
	}
	if err := e.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestIPv4MappedIPv6Unmapped(t *testing.T) {
	// A 4-in-6 source must match an IPv4 deny CIDR (canonicalized via Unmap).
	e, err := New(Config{DenyCIDRs: []string{"192.0.2.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if v := mustInspect(t, e, "::ffff:192.0.2.50"); v.Action != decision.Block {
		t.Fatal("IPv4-mapped IPv6 source must match the IPv4 deny CIDR")
	}
}

func TestAllowListShortCircuitsFeeds(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(fp, []byte("10.0.0.0/8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An allow-listed IP that ALSO matches a threat feed must pass (allow is a
	// trust list that short-circuits the softer feed signal).
	e, err := New(Config{
		AllowCIDRs: []string{"10.1.0.0/16"},
		Feeds:      []FeedConfig{{Name: "f", File: fp, Format: "cidr_lines"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := mustInspect(t, e, "10.1.2.3"); v.Action == decision.Block {
		t.Fatal("an allow-listed IP must short-circuit the feed and pass")
	}
	// A non-allow-listed IP is blocked by default-deny (before the feed even).
	if v := mustInspect(t, e, "8.8.8.8"); v.Action != decision.Block {
		t.Fatal("non-allow-listed IP should be blocked under default-deny")
	}
}

func TestDenyStillBeatsAllowShortCircuit(t *testing.T) {
	e, err := New(Config{
		AllowCIDRs: []string{"10.0.0.0/8"},
		DenyCIDRs:  []string{"10.6.6.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := mustInspect(t, e, "10.6.6.6"); v.RuleID != "ipreputation.deny_cidr" {
		t.Fatalf("explicit deny must win over allow short-circuit, got %+v", v)
	}
}
