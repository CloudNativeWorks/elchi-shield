package policy

import (
	"strings"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
)

// nilHeaders is an empty HeaderSource for routes without header predicates.
type nilHeaders struct{}

func (nilHeaders) Header(string) (string, bool) { return "", false }

func merged(domains ...config.Domain) *config.MergedConfig {
	md := make([]config.MergedDomain, len(domains))
	for i, d := range domains {
		md[i] = config.MergedDomain{Domain: d, Source: "t.yaml"}
	}
	return &config.MergedConfig{Domains: md}
}

func mustCompile(t *testing.T, cfg *config.MergedConfig) *Resolver {
	t.Helper()
	r, err := Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return r
}

func in(host, path, method, listener string) *Input {
	return &Input{Host: host, Path: path, Method: method, ListenerID: listener, Headers: nilHeaders{}}
}

func TestResolveExactBeatsWildcard(t *testing.T) {
	r := mustCompile(t, merged(
		config.Domain{Host: "*.example.com"},
		config.Domain{Host: "api.example.com"},
	))
	got := r.Resolve(in("api.example.com", "/", "GET", ""))
	if got == nil || !strings.HasPrefix(got.ID, "api.example.com|") {
		t.Fatalf("exact host should win, got %v", got)
	}
	// A host only the wildcard covers falls to the wildcard.
	got = r.Resolve(in("foo.example.com", "/", "GET", ""))
	if got == nil || !strings.HasPrefix(got.ID, "*.example.com|") {
		t.Fatalf("wildcard should cover other subdomains, got %v", got)
	}
}

func TestResolveListenerScopedBeatsUnscoped(t *testing.T) {
	r := mustCompile(t, merged(
		config.Domain{Host: "api.example.com"},                   // unscoped
		config.Domain{Host: "api.example.com", ListenerID: "L1"}, // scoped
	))
	// Request on L1 → scoped domain wins.
	got := r.Resolve(in("api.example.com", "/", "GET", "L1"))
	if got == nil || !strings.Contains(got.ID, "|L1|") {
		t.Fatalf("listener-scoped should win on L1, got %v", got)
	}
	// Request on L2 → scoped(L1) excluded, unscoped wins.
	got = r.Resolve(in("api.example.com", "/", "GET", "L2"))
	if got == nil || strings.Contains(got.ID, "|L1|") {
		t.Fatalf("L1-scoped must be excluded on L2, got %v", got)
	}
}

func TestResolvePathPrecedence(t *testing.T) {
	d := config.Domain{
		Host: "api.example.com",
		Routes: []config.Route{
			{Match: config.Match{PathPrefix: "/v1/"}},      // route[0]
			{Match: config.Match{PathExact: "/v1/health"}}, // route[1]
			{Match: config.Match{PathRegex: "^/v1/.*$"}},   // route[2]
		},
	}
	r := mustCompile(t, merged(d))

	// Exact wins over regex and prefix.
	if got := r.Resolve(in("api.example.com", "/v1/health", "GET", "")); !strings.HasSuffix(got.ID, "route[1]") {
		t.Fatalf("exact path should win, got %v", got.ID)
	}
	// Regex (more specific) wins over prefix.
	if got := r.Resolve(in("api.example.com", "/v1/users", "GET", "")); !strings.HasSuffix(got.ID, "route[2]") {
		t.Fatalf("regex should beat prefix, got %v", got.ID)
	}
}

func TestResolveLongerPrefixWins(t *testing.T) {
	d := config.Domain{
		Host: "api.example.com",
		Routes: []config.Route{
			{Match: config.Match{PathPrefix: "/v1/"}},       // route[0]
			{Match: config.Match{PathPrefix: "/v1/users/"}}, // route[1]
		},
	}
	r := mustCompile(t, merged(d))
	if got := r.Resolve(in("api.example.com", "/v1/users/42", "GET", "")); !strings.HasSuffix(got.ID, "route[1]") {
		t.Fatalf("longer prefix should win, got %v", got.ID)
	}
}

func TestResolveRoutePredicatesGateToDomainDefault(t *testing.T) {
	d := config.Domain{
		Host: "api.example.com",
		Routes: []config.Route{
			{Match: config.Match{PathPrefix: "/v1/", Methods: []string{"POST"}}},
		},
	}
	r := mustCompile(t, merged(d))
	// GET doesn't match the POST-only route → domain default.
	got := r.Resolve(in("api.example.com", "/v1/users", "GET", ""))
	if got == nil || !strings.HasSuffix(got.ID, "|*") {
		t.Fatalf("non-matching method should fall to domain default, got %v", got)
	}
	// POST matches the route.
	got = r.Resolve(in("api.example.com", "/v1/users", "POST", ""))
	if got == nil || !strings.HasSuffix(got.ID, "route[0]") {
		t.Fatalf("POST should match the route, got %v", got)
	}
}

func TestResolveMoreSpecificWildcardWins(t *testing.T) {
	r := mustCompile(t, merged(
		config.Domain{Host: "*.example.com"},
		config.Domain{Host: "*.api.example.com"},
	))
	// A host both wildcards cover → the longer-suffix wildcard wins.
	got := r.Resolve(in("v1.api.example.com", "/", "GET", ""))
	if got == nil || !strings.HasPrefix(got.ID, "*.api.example.com|") {
		t.Fatalf("more specific wildcard should win, got %v", got)
	}
	// A host only the broad wildcard covers → broad wildcard.
	got = r.Resolve(in("www.example.com", "/", "GET", ""))
	if got == nil || !strings.HasPrefix(got.ID, "*.example.com|") {
		t.Fatalf("broad wildcard should cover non-api subdomain, got %v", got)
	}
}

func TestResolveTrailingDotHost(t *testing.T) {
	r := mustCompile(t, merged(
		config.Domain{Host: "api.example.com"},
		config.Domain{Host: "*.svc.example.com"},
	))
	// Absolute (FQDN with trailing dot) request still matches the exact policy.
	if got := r.Resolve(in("api.example.com.", "/", "GET", "")); got == nil || !strings.HasPrefix(got.ID, "api.example.com|") {
		t.Fatalf("trailing-dot exact host should match, got %v", got)
	}
	// And the wildcard.
	if got := r.Resolve(in("a.svc.example.com.", "/", "GET", "")); got == nil || !strings.HasPrefix(got.ID, "*.svc.example.com|") {
		t.Fatalf("trailing-dot wildcard host should match, got %v", got)
	}
}

func TestResolveNoMatchReturnsNil(t *testing.T) {
	r := mustCompile(t, merged(config.Domain{Host: "api.example.com"}))
	if got := r.Resolve(in("other.com", "/", "GET", "")); got != nil {
		t.Fatalf("unconfigured host should resolve to nil, got %v", got)
	}
}

func TestNilResolverResolvesNil(t *testing.T) {
	var r *Resolver
	if r.Resolve(in("a.com", "/", "GET", "")) != nil {
		t.Fatal("nil resolver must resolve nil")
	}
}

// TestResolveZeroAlloc machine-checks the "lock-free, allocation-free resolve"
// hot-path invariant so a regression fails a normal test run.
func TestResolveZeroAlloc(t *testing.T) {
	r := mustCompile(t, merged(
		config.Domain{Host: "*.example.com"},
		config.Domain{Host: "api.example.com", Routes: []config.Route{
			{Match: config.Match{PathPrefix: "/v1/"}},
			{Match: config.Match{PathExact: "/v1/health"}},
		}},
	))
	input := in("api.example.com", "/v1/users/42", "GET", "")
	if got := testing.AllocsPerRun(200, func() { _ = r.Resolve(input) }); got != 0 {
		t.Fatalf("Resolve must be 0 allocs/op, got %v", got)
	}
}

// BenchmarkResolve measures hot-path policy lookup against a realistic resolver
// (several domains incl. a wildcard, multiple routes). It must not allocate.
func BenchmarkResolve(b *testing.B) {
	cfg := merged(
		config.Domain{Host: "*.example.com"},
		config.Domain{Host: "api.example.com", ListenerID: "L1", Routes: []config.Route{
			{Match: config.Match{PathExact: "/v1/health"}},
			{Match: config.Match{PathPrefix: "/v1/users/"}},
			{Match: config.Match{PathPrefix: "/v1/", Methods: []string{"GET", "POST"}}},
			{Match: config.Match{PathRegex: "^/admin/.*$"}},
		}},
		config.Domain{Host: "static.example.com"},
	)
	r, err := Compile(cfg)
	if err != nil {
		b.Fatal(err)
	}
	input := in("api.example.com", "/v1/users/42", "GET", "L1")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if r.Resolve(input) == nil {
			b.Fatal("unexpected nil")
		}
	}
}
