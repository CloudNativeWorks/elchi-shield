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

func in(host, path, method string) *Input {
	return &Input{Host: host, Path: path, Method: method, Headers: nilHeaders{}}
}

func TestResolveExactBeatsWildcard(t *testing.T) {
	r := mustCompile(t, merged(
		config.Domain{Hosts: []string{"*.example.com"}},
		config.Domain{Hosts: []string{"api.example.com"}},
	))
	got := r.Resolve(in("api.example.com", "/", "GET"))
	if got == nil || !strings.HasPrefix(got.ID, "api.example.com|") {
		t.Fatalf("exact host should win, got %v", got)
	}
	// A host only the wildcard covers falls to the wildcard.
	got = r.Resolve(in("foo.example.com", "/", "GET"))
	if got == nil || !strings.HasPrefix(got.ID, "*.example.com|") {
		t.Fatalf("wildcard should cover other subdomains, got %v", got)
	}
}

func TestResolveMultipleHosts(t *testing.T) {
	r := mustCompile(t, merged(
		config.Domain{Hosts: []string{"a.com", "b.com", "*.c.com"}},
	))
	for _, h := range []string{"a.com", "b.com", "x.c.com"} {
		if got := r.Resolve(in(h, "/", "GET")); got == nil {
			t.Fatalf("host %q should match the multi-host domain", h)
		}
	}
	if got := r.Resolve(in("other.com", "/", "GET")); got != nil {
		t.Fatalf("an unlisted host must not match, got %v", got)
	}
}

func TestResolveCatchAll(t *testing.T) {
	r := mustCompile(t, merged(
		config.Domain{Hosts: []string{"api.example.com"}}, // specific
		config.Domain{Hosts: []string{"*"}},               // catch-all
	))
	// The specific host beats the catch-all.
	got := r.Resolve(in("api.example.com", "/", "GET"))
	if got == nil || !strings.HasPrefix(got.ID, "api.example.com|") {
		t.Fatalf("exact host should beat catch-all, got %v", got)
	}
	// Any other host falls to the catch-all.
	got = r.Resolve(in("anything.else", "/", "GET"))
	if got == nil || !strings.HasPrefix(got.ID, "*|") {
		t.Fatalf("catch-all should match any host, got %v", got)
	}
}

func TestResolveExclude(t *testing.T) {
	cfg := merged(config.Domain{Hosts: []string{"api.example.com"}})
	cfg.Excludes = []string{"/healthz", "/metrics"}
	r := mustCompile(t, cfg)
	if !r.Excluded("/healthz") || !r.Excluded("/metrics") {
		t.Fatal("configured exclude paths should report excluded")
	}
	if r.Excluded("/api") {
		t.Fatal("a non-excluded path must not be excluded")
	}
	// PassThroughPolicy is mode-off (terminal allow, no inspection).
	if PassThroughPolicy().Enforcing() {
		t.Fatal("the exclude pass-through policy must be non-enforcing (mode off)")
	}
}

func TestResolvePathPrecedence(t *testing.T) {
	d := config.Domain{
		Hosts: []string{"api.example.com"},
		Routes: []config.Route{
			{Match: config.Match{PathPrefix: "/v1/"}},      // route[0]
			{Match: config.Match{PathExact: "/v1/health"}}, // route[1]
			{Match: config.Match{PathRegex: "^/v1/.*$"}},   // route[2]
		},
	}
	r := mustCompile(t, merged(d))

	// Exact wins over regex and prefix.
	if got := r.Resolve(in("api.example.com", "/v1/health", "GET")); !strings.HasSuffix(got.ID, "route[1]") {
		t.Fatalf("exact path should win, got %v", got.ID)
	}
	// Regex (more specific) wins over prefix.
	if got := r.Resolve(in("api.example.com", "/v1/users", "GET")); !strings.HasSuffix(got.ID, "route[2]") {
		t.Fatalf("regex should beat prefix, got %v", got.ID)
	}
}

func TestResolveLongerPrefixWins(t *testing.T) {
	d := config.Domain{
		Hosts: []string{"api.example.com"},
		Routes: []config.Route{
			{Match: config.Match{PathPrefix: "/v1/"}},       // route[0]
			{Match: config.Match{PathPrefix: "/v1/users/"}}, // route[1]
		},
	}
	r := mustCompile(t, merged(d))
	if got := r.Resolve(in("api.example.com", "/v1/users/42", "GET")); !strings.HasSuffix(got.ID, "route[1]") {
		t.Fatalf("longer prefix should win, got %v", got.ID)
	}
}

func TestResolveRoutePredicatesGateToDomainDefault(t *testing.T) {
	d := config.Domain{
		Hosts: []string{"api.example.com"},
		Routes: []config.Route{
			{Match: config.Match{PathPrefix: "/v1/", Methods: []string{"POST"}}},
		},
	}
	r := mustCompile(t, merged(d))
	// GET doesn't match the POST-only route → domain default.
	got := r.Resolve(in("api.example.com", "/v1/users", "GET"))
	if got == nil || !strings.HasSuffix(got.ID, "|*") {
		t.Fatalf("non-matching method should fall to domain default, got %v", got)
	}
	// POST matches the route.
	got = r.Resolve(in("api.example.com", "/v1/users", "POST"))
	if got == nil || !strings.HasSuffix(got.ID, "route[0]") {
		t.Fatalf("POST should match the route, got %v", got)
	}
}

func TestResolveMoreSpecificWildcardWins(t *testing.T) {
	r := mustCompile(t, merged(
		config.Domain{Hosts: []string{"*.example.com"}},
		config.Domain{Hosts: []string{"*.api.example.com"}},
	))
	// A host both wildcards cover → the longer-suffix wildcard wins.
	got := r.Resolve(in("v1.api.example.com", "/", "GET"))
	if got == nil || !strings.HasPrefix(got.ID, "*.api.example.com|") {
		t.Fatalf("more specific wildcard should win, got %v", got)
	}
	// A host only the broad wildcard covers → broad wildcard.
	got = r.Resolve(in("www.example.com", "/", "GET"))
	if got == nil || !strings.HasPrefix(got.ID, "*.example.com|") {
		t.Fatalf("broad wildcard should cover non-api subdomain, got %v", got)
	}
}

func TestResolveTrailingDotHost(t *testing.T) {
	r := mustCompile(t, merged(
		config.Domain{Hosts: []string{"api.example.com"}},
		config.Domain{Hosts: []string{"*.svc.example.com"}},
	))
	// Absolute (FQDN with trailing dot) request still matches the exact policy.
	if got := r.Resolve(in("api.example.com.", "/", "GET")); got == nil || !strings.HasPrefix(got.ID, "api.example.com|") {
		t.Fatalf("trailing-dot exact host should match, got %v", got)
	}
	// And the wildcard.
	if got := r.Resolve(in("a.svc.example.com.", "/", "GET")); got == nil || !strings.HasPrefix(got.ID, "*.svc.example.com|") {
		t.Fatalf("trailing-dot wildcard host should match, got %v", got)
	}
}

func TestResolveNoMatchReturnsNil(t *testing.T) {
	r := mustCompile(t, merged(config.Domain{Hosts: []string{"api.example.com"}}))
	if got := r.Resolve(in("other.com", "/", "GET")); got != nil {
		t.Fatalf("unconfigured host should resolve to nil, got %v", got)
	}
}

func TestNilResolverResolvesNil(t *testing.T) {
	var r *Resolver
	if r.Resolve(in("a.com", "/", "GET")) != nil {
		t.Fatal("nil resolver must resolve nil")
	}
}

// TestResolveZeroAlloc machine-checks the "lock-free, allocation-free resolve"
// hot-path invariant so a regression fails a normal test run.
func TestResolveZeroAlloc(t *testing.T) {
	r := mustCompile(t, merged(
		config.Domain{Hosts: []string{"*.example.com"}},
		config.Domain{Hosts: []string{"api.example.com"}, Routes: []config.Route{
			{Match: config.Match{PathPrefix: "/v1/"}},
			{Match: config.Match{PathExact: "/v1/health"}},
		}},
	))
	input := in("api.example.com", "/v1/users/42", "GET")
	if got := testing.AllocsPerRun(200, func() { _ = r.Resolve(input) }); got != 0 {
		t.Fatalf("Resolve must be 0 allocs/op, got %v", got)
	}
}

// BenchmarkResolve measures hot-path policy lookup against a realistic resolver
// (several domains incl. a wildcard, multiple routes). It must not allocate.
func BenchmarkResolve(b *testing.B) {
	cfg := merged(
		config.Domain{Hosts: []string{"*.example.com"}},
		config.Domain{Hosts: []string{"api.example.com"}, Routes: []config.Route{
			{Match: config.Match{PathExact: "/v1/health"}},
			{Match: config.Match{PathPrefix: "/v1/users/"}},
			{Match: config.Match{PathPrefix: "/v1/", Methods: []string{"GET", "POST"}}},
			{Match: config.Match{PathRegex: "^/admin/.*$"}},
		}},
		config.Domain{Hosts: []string{"static.example.com"}},
	)
	r, err := Compile(cfg)
	if err != nil {
		b.Fatal(err)
	}
	input := in("api.example.com", "/v1/users/42", "GET")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if r.Resolve(input) == nil {
			b.Fatal("unexpected nil")
		}
	}
}
