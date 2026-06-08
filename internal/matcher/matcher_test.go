package matcher

import (
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
)

// fakeHeaders is a case-insensitive HeaderSource for tests.
type fakeHeaders map[string]string

func (f fakeHeaders) Header(name string) (string, bool) {
	for k, v := range f {
		if equalFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
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

func TestHostMatch(t *testing.T) {
	exact, _ := CompileHost("Api.Example.com")
	if !exact.Match("api.example.com") || !exact.Match("API.EXAMPLE.COM:443") {
		t.Fatal("exact host should match case-insensitively and ignore port")
	}
	if exact.Match("x.example.com") {
		t.Fatal("exact host should not match a different host")
	}
	if !exact.Exact() {
		t.Fatal("exact matcher should report Exact")
	}

	wild, _ := CompileHost("*.example.com")
	if !wild.Match("api.example.com") || !wild.Match("a.b.example.com") {
		t.Fatal("wildcard should match sub-labels")
	}
	if wild.Match("example.com") {
		t.Fatal("wildcard must require a leading label")
	}
	if wild.Exact() {
		t.Fatal("wildcard matcher should not report Exact")
	}
}

func TestHostMatchStripsUserinfo(t *testing.T) {
	exact, _ := CompileHost("api.example.com")
	// Userinfo prefix must not let a host-scoped policy be dodged.
	if !exact.Match("evil@api.example.com") || !exact.Match("user:pass@api.example.com:443") {
		t.Fatal("host match must strip userinfo before comparing")
	}
	if NormalizeHost("evil@api.example.com.:443") != "api.example.com" {
		t.Fatalf("NormalizeHost should strip userinfo, port, and trailing dot, got %q",
			NormalizeHost("evil@api.example.com.:443"))
	}
}

func TestPathMatch(t *testing.T) {
	exact, _ := CompilePath("/x", "", "")
	if !exact.Match("/x") || exact.Match("/x/y") {
		t.Fatal("exact path")
	}
	prefix, _ := CompilePath("", "/v1/", "")
	if !prefix.Match("/v1/users") || prefix.Match("/v2/") {
		t.Fatal("prefix path")
	}
	re, _ := CompilePath("", "", "^/admin/.*$")
	if !re.Match("/admin/x") || re.Match("/user") {
		t.Fatal("regex path")
	}
	any, _ := CompilePath("", "", "")
	if !any.Match("/anything") {
		t.Fatal("any path")
	}
	if exact.Specificity() <= re.Specificity() || re.Specificity() <= prefix.Specificity() {
		t.Fatalf("specificity order exact>regex>prefix violated: %d %d %d",
			exact.Specificity(), re.Specificity(), prefix.Specificity())
	}
	if prefix.PrefixLen() != len("/v1/") {
		t.Fatalf("prefix len: %d", prefix.PrefixLen())
	}
}

func TestMethodMatch(t *testing.T) {
	any := CompileMethods(nil)
	if !any.Match("GET") || !any.Any() {
		t.Fatal("empty methods match any")
	}
	m := CompileMethods([]string{"get", "POST"})
	if !m.Match("GET") || !m.Match("get") || !m.Match("POST") {
		t.Fatal("method match case-insensitive")
	}
	if m.Match("DELETE") {
		t.Fatal("method not in set should not match")
	}
}

func TestContentTypeMatch(t *testing.T) {
	any := CompileContentTypes(nil)
	if !any.Match("application/json") || !any.Any() {
		t.Fatal("empty content types match any")
	}
	c := CompileContentTypes([]string{"application/json", "text/*"})
	if !c.Match("application/json; charset=utf-8") {
		t.Fatal("exact content type with params should match")
	}
	if !c.Match("text/html") {
		t.Fatal("subtype wildcard should match")
	}
	if c.Match("image/png") {
		t.Fatal("unlisted content type should not match")
	}
	all := CompileContentTypes([]string{"*/*"})
	if !all.Match("image/png") {
		t.Fatal("*/* should match anything")
	}
}

func TestHeaderMatch(t *testing.T) {
	src := fakeHeaders{"X-Env": "prod", "X-Trace": "abc123"}

	exact, _ := CompileHeader(config.HeaderMatch{Name: "X-Env", Exact: "prod"})
	if !exact.Match(src) {
		t.Fatal("exact header should match")
	}
	contains, _ := CompileHeader(config.HeaderMatch{Name: "X-Trace", Contains: "bc1"})
	if !contains.Match(src) {
		t.Fatal("contains header should match")
	}
	re, _ := CompileHeader(config.HeaderMatch{Name: "X-Trace", Regex: "^[a-z0-9]+$"})
	if !re.Match(src) {
		t.Fatal("regex header should match")
	}
	present := true
	pres, _ := CompileHeader(config.HeaderMatch{Name: "X-Env", Present: &present})
	if !pres.Match(src) {
		t.Fatal("present=true should match existing header")
	}
	absent := false
	abs, _ := CompileHeader(config.HeaderMatch{Name: "X-Missing", Present: &absent})
	if !abs.Match(src) {
		t.Fatal("present=false should match missing header")
	}
}

func BenchmarkHostMatchExact(b *testing.B) {
	h, _ := CompileHost("api.example.com")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = h.Match("api.example.com")
	}
}

func BenchmarkHostMatchWildcard(b *testing.B) {
	h, _ := CompileHost("*.example.com")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = h.Match("api.example.com")
	}
}

func BenchmarkPathPrefix(b *testing.B) {
	p, _ := CompilePath("", "/v1/", "")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.Match("/v1/users/42")
	}
}

// BenchmarkContentTypeMatch measures the per-request content-type check.
func BenchmarkContentTypeMatch(b *testing.B) {
	ct := CompileContentTypes([]string{"application/json", "text/*"})
	b.ReportAllocs()
	for b.Loop() {
		_ = ct.Match("application/json; charset=utf-8")
	}
}
