package xfcc

import (
	"context"
	"testing"

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

func inspect(t *testing.T, e *Engine, xfcc string) decision.Verdict {
	t.Helper()
	h := hdrs{}
	if xfcc != "" {
		h["x-forwarded-client-cert"] = xfcc
	}
	v, err := e.Inspect(context.Background(), &engine.Request{Direction: engine.DirectionRequest, Headers: h})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return v
}

func TestParseQuoteAware(t *testing.T) {
	// Subject is a quoted DN containing commas; URI and DNS repeat.
	hdr := `Hash=abc123;Subject="CN=client,O=Acme,C=US";URI=spiffe://cluster/ns/team/sa/web;DNS=web.example.com`
	els := parse(hdr)
	if len(els) != 1 {
		t.Fatalf("want 1 element, got %d", len(els))
	}
	e := els[0]
	if e.Hash != "abc123" {
		t.Errorf("hash = %q", e.Hash)
	}
	if e.Subject != "CN=client,O=Acme,C=US" {
		t.Errorf("subject = %q (comma inside quotes must not split)", e.Subject)
	}
	if len(e.URIs) != 1 || e.URIs[0] != "spiffe://cluster/ns/team/sa/web" {
		t.Errorf("uris = %v", e.URIs)
	}
	if len(e.DNSs) != 1 || e.DNSs[0] != "web.example.com" {
		t.Errorf("dns = %v", e.DNSs)
	}
}

func TestParseMultipleCerts(t *testing.T) {
	els := parse(`URI=spiffe://a,URI=spiffe://b`)
	if len(els) != 2 {
		t.Fatalf("want 2 elements, got %d: %+v", len(els), els)
	}
}

func TestMatchURI(t *testing.T) {
	e, _ := New(Config{URIs: []string{"spiffe://cluster/ns/team/sa/web"}})
	if v := inspect(t, e, `URI=spiffe://cluster/ns/team/sa/web`); v.Action == decision.Block {
		t.Fatal("matching SPIFFE URI should pass")
	}
	if v := inspect(t, e, `URI=spiffe://cluster/ns/other/sa/x`); v.RuleID != "xfcc.no_match" {
		t.Fatalf("non-matching URI should block, got %+v", v)
	}
}

func TestMatchHashCaseInsensitive(t *testing.T) {
	e, _ := New(Config{Hashes: []string{"ABCDEF123456"}})
	if v := inspect(t, e, `Hash=abcdef123456;URI=spiffe://x`); v.Action == decision.Block {
		t.Fatal("fingerprint should match case-insensitively")
	}
}

func TestMatchSubjectAndDNS(t *testing.T) {
	e, _ := New(Config{Subjects: []string{"CN=client,O=Acme"}, DNSNames: []string{"web.example.com"}})
	if v := inspect(t, e, `Subject="CN=client,O=Acme"`); v.Action == decision.Block {
		t.Fatal("matching subject should pass")
	}
	if v := inspect(t, e, `DNS=web.example.com`); v.Action == decision.Block {
		t.Fatal("matching DNS should pass")
	}
}

func TestRequirePresent(t *testing.T) {
	e, _ := New(Config{RequirePresent: true, URIs: []string{"spiffe://x"}})
	if v := inspect(t, e, ""); v.RuleID != "xfcc.missing" {
		t.Fatalf("missing XFCC should block when required, got %+v", v)
	}
	// Not required + no allow-list → presence-only, missing passes.
	e2, _ := New(Config{})
	if v := inspect(t, e2, ""); v.Action == decision.Block {
		t.Fatal("missing XFCC should pass when not required")
	}
}

func TestPresenceOnly(t *testing.T) {
	// No allow-list, require present: any cert passes; none blocks.
	e, _ := New(Config{RequirePresent: true})
	if v := inspect(t, e, `URI=spiffe://anything`); v.Action == decision.Block {
		t.Fatal("presence-only should pass any present cert")
	}
}

func TestOnlyLastElementTrusted(t *testing.T) {
	e, _ := New(Config{URIs: []string{"spiffe://cluster/ns/team/sa/web"}})
	// A client prepends a forged allow-listed identity; Envoy appends the real
	// (non-allow-listed) cert as the LAST element. Only the last is trusted, so
	// the forged prefix must NOT authenticate.
	spoof := `URI=spiffe://cluster/ns/team/sa/web,Hash=abc;URI=spiffe://cluster/ns/evil/sa/x`
	if v := inspect(t, e, spoof); v.RuleID != "xfcc.no_match" {
		t.Fatalf("a prepended spoofed identity must not authenticate (only the last/Envoy element is trusted), got %+v", v)
	}
	// Legitimate: Envoy's appended (last) element matches the allow-list.
	legit := `URI=spiffe://cluster/ns/evil/sa/x,Hash=abc;URI=spiffe://cluster/ns/team/sa/web`
	if v := inspect(t, e, legit); v.Action == decision.Block {
		t.Fatalf("the last (Envoy) element matching the allow-list should pass, got %+v", v)
	}
}

func TestParseEscapedQuoteNoDesync(t *testing.T) {
	// A Subject DN with an escaped quote and an embedded comma must stay a SINGLE
	// element: the escaped `\"` must not close the quote (which would let the
	// comma split off a forged second cert element).
	els := parse(`Subject="CN=a\",O=b";Hash=h`)
	if len(els) != 1 {
		t.Fatalf("escaped quote/comma must not split the element, got %d: %+v", len(els), els)
	}
	if els[0].Subject != `CN=a",O=b` {
		t.Errorf("subject = %q, want %q (backslash escapes undone)", els[0].Subject, `CN=a",O=b`)
	}
	if els[0].Hash != "h" {
		t.Errorf("hash = %q, want %q", els[0].Hash, "h")
	}
}

func TestParseEscapedBackslash(t *testing.T) {
	els := parse(`Subject="CN=path\\to\\x"`)
	if len(els) != 1 || els[0].Subject != `CN=path\to\x` {
		t.Fatalf("escaped backslashes must be unescaped, got %+v", els)
	}
}

func TestMatchDNSCaseInsensitive(t *testing.T) {
	e, _ := New(Config{DNSNames: []string{"api.example.com"}})
	if v := inspect(t, e, `DNS=API.Example.COM`); v.Action == decision.Block {
		t.Fatal("DNS names must match case-insensitively (RFC 1035)")
	}
}

func TestResponseDirectionPasses(t *testing.T) {
	e, _ := New(Config{RequirePresent: true, URIs: []string{"spiffe://x"}})
	v, err := e.Inspect(context.Background(), &engine.Request{Direction: engine.DirectionResponse, Headers: hdrs{}})
	if err != nil {
		t.Fatal(err)
	}
	if v.Action == decision.Block {
		t.Fatal("xfcc must not run on the response direction")
	}
}

func TestMetadata(t *testing.T) {
	e, _ := New(Config{URIs: []string{"spiffe://x"}})
	if e.Name() != "xfcc" || e.RequiresBody() {
		t.Error("xfcc should be a header-phase engine named xfcc")
	}
	if err := e.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}
