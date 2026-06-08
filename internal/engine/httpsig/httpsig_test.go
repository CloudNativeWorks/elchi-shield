//go:build httpsig

package httpsig

import (
	"context"
	"net/http"
	"testing"

	"github.com/yaronf/httpsign"

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

// RFC 9421 HMAC-SHA256 keys must be at least 64 bytes.
const secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// signedHeaders signs GET http://host/path and returns the two RFC 9421 headers.
func signedHeaders(t *testing.T, host, path string) (string, string) {
	t.Helper()
	signer, err := httpsign.NewHMACSHA256Signer([]byte(secret),
		httpsign.NewSignConfig(), httpsign.Headers("@method", "@authority", "@path"))
	if err != nil {
		t.Fatal(err)
	}
	hr, _ := http.NewRequest(http.MethodGet, "http://"+host+path, nil)
	hr.Host = host
	sigInput, sig, err := httpsign.SignRequest("sig1", *signer, hr)
	if err != nil {
		t.Fatal(err)
	}
	return sigInput, sig
}

func mkEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	return e.(*Engine)
}

func TestValidSignature(t *testing.T) {
	e := mkEngine(t)
	si, sig := signedHeaders(t, "api.example.com", "/sig")
	req := &engine.Request{
		Direction: engine.DirectionRequest, Method: "GET", Host: "api.example.com", Path: "/sig",
		Headers: hdrs{"Signature-Input": si, "Signature": sig},
	}
	v, err := e.Inspect(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if v.Action == decision.Block {
		t.Fatalf("valid RFC 9421 signature should pass, got %+v", v)
	}
}

func TestTamperedPath(t *testing.T) {
	e := mkEngine(t)
	si, sig := signedHeaders(t, "api.example.com", "/sig")
	// Verify against a different path than was signed → @path mismatch → block.
	req := &engine.Request{
		Direction: engine.DirectionRequest, Method: "GET", Host: "api.example.com", Path: "/admin",
		Headers: hdrs{"Signature-Input": si, "Signature": sig},
	}
	v, _ := e.Inspect(context.Background(), req)
	if v.RuleID != "httpsig.invalid" {
		t.Fatalf("tampered path should fail verification, got %+v", v)
	}
}

func TestMissingSignature(t *testing.T) {
	e := mkEngine(t)
	req := &engine.Request{Direction: engine.DirectionRequest, Method: "GET", Host: "api.example.com", Path: "/sig", Headers: hdrs{}}
	v, _ := e.Inspect(context.Background(), req)
	if v.RuleID != "httpsig.invalid" {
		t.Fatalf("missing signature should block, got %+v", v)
	}
}

func TestResponseDirectionPasses(t *testing.T) {
	e := mkEngine(t)
	v, err := e.Inspect(context.Background(), &engine.Request{Direction: engine.DirectionResponse, Headers: hdrs{}})
	if err != nil {
		t.Fatal(err)
	}
	if v.Action == decision.Block {
		t.Fatal("httpsig must not run on the response direction")
	}
}

func TestMetadata(t *testing.T) {
	e := mkEngine(t)
	if e.Name() != "httpsig" {
		t.Errorf("name = %q", e.Name())
	}
	if e.RequiresBody() {
		t.Error("default covered components do not include the body")
	}
	if err := e.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}
