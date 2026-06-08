package apikey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func inspect(t *testing.T, e *Engine, path string, h hdrs) decision.Verdict {
	t.Helper()
	v, err := e.Inspect(context.Background(), &engine.Request{Direction: engine.DirectionRequest, Method: "GET", Path: path, Headers: h})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return v
}

func TestHeaderKey(t *testing.T) {
	e, err := New(Config{Keys: []KeyEntry{{Key: "secret-key-1", Subject: "svc-a"}}})
	if err != nil {
		t.Fatal(err)
	}
	if v := inspect(t, e, "/", hdrs{"X-Api-Key": "secret-key-1"}); v.Action == decision.Block {
		t.Fatal("valid key should pass")
	}
	if v := inspect(t, e, "/", hdrs{"X-Api-Key": "wrong"}); v.RuleID != "apikey.unknown" {
		t.Fatalf("unknown key should block, got %+v", v)
	}
	if v := inspect(t, e, "/", hdrs{}); v.RuleID != "apikey.missing" {
		t.Fatalf("missing key should block, got %+v", v)
	}
}

func TestHashedKeyAtRest(t *testing.T) {
	sum := sha256.Sum256([]byte("hashed-secret"))
	e, err := New(Config{Keys: []KeyEntry{{SHA256: hex.EncodeToString(sum[:])}}})
	if err != nil {
		t.Fatal(err)
	}
	if v := inspect(t, e, "/", hdrs{"X-Api-Key": "hashed-secret"}); v.Action == decision.Block {
		t.Fatal("key matching the configured sha256 should pass")
	}
}

func TestQuerySource(t *testing.T) {
	e, err := New(Config{Source: "query", Name: "api_key", Keys: []KeyEntry{{Key: "qk"}}})
	if err != nil {
		t.Fatal(err)
	}
	if v := inspect(t, e, "/x?api_key=qk", hdrs{}); v.Action == decision.Block {
		t.Fatal("valid query key should pass")
	}
	if v := inspect(t, e, "/x?api_key=bad", hdrs{}); v.Action != decision.Block {
		t.Fatal("bad query key should block")
	}
}

func TestScopeBinding(t *testing.T) {
	e, err := New(Config{
		Keys: []KeyEntry{
			{Key: "admin-key", Scopes: []string{"admin"}},
			{Key: "read-key", Scopes: []string{"read"}},
		},
		Bindings: []ScopeBinding{{PathPrefix: "/admin", Scope: "admin"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := inspect(t, e, "/admin/x", hdrs{"X-Api-Key": "admin-key"}); v.Action == decision.Block {
		t.Fatal("admin key should access /admin")
	}
	if v := inspect(t, e, "/admin/x", hdrs{"X-Api-Key": "read-key"}); v.RuleID != "apikey.scope" {
		t.Fatalf("read key should be denied /admin, got %+v", v)
	}
	// Non-bound path: any valid key works.
	if v := inspect(t, e, "/public", hdrs{"X-Api-Key": "read-key"}); v.Action == decision.Block {
		t.Fatal("read key should access a non-bound path")
	}
}

func TestBadConfig(t *testing.T) {
	if _, err := New(Config{Keys: []KeyEntry{{SHA256: "nothex"}}}); err == nil {
		t.Fatal("expected error for invalid sha256")
	}
}

func TestResponseDirectionPasses(t *testing.T) {
	e, _ := New(Config{Keys: []KeyEntry{{Key: "k"}}})
	v, err := e.Inspect(context.Background(), &engine.Request{Direction: engine.DirectionResponse, Headers: hdrs{}})
	if err != nil {
		t.Fatal(err)
	}
	if v.Action == decision.Block {
		t.Fatal("apikey must not run on the response direction")
	}
}

func TestMetadata(t *testing.T) {
	e, _ := New(Config{Keys: []KeyEntry{{Key: "k"}}})
	if e.Name() != "apikey" || e.RequiresBody() {
		t.Error("apikey should be a header-phase engine named apikey")
	}
	if err := e.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}
