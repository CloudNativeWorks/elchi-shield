package jwt

import (
	"context"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

type hdr map[string]string

func (h hdr) Header(name string) (string, bool) { v, ok := h[name]; return v, ok }
func (h hdr) RangeHeaders(fn func(string, string) bool) {
	for k, v := range h {
		if !fn(k, v) {
			return
		}
	}
}

var secret = []byte("test-secret")

func token(t *testing.T, claims gojwt.MapClaims) string {
	t.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{
		Issuer:         "auth",
		Audience:       "api",
		Algorithms:     []string{"HS256"},
		HMACSecret:     secret,
		RequiredClaims: []string{"sub"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func req(h hdr) *engine.Request {
	return &engine.Request{Direction: engine.DirectionRequest, Headers: h}
}

func inspect(t *testing.T, e *Engine, r *engine.Request) decision.Verdict {
	t.Helper()
	v, err := e.Inspect(context.Background(), r)
	if err != nil {
		t.Fatalf("Inspect err: %v", err)
	}
	return v
}

func validClaims() gojwt.MapClaims {
	return gojwt.MapClaims{"iss": "auth", "aud": "api", "sub": "u1", "exp": time.Now().Add(time.Hour).Unix()}
}

func TestJWTValid(t *testing.T) {
	e := newEngine(t)
	v := inspect(t, e, req(hdr{"Authorization": "Bearer " + token(t, validClaims())}))
	if v.Action == decision.Block {
		t.Fatalf("valid token should pass: %+v", v)
	}
}

func TestJWTMissing(t *testing.T) {
	e := newEngine(t)
	if v := inspect(t, e, req(hdr{})); v.RuleID != "jwt.missing" {
		t.Fatalf("missing token should block jwt.missing: %+v", v)
	}
}

func TestJWTExpired(t *testing.T) {
	e := newEngine(t)
	claims := validClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix()
	if v := inspect(t, e, req(hdr{"Authorization": "Bearer " + token(t, claims)})); v.Action != decision.Block {
		t.Fatalf("expired token should block: %+v", v)
	}
}

func TestJWTLeewayToleratesSkew(t *testing.T) {
	// Token expired 10s ago. Strict (no leeway) blocks; 30s leeway tolerates it.
	claims := validClaims()
	claims["exp"] = time.Now().Add(-10 * time.Second).Unix()
	tok := "Bearer " + token(t, claims)

	strict := newEngine(t)
	if v := inspect(t, strict, req(hdr{"Authorization": tok})); v.Action != decision.Block {
		t.Fatalf("strict engine should block a just-expired token: %+v", v)
	}

	lenient, err := New(Config{
		Issuer: "auth", Audience: "api", Algorithms: []string{"HS256"},
		HMACSecret: secret, RequiredClaims: []string{"sub"}, Leeway: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := inspect(t, lenient, req(hdr{"Authorization": tok})); v.Action == decision.Block {
		t.Fatalf("leeway should tolerate a 10s-expired token: %+v", v)
	}
}

func TestJWTWrongIssuer(t *testing.T) {
	e := newEngine(t)
	claims := validClaims()
	claims["iss"] = "evil"
	if v := inspect(t, e, req(hdr{"Authorization": "Bearer " + token(t, claims)})); v.Action != decision.Block {
		t.Fatalf("wrong issuer should block: %+v", v)
	}
}

func TestJWTMissingRequiredClaim(t *testing.T) {
	e := newEngine(t)
	claims := validClaims()
	delete(claims, "sub")
	if v := inspect(t, e, req(hdr{"Authorization": "Bearer " + token(t, claims)})); v.RuleID != "jwt.missing_claim" {
		t.Fatalf("missing claim should block jwt.missing_claim: %+v", v)
	}
}

func TestJWTResponseDirectionPasses(t *testing.T) {
	e := newEngine(t)
	r := &engine.Request{Direction: engine.DirectionResponse, Headers: hdr{}}
	if v := inspect(t, e, r); v.Action == decision.Block {
		t.Fatal("response direction should pass through")
	}
}

func TestJWTConfigValidation(t *testing.T) {
	if _, err := New(Config{Algorithms: []string{"HS256"}}); err == nil {
		t.Error("missing key should error")
	}
	if _, err := New(Config{HMACSecret: secret}); err == nil {
		t.Error("missing algorithms should error")
	}
}

// BenchmarkJWTInspect measures the per-request JWT validation cost (the engine
// path the e2e benchmarks don't cover).
func BenchmarkJWTInspect(b *testing.B) {
	e, err := New(Config{Issuer: "auth", Audience: "api", Algorithms: []string{"HS256"}, HMACSecret: secret, RequiredClaims: []string{"sub"}})
	if err != nil {
		b.Fatal(err)
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, validClaims())
	s, _ := tok.SignedString(secret)
	r := &engine.Request{Direction: engine.DirectionRequest, Headers: hdr{"Authorization": "Bearer " + s}}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = e.Inspect(context.Background(), r)
	}
}

func TestRejectsAlgNoneToken(t *testing.T) {
	e := newEngine(t)
	// A real unsigned (alg:none) token must be rejected.
	tok := gojwt.NewWithClaims(gojwt.SigningMethodNone, validClaims())
	s, err := tok.SignedString(gojwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if v := inspect(t, e, req(hdr{"Authorization": "Bearer " + s})); v.RuleID != "jwt.invalid" {
		t.Fatalf("alg:none token must be blocked, got %+v", v)
	}
}

func TestBearerCaseInsensitive(t *testing.T) {
	e := newEngine(t)
	tok := token(t, validClaims())
	for _, prefix := range []string{"Bearer ", "bearer ", "BEARER "} {
		if v := inspect(t, e, req(hdr{"Authorization": prefix + tok})); v.Action == decision.Block {
			t.Fatalf("a valid token with %q prefix should pass", prefix)
		}
	}
}

func TestRequiredClaimEmptyCollectionRejected(t *testing.T) {
	e, err := New(Config{Algorithms: []string{"HS256"}, HMACSecret: secret, RequiredClaims: []string{"roles"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, empty := range []any{[]any{}, "", map[string]any{}, nil} {
		c := validClaims()
		c["roles"] = empty
		if v := inspect(t, e, req(hdr{"Authorization": "Bearer " + token(t, c)})); v.RuleID != "jwt.missing_claim" {
			t.Fatalf("empty required claim %#v should be rejected, got %+v", empty, v)
		}
	}
	// A meaningful value passes.
	c := validClaims()
	c["roles"] = []any{"admin"}
	if v := inspect(t, e, req(hdr{"Authorization": "Bearer " + token(t, c)})); v.Action == decision.Block {
		t.Fatal("a non-empty required claim should pass")
	}
}
