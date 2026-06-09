package jwks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

type hdrs map[string]string

func (h hdrs) Header(name string) (string, bool) {
	for k, v := range h {
		if len(k) == len(name) && eqFold(k, name) {
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
func eqFold(a, b string) bool {
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

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// rsaJWKS builds a one-key JWKS JSON for an RSA public key with the given kid.
func rsaJWKS(t *testing.T, pub *rsa.PublicKey, kid string) []byte {
	t.Helper()
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(pub.E))
	i := 0
	for i < 7 && eb[i] == 0 {
		i++
	}
	jwk := map[string]any{"kty": "RSA", "kid": kid, "n": b64u(pub.N.Bytes()), "e": b64u(eb[i:])}
	data, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	return data
}

func ecJWKS(t *testing.T, pub *ecdsa.PublicKey, kid string) []byte {
	t.Helper()
	ek, err := pub.ECDH() // avoids the deprecated raw X/Y coordinate fields
	if err != nil {
		t.Fatal(err)
	}
	raw := ek.Bytes() // uncompressed point: 0x04 || X(32) || Y(32)
	jwk := map[string]any{"kty": "EC", "kid": kid, "crv": "P-256", "x": b64u(raw[1:33]), "y": b64u(raw[33:65])}
	data, _ := json.Marshal(map[string]any{"keys": []any{jwk}})
	return data
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid, aud string) string {
	t.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims{
		"sub": "u1", "aud": aud, "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func auth(tok string) hdrs { return hdrs{"Authorization": "Bearer " + tok} }

func inspect(t *testing.T, e *Engine, h hdrs) decision.Verdict {
	t.Helper()
	v, err := e.Inspect(context.Background(), &engine.Request{Direction: engine.DirectionRequest, Headers: h})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return v
}

func TestFileSourceRS256(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	dir := t.TempDir()
	fp := filepath.Join(dir, "jwks.json")
	if err := os.WriteFile(fp, rsaJWKS(t, &key.PublicKey, "k1"), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(Config{File: fp, Algorithms: []string{"RS256"}, Audience: "api", RequiredClaims: []string{"sub"}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close() //nolint:errcheck

	if v := inspect(t, e, auth(signRS256(t, key, "k1", "api"))); v.Action == decision.Block {
		t.Fatalf("valid RS256 token should pass, got %+v", v)
	}
	if v := inspect(t, e, hdrs{}); v.RuleID != "jwks.missing" {
		t.Fatalf("missing token should block, got %+v", v)
	}
	// Token signed by a different key → verification fails.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if v := inspect(t, e, auth(signRS256(t, other, "k1", "api"))); v.RuleID != "jwks.invalid" {
		t.Fatalf("wrong-key token should block, got %+v", v)
	}
	// Wrong audience.
	if v := inspect(t, e, auth(signRS256(t, key, "k1", "other"))); v.RuleID != "jwks.invalid" {
		t.Fatalf("wrong-audience token should block, got %+v", v)
	}
}

func TestUnknownKidBlocksWithoutFetch(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := filepath.Join(t.TempDir(), "jwks.json")
	_ = os.WriteFile(fp, rsaJWKS(t, &key.PublicKey, "k1"), 0o600)
	e, _ := New(Config{File: fp, Algorithms: []string{"RS256"}})
	defer e.Close() //nolint:errcheck
	// Token with a kid that isn't in the set.
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims{"sub": "u", "exp": time.Now().Add(time.Hour).Unix()})
	tok.Header["kid"] = "unknown-kid"
	s, _ := tok.SignedString(key)
	if v := inspect(t, e, auth(s)); v.RuleID != "jwks.invalid" {
		t.Fatalf("unknown kid should block, got %+v", v)
	}
}

func TestECSource(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fp := filepath.Join(t.TempDir(), "jwks.json")
	_ = os.WriteFile(fp, ecJWKS(t, &key.PublicKey, "ec1"), 0o600)
	e, err := New(Config{File: fp, Algorithms: []string{"ES256"}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close() //nolint:errcheck
	tok := gojwt.NewWithClaims(gojwt.SigningMethodES256, gojwt.MapClaims{"sub": "u", "exp": time.Now().Add(time.Hour).Unix()})
	tok.Header["kid"] = "ec1"
	s, _ := tok.SignedString(key)
	if v := inspect(t, e, auth(s)); v.Action == decision.Block {
		t.Fatalf("valid ES256 token should pass, got %+v", v)
	}
}

func TestURLSourceAndNoLeak(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	body := rsaJWKS(t, &key.PublicKey, "k1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	// A no-keep-alive client so HTTP machinery leaves no lingering goroutines to
	// confuse the leak check; we want to observe ONLY our refresher.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

	base := runtime.NumGoroutine()
	e, err := New(Config{URL: srv.URL, Algorithms: []string{"RS256"}, RefreshInterval: time.Hour, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if v := inspect(t, e, auth(signRS256(t, key, "k1", ""))); v.Action == decision.Block {
		t.Fatalf("valid token via URL JWKS should pass, got %+v", v)
	}
	// Close stops the refresher; the server + transport are torn down too, so the
	// goroutine count returns to baseline (no refresher leak).
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections()
	srv.Close()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > base && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base {
		t.Fatalf("refresher goroutine leaked: baseline %d, now %d", base, n)
	}
}

func TestURLFetchFailureAbortsLoad(t *testing.T) {
	if _, err := New(Config{URL: "http://127.0.0.1:0/jwks", Algorithms: []string{"RS256"}, HTTPTimeout: 200 * time.Millisecond}); err == nil {
		t.Fatal("an unreachable JWKS URL must fail New (abort the reload)")
	}
}

func TestBadConfig(t *testing.T) {
	if _, err := New(Config{Algorithms: []string{"RS256"}}); err == nil {
		t.Fatal("must require file or url")
	}
	if _, err := New(Config{File: "/x", URL: "http://x", Algorithms: []string{"RS256"}}); err == nil {
		t.Fatal("must reject both file and url")
	}
	fp := filepath.Join(t.TempDir(), "j.json")
	_ = os.WriteFile(fp, []byte("{}"), 0o600)
	if _, err := New(Config{File: fp, Algorithms: []string{"RS256"}}); err == nil {
		t.Fatal("empty JWKS should error")
	}
}

func TestMetadata(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := filepath.Join(t.TempDir(), "j.json")
	_ = os.WriteFile(fp, rsaJWKS(t, &key.PublicKey, "k1"), 0o600)
	e, _ := New(Config{File: fp, Algorithms: []string{"RS256"}})
	defer e.Close() //nolint:errcheck
	if e.Name() != "jwks" || e.RequiresBody() {
		t.Error("jwks should be a header-phase engine named jwks")
	}
}

func TestParseRejectsWeakRSA(t *testing.T) {
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := parseJWKS(rsaJWKS(t, &weak.PublicKey, "w")); err == nil {
		t.Fatal("a 1024-bit RSA key must be rejected (min 2048)")
	}
}

func TestParseRejectsMissingFields(t *testing.T) {
	if _, err := parseJWKS([]byte(`{"keys":[{"kty":"RSA","kid":"x","e":"AQAB"}]}`)); err == nil {
		t.Fatal("RSA key missing n must be rejected")
	}
	if _, err := parseJWKS([]byte(`{"keys":[{"kty":"EC","kid":"x","crv":"P-256","x":""}]}`)); err == nil {
		t.Fatal("EC key missing x/y must be rejected")
	}
}

func TestParseRejectsDuplicateKid(t *testing.T) {
	k1, _ := rsa.GenerateKey(rand.Reader, 2048)
	k2, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Two keys, same kid.
	merged := `{"keys":[` +
		string(rsaJWKS(t, &k1.PublicKey, "dup"))[len(`{"keys":[`):len(string(rsaJWKS(t, &k1.PublicKey, "dup")))-2] + `,` +
		string(rsaJWKS(t, &k2.PublicKey, "dup"))[len(`{"keys":[`):]
	if _, err := parseJWKS([]byte(merged)); err == nil {
		t.Fatal("a duplicate kid must be rejected")
	}
}

func TestParseRejectsOffCurveEC(t *testing.T) {
	// Valid-length but off-curve coordinates.
	bad := `{"keys":[{"kty":"EC","kid":"e","crv":"P-256","x":"` +
		b64u(make([]byte, 32)) + `","y":"` + b64u(make([]byte, 32)) + `"}]}`
	if _, err := parseJWKS([]byte(bad)); err == nil {
		t.Fatal("an off-curve EC point must be rejected")
	}
}

func TestKeyFuncRejectsHMACToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := filepath.Join(t.TempDir(), "jwks.json")
	_ = os.WriteFile(fp, rsaJWKS(t, &key.PublicKey, "k1"), 0o600)
	// Engine pinned to RS256; an HS256 token must never verify against the RSA key.
	e, err := New(Config{File: fp, Algorithms: []string{"RS256"}})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close() //nolint:errcheck
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{"sub": "u", "exp": time.Now().Add(time.Hour).Unix()})
	tok.Header["kid"] = "k1"
	s, _ := tok.SignedString([]byte("attacker-secret"))
	if v := inspect(t, e, auth(s)); v.Action != decision.Block {
		t.Fatal("an HS256 token must be blocked by an RS256 JWKS engine")
	}
}
