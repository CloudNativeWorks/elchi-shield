package hmacsign

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

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

// sign computes the native canonical signature exactly as the engine expects.
func sign(secret, method, path, ts, nonce, bodyDigest string) string {
	canonical := method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + bodyDigest
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

const fixedNow = 1_700_000_000

func newEngine(t *testing.T, cfg Config) *Engine {
	t.Helper()
	cfg.now = func() time.Time { return time.Unix(fixedNow, 0) }
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func inspect(t *testing.T, e *Engine, req *engine.Request) decision.Verdict {
	t.Helper()
	req.Direction = engine.DirectionRequest
	v, err := e.Inspect(context.Background(), req)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return v
}

func TestValidSignature(t *testing.T) {
	e := newEngine(t, Config{Secret: "s3cr3t"})
	ts := strconv.Itoa(fixedNow)
	sig := sign("s3cr3t", "GET", "/hmac", ts, "", "")
	v := inspect(t, e, &engine.Request{Method: "GET", Path: "/hmac", Headers: hdrs{
		"X-Signature": sig, "X-Timestamp": ts,
	}})
	if v.Action == decision.Block {
		t.Fatalf("valid signature should pass, got %+v", v)
	}
}

func TestTamperedSignature(t *testing.T) {
	e := newEngine(t, Config{Secret: "s3cr3t"})
	ts := strconv.Itoa(fixedNow)
	sig := sign("wrong-secret", "GET", "/hmac", ts, "", "")
	if v := inspect(t, e, &engine.Request{Method: "GET", Path: "/hmac", Headers: hdrs{"X-Signature": sig, "X-Timestamp": ts}}); v.RuleID != "sig.invalid" {
		t.Fatalf("wrong-secret signature should block, got %+v", v)
	}
}

func TestMissingSignature(t *testing.T) {
	e := newEngine(t, Config{Secret: "s"})
	if v := inspect(t, e, &engine.Request{Method: "GET", Path: "/hmac", Headers: hdrs{}}); v.RuleID != "sig.missing" {
		t.Fatalf("missing signature should block, got %+v", v)
	}
}

func TestStaleTimestamp(t *testing.T) {
	e := newEngine(t, Config{Secret: "s", Window: time.Minute})
	ts := strconv.Itoa(fixedNow - 600) // 10 min old, window 1 min
	sig := sign("s", "GET", "/hmac", ts, "", "")
	if v := inspect(t, e, &engine.Request{Method: "GET", Path: "/hmac", Headers: hdrs{"X-Signature": sig, "X-Timestamp": ts}}); v.RuleID != "sig.stale" {
		t.Fatalf("stale timestamp should block, got %+v", v)
	}
}

func TestReplayNonce(t *testing.T) {
	e := newEngine(t, Config{Secret: "s", RequireNonce: true})
	ts := strconv.Itoa(fixedNow)
	sig := sign("s", "POST", "/hmac", ts, "nonce-xyz", "")
	mk := func() *engine.Request {
		return &engine.Request{Method: "POST", Path: "/hmac", Headers: hdrs{"X-Signature": sig, "X-Timestamp": ts, "X-Nonce": "nonce-xyz"}}
	}
	if v := inspect(t, e, mk()); v.Action == decision.Block {
		t.Fatalf("first use of nonce should pass, got %+v", v)
	}
	if v := inspect(t, e, mk()); v.RuleID != "sig.replayed" {
		t.Fatalf("replayed nonce should block, got %+v", v)
	}
}

func TestRequireNonceMissing(t *testing.T) {
	e := newEngine(t, Config{Secret: "s", RequireNonce: true})
	ts := strconv.Itoa(fixedNow)
	sig := sign("s", "GET", "/hmac", ts, "", "")
	if v := inspect(t, e, &engine.Request{Method: "GET", Path: "/hmac", Headers: hdrs{"X-Signature": sig, "X-Timestamp": ts}}); v.RuleID != "sig.nonce_missing" {
		t.Fatalf("missing required nonce should block, got %+v", v)
	}
}

func TestBodyDigest(t *testing.T) {
	e := newEngine(t, Config{Secret: "s", RequireBodyDigest: true})
	if !e.RequiresBody() {
		t.Fatal("require_body_digest must set RequiresBody")
	}
	body := []byte(`{"amount":100}`)
	sum := sha256.Sum256(body)
	ts := strconv.Itoa(fixedNow)
	sig := sign("s", "POST", "/pay", ts, "", hex.EncodeToString(sum[:]))
	good := &engine.Request{Method: "POST", Path: "/pay", Body: body, Headers: hdrs{"X-Signature": sig, "X-Timestamp": ts}}
	if v := inspect(t, e, good); v.Action == decision.Block {
		t.Fatalf("valid body-digest signature should pass, got %+v", v)
	}
	// Swap the body → digest no longer matches → block (proves body is covered).
	tampered := &engine.Request{Method: "POST", Path: "/pay", Body: []byte(`{"amount":999}`), Headers: hdrs{"X-Signature": sig, "X-Timestamp": ts}}
	if v := inspect(t, e, tampered); v.RuleID != "sig.invalid" {
		t.Fatalf("swapped body should fail verification, got %+v", v)
	}
}

func TestKeyRotation(t *testing.T) {
	e := newEngine(t, Config{Secrets: map[string]string{"k1": "secret-one", "k2": "secret-two"}})
	ts := strconv.Itoa(fixedNow)
	sig := sign("secret-two", "GET", "/x", ts, "", "")
	if v := inspect(t, e, &engine.Request{Method: "GET", Path: "/x", Headers: hdrs{"X-Signature": sig, "X-Timestamp": ts, "X-Key-Id": "k2"}}); v.Action == decision.Block {
		t.Fatalf("valid rotated key should pass, got %+v", v)
	}
	if v := inspect(t, e, &engine.Request{Method: "GET", Path: "/x", Headers: hdrs{"X-Signature": sig, "X-Timestamp": ts, "X-Key-Id": "unknown"}}); v.RuleID != "sig.unknown_key" {
		t.Fatalf("unknown key id should block, got %+v", v)
	}
}

func TestQueryIsSigned(t *testing.T) {
	e := newEngine(t, Config{Secret: "shared-secret-1234"})
	ts := strconv.Itoa(fixedNow)
	// Signature is computed over the full path including the query.
	sig := sign("shared-secret-1234", "GET", "/x?a=1", ts, "", "")
	if v := inspect(t, e, &engine.Request{Method: "GET", Path: "/x?a=1", Headers: hdrs{"X-Signature": sig, "X-Timestamp": ts}}); v.Action == decision.Block {
		t.Fatalf("matching query signature should pass, got %+v", v)
	}
	// Replaying the same signature against a tampered query must fail: the query
	// is part of the canonical string.
	if v := inspect(t, e, &engine.Request{Method: "GET", Path: "/x?a=2", Headers: hdrs{"X-Signature": sig, "X-Timestamp": ts}}); v.RuleID != "sig.invalid" {
		t.Fatalf("tampered query should fail verification, got %+v", v)
	}
}

func TestNoNonceReplayBlocked(t *testing.T) {
	// With no nonce sent (and not required), an identical signed request replayed
	// within the window is still caught — the verified MAC is the replay key.
	e := newEngine(t, Config{Secret: "shared-secret-1234"})
	ts := strconv.Itoa(fixedNow)
	sig := sign("shared-secret-1234", "POST", "/pay", ts, "", "")
	mk := func() *engine.Request {
		return &engine.Request{Method: "POST", Path: "/pay", Headers: hdrs{"X-Signature": sig, "X-Timestamp": ts}}
	}
	if v := inspect(t, e, mk()); v.Action == decision.Block {
		t.Fatalf("first no-nonce request should pass, got %+v", v)
	}
	if v := inspect(t, e, mk()); v.RuleID != "sig.replayed" {
		t.Fatalf("replayed no-nonce request should block, got %+v", v)
	}
}

func TestInvalidSigDoesNotBurnNonce(t *testing.T) {
	// An attacker presenting a bogus signature with a victim's nonce must not
	// poison the replay cache: the legitimate request with that nonce still works.
	e := newEngine(t, Config{Secret: "shared-secret-1234", RequireNonce: true})
	ts := strconv.Itoa(fixedNow)
	nonce := "n-1"
	bad := &engine.Request{Method: "GET", Path: "/x", Headers: hdrs{"X-Signature": "deadbeef", "X-Timestamp": ts, "X-Nonce": nonce}}
	if v := inspect(t, e, bad); v.RuleID != "sig.invalid" {
		t.Fatalf("bogus signature should block, got %+v", v)
	}
	good := sign("shared-secret-1234", "GET", "/x", ts, nonce, "")
	if v := inspect(t, e, &engine.Request{Method: "GET", Path: "/x", Headers: hdrs{"X-Signature": good, "X-Timestamp": ts, "X-Nonce": nonce}}); v.Action == decision.Block {
		t.Fatalf("legit request must not be blocked by a pre-burned nonce, got %+v", v)
	}
}

func TestResponseDirectionPasses(t *testing.T) {
	e := newEngine(t, Config{Secret: "s"})
	v, err := e.Inspect(context.Background(), &engine.Request{Direction: engine.DirectionResponse, Headers: hdrs{}})
	if err != nil {
		t.Fatal(err)
	}
	if v.Action == decision.Block {
		t.Fatal("hmacsign must not run on the response direction")
	}
}

func TestMetadata(t *testing.T) {
	e := newEngine(t, Config{Secret: "s"})
	if e.Name() != "hmacsign" {
		t.Errorf("name = %q", e.Name())
	}
	if err := e.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}
