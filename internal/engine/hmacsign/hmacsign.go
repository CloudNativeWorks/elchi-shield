// Package hmacsign implements a header-phase HMAC request-signing engine using a
// native, explicitly-specified canonicalization. A client signs a canonical
// string and presents the MAC; the engine recomputes it with the shared secret
// and compares in constant time, with timestamp-window and nonce-replay
// protection.
//
// Canonical string (exactly, fields joined by '\n', no trailing newline):
//
//	method '\n' path '\n' timestamp '\n' nonce '\n' body-sha256
//
// where path is the request path with any query stripped, nonce is empty when
// not sent, and body-sha256 is the lowercase hex SHA-256 of the body when
// require_body_digest is set (empty otherwise). Because the body digest is part
// of the signature only when require_body_digest is on, the engine declares
// RequiresBody()==true exactly then — otherwise a swapped body would bypass the
// signature.
package hmacsign

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"strconv"
	"strings"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/engine/auth"
)

const engineName = "hmacsign"

// Config configures the HMAC-signing engine.
type Config struct {
	// Secret is the shared secret (used when Secrets is empty).
	Secret string
	// Secrets maps a key ID (sent in KeyIDHeader) to a secret, for key rotation.
	Secrets map[string]string

	SignatureHeader string // default "X-Signature"
	TimestampHeader string // default "X-Timestamp"
	NonceHeader     string // default "X-Nonce"
	KeyIDHeader     string // default "X-Key-Id"

	Algorithm string // "sha256" (default) or "sha512"
	Window    time.Duration
	NonceTTL  time.Duration

	RequireNonce      bool
	RequireBodyDigest bool

	now func() time.Time // injectable for tests
}

// Engine is the compiled, immutable HMAC verifier.
type Engine struct {
	secret    string
	secrets   map[string]string
	sigHdr    string
	tsHdr     string
	nonceHdr  string
	keyIDHdr  string
	newHash   func() hash.Hash
	window    time.Duration
	requireN  bool
	requireBD bool
	now       func() time.Time
	replay    *auth.ReplayCache
}

// New compiles the configuration into an Engine.
func New(cfg Config) (*Engine, error) {
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	window := cfg.Window
	if window <= 0 {
		window = 5 * time.Minute
	}
	nonceTTL := cfg.NonceTTL
	if nonceTTL <= 0 {
		nonceTTL = window
	}
	newHash := sha256.New
	if cfg.Algorithm == "sha512" {
		newHash = sha512.New
	}
	return &Engine{
		secret:    cfg.Secret,
		secrets:   cfg.Secrets,
		sigHdr:    orDefault(cfg.SignatureHeader, "X-Signature"),
		tsHdr:     orDefault(cfg.TimestampHeader, "X-Timestamp"),
		nonceHdr:  orDefault(cfg.NonceHeader, "X-Nonce"),
		keyIDHdr:  orDefault(cfg.KeyIDHeader, "X-Key-Id"),
		newHash:   newHash,
		window:    window,
		requireN:  cfg.RequireNonce,
		requireBD: cfg.RequireBodyDigest,
		now:       now,
		replay:    auth.NewReplayCache(nonceTTL, now),
	}, nil
}

// Name implements engine.SecurityEngine.
func (*Engine) Name() string { return engineName }

// RequiresBody reports whether the body digest is part of the signature.
func (e *Engine) RequiresBody() bool { return e.requireBD }

// Close implements engine.SecurityEngine.
func (*Engine) Close() error { return nil }

// Inspect verifies the request signature. Responses pass through.
func (e *Engine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	if req.Direction != engine.DirectionRequest {
		return decision.Verdict{}, nil
	}
	sig, _ := req.Headers.Header(e.sigHdr)
	if sig == "" {
		return block("sig.missing", "missing request signature"), nil
	}
	provided, err := hex.DecodeString(strings.TrimSpace(sig))
	if err != nil {
		return block("sig.invalid", "malformed signature encoding"), nil
	}

	tsStr, _ := req.Headers.Header(e.tsHdr)
	ts, err := strconv.ParseInt(strings.TrimSpace(tsStr), 10, 64)
	if err != nil {
		return block("sig.invalid_timestamp", "missing or malformed timestamp"), nil
	}
	now := e.now().Unix()
	if diff := now - ts; diff > int64(e.window/time.Second) || diff < -int64(e.window/time.Second) {
		return block("sig.stale", "request timestamp outside the allowed window"), nil
	}

	nonce, _ := req.Headers.Header(e.nonceHdr)
	if e.requireN && nonce == "" {
		return block("sig.nonce_missing", "missing nonce"), nil
	}
	if nonce != "" && e.replay.SeenBefore(nonce) {
		return block("sig.replayed", "nonce already used (replay)"), nil
	}

	secret, ok := e.secretFor(req)
	if !ok {
		return block("sig.unknown_key", "unknown signing key id"), nil
	}

	digest := ""
	if e.requireBD {
		sum := sha256.Sum256(req.Body)
		digest = hex.EncodeToString(sum[:])
	}
	canonical := req.Method + "\n" + pathOnly(req.Path) + "\n" + tsStr + "\n" + nonce + "\n" + digest

	mac := hmac.New(e.newHash, []byte(secret))
	mac.Write([]byte(canonical))
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, provided) {
		return block("sig.invalid", "signature verification failed"), nil
	}
	return decision.Verdict{}, nil
}

// secretFor resolves the signing secret: a per-key-id secret when Secrets is
// configured, else the single shared secret.
func (e *Engine) secretFor(req *engine.Request) (string, bool) {
	if len(e.secrets) == 0 {
		return e.secret, true
	}
	keyID, _ := req.Headers.Header(e.keyIDHdr)
	s, ok := e.secrets[keyID]
	return s, ok
}

func pathOnly(p string) string {
	before, _, _ := strings.Cut(p, "?")
	return before
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func block(ruleID, reason string) decision.Verdict {
	return decision.Verdict{
		Action:     decision.Block,
		Reason:     reason,
		RuleID:     ruleID,
		Engine:     engineName,
		Severity:   decision.SeverityHigh,
		StatusCode: decision.DefaultBlockStatus,
	}
}
