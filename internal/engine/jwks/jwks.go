// Package jwks implements a header-phase JWT authentication engine whose
// verification keys come from a JWK Set (RFC 7517) — either a local file written
// by the management plane (the local-first path: no network, hot-reloaded on
// config change) or a remote OIDC JWKS URL.
//
// Critically, there is NEVER a synchronous network fetch on the request path. A
// URL key source does ONE blocking fetch at config-load (so the snapshot is hot)
// and then a background goroutine refreshes an immutable key map published via an
// atomic.Pointer; the verify path only reads that pointer. An unknown `kid` is a
// fail-posture block, never a fetch. The refresher goroutine is canceled by
// Close (called once per snapshot retirement), so it cannot leak.
package jwks

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

const engineName = "jwks"

// Config configures the JWKS engine. Exactly one of File or URL is the key
// source.
type Config struct {
	File string // path to a JWKS JSON file (local, hot-reloaded)
	URL  string // remote JWKS endpoint (fetched once at load, then refreshed)

	Issuer         string
	Audience       string
	Algorithms     []string // allowed signing algs (e.g. ["RS256","ES256"])
	RequiredClaims []string
	HeaderName     string // bearer header (default "Authorization")
	Leeway         time.Duration

	RefreshInterval time.Duration // URL refresh cadence (default 10m)
	HTTPTimeout     time.Duration // URL fetch timeout (default 10s)

	HTTPClient *http.Client // injectable for tests
}

// Engine verifies bearer JWTs against a JWK Set.
type Engine struct {
	cfg        Config
	header     string
	parserOpts []gojwt.ParserOption
	keys       atomic.Pointer[map[string]crypto.PublicKey]
	cancel     context.CancelFunc
}

// New compiles the configuration and loads the initial key set. For a URL source
// it does one blocking fetch and starts the background refresher; a fetch/parse
// failure is returned so the reload aborts and the last-good snapshot stays.
func New(cfg Config) (*Engine, error) {
	if (cfg.File == "") == (cfg.URL == "") {
		return nil, errors.New("jwks: exactly one of file or url is required")
	}
	if len(cfg.Algorithms) == 0 {
		return nil, errors.New("jwks: algorithms is required")
	}
	header := cfg.HeaderName
	if header == "" {
		header = "Authorization"
	}
	e := &Engine{cfg: cfg, header: header}
	e.parserOpts = []gojwt.ParserOption{gojwt.WithValidMethods(cfg.Algorithms), gojwt.WithExpirationRequired()}
	if cfg.Issuer != "" {
		e.parserOpts = append(e.parserOpts, gojwt.WithIssuer(cfg.Issuer))
	}
	if cfg.Audience != "" {
		e.parserOpts = append(e.parserOpts, gojwt.WithAudience(cfg.Audience))
	}
	if cfg.Leeway > 0 {
		e.parserOpts = append(e.parserOpts, gojwt.WithLeeway(cfg.Leeway))
	}

	keys, err := e.load(context.Background())
	if err != nil {
		return nil, err
	}
	e.keys.Store(&keys)

	if cfg.URL != "" {
		interval := cfg.RefreshInterval
		if interval <= 0 {
			interval = 10 * time.Minute
		}
		ctx, cancel := context.WithCancel(context.Background())
		e.cancel = cancel
		go e.refreshLoop(ctx, interval)
	}
	return e, nil
}

// Name implements engine.SecurityEngine.
func (*Engine) Name() string { return engineName }

// RequiresBody implements engine.SecurityEngine.
func (*Engine) RequiresBody() bool { return false }

// Close stops the background refresher (URL source) and releases resources.
func (e *Engine) Close() error {
	if e.cancel != nil {
		e.cancel()
	}
	return nil
}

// Inspect verifies the bearer JWT. Responses pass through.
func (e *Engine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	if req.Direction != engine.DirectionRequest {
		return decision.Verdict{}, nil
	}
	raw, ok := req.Headers.Header(e.header)
	if !ok || raw == "" {
		return block("jwks.missing", "missing JWT in "+e.header), nil
	}
	if len(raw) > 7 && (raw[:7] == "Bearer " || raw[:7] == "bearer ") {
		raw = raw[7:]
	}

	claims := gojwt.MapClaims{}
	if _, err := gojwt.ParseWithClaims(raw, claims, e.keyFunc, e.parserOpts...); err != nil {
		return block("jwks.invalid", "JWT validation failed"), nil
	}
	for _, name := range e.cfg.RequiredClaims {
		if v, ok := claims[name]; !ok || v == nil || v == "" {
			return block("jwks.missing_claim", "required claim missing: "+name), nil
		}
	}
	return decision.Verdict{}, nil
}

// keyFunc resolves the verification key for the token's kid from the current key
// set. An unknown kid is an error (block) — never a network fetch.
func (e *Engine) keyFunc(t *gojwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	keys := *e.keys.Load()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	// No kid match: if exactly one key is configured, allow it (single-key JWKS
	// commonly omits kid); otherwise reject.
	if kid == "" && len(keys) == 1 {
		for _, k := range keys {
			return k, nil
		}
	}
	return nil, fmt.Errorf("jwks: no key for kid %q", kid)
}

// load fetches/reads and parses the configured key source.
func (e *Engine) load(ctx context.Context) (map[string]crypto.PublicKey, error) {
	var data []byte
	if e.cfg.File != "" {
		b, err := os.ReadFile(e.cfg.File) //nolint:gosec // operator-controlled config path
		if err != nil {
			return nil, fmt.Errorf("jwks: read file: %w", err)
		}
		data = b
	} else {
		b, err := e.fetch(ctx)
		if err != nil {
			return nil, err
		}
		data = b
	}
	return parseJWKS(data)
}

// fetch retrieves the JWKS document over HTTP.
func (e *Engine) fetch(ctx context.Context) ([]byte, error) {
	client := e.cfg.HTTPClient
	if client == nil {
		timeout := e.cfg.HTTPTimeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, e.cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(reqHTTP)
	if err != nil {
		return nil, fmt.Errorf("jwks: fetch %s: %w", e.cfg.URL, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: fetch %s: status %d", e.cfg.URL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// refreshLoop periodically re-fetches the JWKS and swaps the key map. A failed
// refresh keeps the current (last-good) keys.
func (e *Engine) refreshLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if keys, err := e.load(ctx); err == nil && len(keys) > 0 {
				e.keys.Store(&keys)
			}
		}
	}
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

// --- JWK Set parsing (RFC 7517 / 7518) ---

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwkKey `json:"keys"`
}

// parseJWKS decodes a JWK Set into kid → crypto.PublicKey, supporting RSA and EC
// (P-256/384/521). Unknown key types are skipped.
func parseJWKS(data []byte) (map[string]crypto.PublicKey, error) {
	var set jwkSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("jwks: parse: %w", err)
	}
	out := make(map[string]crypto.PublicKey, len(set.Keys))
	for i := range set.Keys {
		k := &set.Keys[i]
		switch k.Kty {
		case "RSA":
			pub, err := rsaFromJWK(k)
			if err != nil {
				return nil, err
			}
			out[k.Kid] = pub
		case "EC":
			pub, err := ecFromJWK(k)
			if err != nil {
				return nil, err
			}
			out[k.Kid] = pub
		}
	}
	if len(out) == 0 {
		return nil, errors.New("jwks: no usable RSA/EC keys")
	}
	return out, nil
}

func rsaFromJWK(k *jwkKey) (*rsa.PublicKey, error) {
	n, err := b64uBig(k.N)
	if err != nil {
		return nil, fmt.Errorf("jwks: RSA n: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("jwks: RSA e: %w", err)
	}
	// Big-endian exponent, left-padded to 8 bytes.
	var buf [8]byte
	copy(buf[8-len(eb):], eb)
	return &rsa.PublicKey{N: n, E: int(binary.BigEndian.Uint64(buf[:]))}, nil
}

func ecFromJWK(k *jwkKey) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("jwks: unsupported EC curve %q", k.Crv)
	}
	x, err := b64uBig(k.X)
	if err != nil {
		return nil, fmt.Errorf("jwks: EC x: %w", err)
	}
	y, err := b64uBig(k.Y)
	if err != nil {
		return nil, fmt.Errorf("jwks: EC y: %w", err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func b64uBig(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
