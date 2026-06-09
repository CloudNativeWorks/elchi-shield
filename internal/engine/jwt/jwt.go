// Package jwt provides a SecurityEngine that validates a JSON Web Token from a
// request header (typically Authorization: Bearer ...). It checks the signature,
// issuer, audience, expiry, and any required claims, blocking on failure. It is
// a light, always-available engine (no heavy dependencies) and is built into the
// default binary.
package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

// Config configures the JWT engine.
type Config struct {
	Issuer         string        // expected "iss" (optional)
	Audience       string        // expected "aud" (optional)
	Algorithms     []string      // allowed signing algs, e.g. ["RS256","HS256"]
	HMACSecret     []byte        // key for HS* algorithms
	PublicKeyPEM   []byte        // PEM public key for RS*/ES* algorithms
	RequiredClaims []string      // claim names that must be present and non-empty
	HeaderName     string        // header carrying the token; default "Authorization"
	Leeway         time.Duration // clock-skew tolerance for exp/nbf/iat (0 = none)
}

// Engine validates JWTs on the request. It is immutable after construction and
// safe for concurrent use.
type Engine struct {
	cfg        Config
	headerName string
	pubKey     any
	parserOpts []gojwt.ParserOption
}

// New builds a JWT engine. It requires at least one verification key (HMAC secret
// or public key) and that all configured algorithms are supported by the key.
func New(cfg Config) (*Engine, error) {
	if len(cfg.HMACSecret) == 0 && len(cfg.PublicKeyPEM) == 0 {
		return nil, errors.New("jwt: a hmac_secret or public_key is required")
	}
	if len(cfg.Algorithms) == 0 {
		return nil, errors.New("jwt: at least one algorithm must be configured")
	}

	e := &Engine{cfg: cfg, headerName: cfg.HeaderName}
	if e.headerName == "" {
		e.headerName = "Authorization"
	}

	if len(cfg.PublicKeyPEM) > 0 {
		key, err := parsePublicKey(cfg.PublicKeyPEM)
		if err != nil {
			return nil, err
		}
		// The loaded key type must match every configured algorithm family, or
		// valid tokens are silently rejected at runtime (and a confused config
		// goes unnoticed). Catch it loudly at load time.
		if err := checkKeyAlgMatch(key, cfg.Algorithms); err != nil {
			return nil, err
		}
		e.pubKey = key
	}

	e.parserOpts = []gojwt.ParserOption{gojwt.WithValidMethods(cfg.Algorithms)}
	if cfg.Issuer != "" {
		e.parserOpts = append(e.parserOpts, gojwt.WithIssuer(cfg.Issuer))
	}
	if cfg.Audience != "" {
		e.parserOpts = append(e.parserOpts, gojwt.WithAudience(cfg.Audience))
	}
	e.parserOpts = append(e.parserOpts, gojwt.WithExpirationRequired())
	if cfg.Leeway > 0 {
		// golang-jwt applies zero leeway by default, so tokens near exp/nbf get
		// rejected under normal clock skew. A small configured leeway avoids
		// spurious rejections without materially weakening expiry.
		e.parserOpts = append(e.parserOpts, gojwt.WithLeeway(cfg.Leeway))
	}
	return e, nil
}

// Name implements engine.SecurityEngine.
func (e *Engine) Name() string { return "jwt" }

// RequiresBody implements engine.SecurityEngine. JWT only reads headers.
func (e *Engine) RequiresBody() bool { return false }

// Close implements engine.SecurityEngine.
func (e *Engine) Close() error { return nil }

// Inspect validates the token. It only acts on the request direction; responses
// pass through.
func (e *Engine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	if req.Direction != engine.DirectionRequest {
		return decision.Verdict{}, nil
	}

	raw, ok := req.Headers.Header(e.headerName)
	if !ok || strings.TrimSpace(raw) == "" {
		return e.block("jwt.missing", "missing JWT in "+e.headerName), nil
	}
	// Strip a case-insensitive "Bearer " prefix (RFC 6750 schemes are
	// case-insensitive), matching the JWKS engine.
	token := raw
	if len(raw) >= 7 && strings.EqualFold(raw[:7], "Bearer ") {
		token = strings.TrimSpace(raw[7:])
	}

	claims := gojwt.MapClaims{}
	_, err := gojwt.ParseWithClaims(token, claims, e.keyFunc, e.parserOpts...)
	if err != nil {
		// Do not embed err.Error() (which could echo token/claim contents in a
		// future library version) into the auditable reason.
		return e.block("jwt.invalid", "JWT validation failed"), nil
	}

	for _, name := range e.cfg.RequiredClaims {
		v, present := claims[name]
		if !present || isEmptyClaim(v) {
			return e.block("jwt.missing_claim", "required claim missing or empty: "+name), nil
		}
	}
	return decision.Verdict{}, nil
}

// isEmptyClaim reports whether a claim value is "empty" for the required-claims
// check: nil, an empty string, or an empty array/object. Meaningful zero values
// (a numeric 0, a boolean false) are NOT treated as empty.
func isEmptyClaim(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	default:
		return false
	}
}

// keyFunc returns the verification key for the token's algorithm. It gates the
// key on the token's signing-method TYPE, which (with WithValidMethods) defeats
// the RS256→HS256 algorithm-confusion attack: an HMAC token can only ever be
// verified with the configured HMAC secret, never with an asymmetric public key.
func (e *Engine) keyFunc(t *gojwt.Token) (any, error) {
	// Defense in depth: WithValidMethods already rejects alg:none, but never hand
	// back a key for the "none" method.
	if t.Method == gojwt.SigningMethodNone {
		return nil, errors.New("alg:none is not allowed")
	}
	switch t.Method.(type) {
	case *gojwt.SigningMethodHMAC:
		if len(e.cfg.HMACSecret) == 0 {
			return nil, errors.New("HMAC token but no hmac_secret configured")
		}
		return e.cfg.HMACSecret, nil
	default:
		if e.pubKey == nil {
			return nil, errors.New("asymmetric token but no public key configured")
		}
		return e.pubKey, nil
	}
}

// checkKeyAlgMatch ensures every configured algorithm is verifiable with the
// loaded public key type (RSA→RS*/PS*, ECDSA→ES*, Ed25519→EdDSA).
func checkKeyAlgMatch(key any, algs []string) error {
	for _, alg := range algs {
		ok := false
		switch key.(type) {
		case *rsa.PublicKey:
			ok = strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
		case *ecdsa.PublicKey:
			ok = strings.HasPrefix(alg, "ES")
		case ed25519.PublicKey:
			ok = alg == "EdDSA"
		}
		if !ok {
			return fmt.Errorf("jwt: algorithm %q does not match the configured public key type %T", alg, key)
		}
	}
	return nil
}

func (e *Engine) block(ruleID, reason string) decision.Verdict {
	return decision.Verdict{
		Action:   decision.Block,
		Reason:   reason,
		RuleID:   ruleID,
		Engine:   "jwt",
		Severity: decision.SeverityHigh,
	}
}

// parsePublicKey parses a PEM-encoded public key (PKIX or certificate).
func parsePublicKey(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("jwt: invalid PEM public key")
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert.PublicKey, nil
	}
	return nil, errors.New("jwt: unsupported public key format")
}
