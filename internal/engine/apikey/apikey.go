// Package apikey implements a header-phase API-key authentication engine. Keys
// are stored hashed (SHA-256) at rest and looked up by the hash of the presented
// key, so the configuration never holds plaintext secrets and the lookup does not
// compare raw secrets byte-by-byte. Optional scope→path bindings let a key be
// restricted to certain path prefixes.
//
// The engine is stateless (no per-request mutation) and reads only request
// attributes, so it runs at the cheap header phase and never buffers the body.
package apikey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

const engineName = "apikey"

// KeyEntry is one configured credential. Exactly one of SHA256 (hex digest) or
// Key (raw, hashed at load) identifies it.
type KeyEntry struct {
	SHA256  string // hex-encoded sha256 of the key
	Key     string // raw key (hashed at New time); use SHA256 to avoid plaintext
	Subject string
	Scopes  []string
}

// ScopeBinding requires that a key carry Scope to access paths under PathPrefix.
type ScopeBinding struct {
	PathPrefix string
	Scope      string
}

// Config configures the API-key engine.
type Config struct {
	// Source is "header" (default) or "query".
	Source string
	// Name is the header or query-parameter carrying the key (default "X-Api-Key").
	Name     string
	Keys     []KeyEntry
	Bindings []ScopeBinding
}

// Engine is the compiled, immutable API-key matcher. Each known key maps to its
// granted scope set (Subject is config-level metadata, not used in matching).
type Engine struct {
	fromQuery bool
	name      string
	keys      map[[32]byte]map[string]struct{}
	bindings  []ScopeBinding
}

// New compiles the configuration into an Engine.
func New(cfg Config) (*Engine, error) {
	name := cfg.Name
	if name == "" {
		name = "X-Api-Key"
	}
	e := &Engine{
		fromQuery: cfg.Source == "query",
		name:      name,
		keys:      make(map[[32]byte]map[string]struct{}, len(cfg.Keys)),
		bindings:  cfg.Bindings,
	}
	for _, k := range cfg.Keys {
		var sum [32]byte
		if k.SHA256 != "" {
			b, err := decodeHex32(k.SHA256)
			if err != nil {
				return nil, err
			}
			sum = b
		} else {
			sum = sha256.Sum256([]byte(k.Key))
		}
		// Reject a duplicate key: a second entry would silently overwrite the
		// first's scope grant (operators expect additive config, not last-wins).
		if _, dup := e.keys[sum]; dup {
			return nil, errors.New("apikey: duplicate key configured")
		}
		scopes := make(map[string]struct{}, len(k.Scopes))
		for _, s := range k.Scopes {
			scopes[s] = struct{}{}
		}
		e.keys[sum] = scopes
	}
	return e, nil
}

// Name implements engine.SecurityEngine.
func (*Engine) Name() string { return engineName }

// RequiresBody implements engine.SecurityEngine.
func (*Engine) RequiresBody() bool { return false }

// Close implements engine.SecurityEngine.
func (*Engine) Close() error { return nil }

// Inspect authenticates the request by API key. Responses pass through.
func (e *Engine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	if req.Direction != engine.DirectionRequest {
		return decision.Verdict{}, nil
	}
	key := e.extract(req)
	if key == "" {
		return block("apikey.missing", "missing API key"), nil
	}
	sum := sha256.Sum256([]byte(key))
	scopes, ok := e.keys[sum]
	if !ok {
		return block("apikey.unknown", "unknown API key"), nil
	}
	// Scope→path bindings: a matched prefix requires the key to carry the scope.
	// Match on the NORMALIZED path (percent-decoded + dot-segment/slash collapsed),
	// the same form the router resolves on — otherwise "//v1/admin", "/v1/%61dmin",
	// or "/v1/./admin" would dodge the scope check while the backend still routes
	// to the protected resource (scope escalation).
	path := normalizePath(req.Path)
	for _, b := range e.bindings {
		if strings.HasPrefix(path, b.PathPrefix) {
			if _, has := scopes[b.Scope]; !has {
				return block("apikey.scope", "API key lacks required scope: "+b.Scope), nil
			}
		}
	}
	return decision.Verdict{}, nil
}

// extract reads the key from the configured header or query parameter, trimming
// surrounding whitespace (a proxy may pad a header value).
func (e *Engine) extract(req *engine.Request) string {
	if e.fromQuery {
		if i := strings.IndexByte(req.Path, '?'); i >= 0 {
			if vals, err := url.ParseQuery(req.Path[i+1:]); err == nil {
				return strings.TrimSpace(vals.Get(e.name))
			}
		}
		return ""
	}
	v, _ := req.Headers.Header(e.name)
	return strings.TrimSpace(v)
}

// decodeHex32 decodes a 64-char hex string into a 32-byte SHA-256 digest.
func decodeHex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("apikey: invalid sha256 hex %q: %w", s, err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("apikey: sha256 must be 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// normalizePath returns the route-matching form of a path: query/fragment
// stripped, percent-decoded once, and dot-segments / duplicate slashes collapsed
// (a trailing slash is preserved). It mirrors the router's matchPath so a scope
// binding can't be dodged by an alternate encoding of the same resource.
func normalizePath(raw string) string {
	p := raw
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	if p == "" {
		return raw
	}
	cleaned := path.Clean(p)
	if cleaned == "." {
		cleaned = "/"
	}
	if strings.HasSuffix(p, "/") && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}
	return cleaned
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
