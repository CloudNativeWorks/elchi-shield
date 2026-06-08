package redaction

import "strings"

// Mask replaces any redacted value.
const Mask = "[REDACTED]"

// defaultSensitive is the always-on set of sensitive header names (lowercased).
// Their values must never appear in logs or audit output.
var defaultSensitive = []string{
	"authorization",
	"proxy-authorization",
	"cookie",
	"set-cookie",
	"x-api-key",
	"api-key",
	"x-auth-token",
	"x-amz-security-token",
	"x-csrf-token",
}

// Redactor decides what to redact. It is immutable after construction and safe
// for concurrent use. Use New to extend the default sensitive-header set with
// deployment-specific names.
type Redactor struct {
	sensitive map[string]struct{}
}

// New returns a Redactor with the default sensitive headers plus any extras
// (matched case-insensitively).
func New(extra ...string) *Redactor {
	r := &Redactor{sensitive: make(map[string]struct{}, len(defaultSensitive)+len(extra))}
	for _, h := range defaultSensitive {
		r.sensitive[h] = struct{}{}
	}
	for _, h := range extra {
		r.sensitive[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	return r
}

// Default returns a Redactor with only the built-in sensitive headers.
func Default() *Redactor { return New() }

// IsSensitiveHeader reports whether a header name is sensitive (case-insensitive).
func (r *Redactor) IsSensitiveHeader(name string) bool {
	_, ok := r.sensitive[strings.ToLower(name)]
	return ok
}

// HeaderValue returns the value to log for a header: Mask if the header is
// sensitive, otherwise the value unchanged.
func (r *Redactor) HeaderValue(name, value string) string {
	if r.IsSensitiveHeader(name) {
		return Mask
	}
	return value
}

// Value redacts a free-form string that looks like a credential (a Bearer token
// or a JWT), returning Mask; otherwise it returns the input unchanged. This is a
// best-effort guard for values that slip outside known header names.
func (r *Redactor) Value(v string) string {
	trimmed := strings.TrimSpace(v)
	if hasPrefixFold(trimmed, "bearer ") || hasPrefixFold(trimmed, "basic ") {
		return Mask
	}
	if looksLikeJWT(trimmed) {
		return Mask
	}
	return v
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// looksLikeJWT reports whether s resembles a JWT (three base64url segments
// separated by dots, each non-trivial).
func looksLikeJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) < 2 {
			return false
		}
		for i := range len(p) {
			if !isBase64URLChar(p[i]) {
				return false
			}
		}
	}
	return true
}

// isBase64URLChar reports whether c is a base64url character.
func isBase64URLChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_':
		return true
	default:
		return false
	}
}
