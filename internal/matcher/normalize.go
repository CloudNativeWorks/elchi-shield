package matcher

import (
	"net/url"
	"path"
	"strings"
)

// NormalizePath returns the canonical route-matching form of a request path: the
// query/fragment is stripped, the path is percent-decoded once, and dot-segments
// and duplicate slashes are collapsed (a trailing slash is preserved). It is the
// single source of truth for path normalization, used both for route/exclude
// matching and the /policyz explainer, so an attacker can't dodge an exact/
// prefix/regex path policy via encodings or traversal (e.g. "/%61dmin",
// "/foo/../admin", "//admin") that a downstream server would normalize anyway.
func NormalizePath(raw string) string {
	p := raw
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	// Percent-decode once (best effort: keep the raw form if it is malformed).
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	if p == "" {
		return raw
	}
	// Collapse "." / ".." / "//". path.Clean drops a trailing slash, so restore it
	// to keep prefix semantics (a "/v1/" prefix should still match "/v1/").
	cleaned := path.Clean(p)
	if cleaned == "." {
		cleaned = "/"
	}
	if strings.HasSuffix(p, "/") && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}
	return cleaned
}
