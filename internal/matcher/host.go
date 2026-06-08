package matcher

import (
	"errors"
	"fmt"
	"strings"
)

// Host matches a request authority/Host. It supports an exact host and a single
// leading-wildcard form ("*.example.com", matching one or more leading labels).
// Matching is case-insensitive. Compiled once during config load; Match is
// allocation-free.
type Host struct {
	exact  string // lowercased; set for exact matches
	suffix string // lowercased ".example.com"; set for wildcard matches
}

// CompileHost compiles a host pattern. An empty pattern is rejected (callers
// validate non-empty hosts earlier, but this keeps the matcher self-contained).
func CompileHost(pattern string) (Host, error) {
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "" {
		return Host{}, errors.New("empty host pattern")
	}
	if rest, ok := strings.CutPrefix(p, "*."); ok {
		rest = stripTrailingDot(rest)
		if rest == "" {
			return Host{}, fmt.Errorf("invalid wildcard host %q", pattern)
		}
		return Host{suffix: "." + rest}, nil
	}
	return Host{exact: stripTrailingDot(p)}, nil
}

// Match reports whether host satisfies this matcher.
func (h Host) Match(host string) bool {
	host = stripTrailingDot(trimPort(stripUserinfo(host)))
	if h.exact != "" {
		return strings.EqualFold(host, h.exact)
	}
	// Wildcard: host must end with the suffix and have at least one label before
	// it (e.g. "*.example.com" matches "api.example.com" but not "example.com").
	if len(host) <= len(h.suffix) {
		return false
	}
	return hasSuffixFold(host, h.suffix)
}

// Exact reports whether this matcher is an exact host (more specific than a
// wildcard) for precedence ranking.
func (h Host) Exact() bool { return h.exact != "" }

// hostExactScore is the specificity of an exact host. It sits far above any
// wildcard score (a wildcard's score is its suffix length, bounded by the DNS
// name limit of 253) so an exact host always outranks any wildcard.
const hostExactScore = 1 << 20

// Specificity ranks how specific this host matcher is for precedence: an exact
// host always outranks any wildcard, and among wildcards a longer suffix (e.g.
// "*.api.example.com") outranks a shorter one ("*.example.com").
func (h Host) Specificity() int {
	if h.exact != "" {
		return hostExactScore
	}
	return len(h.suffix)
}

// NormalizeHost lowercases host and strips any userinfo, trailing port, and the
// optional fully-qualified trailing dot, matching how Host.Match compares. Used
// to key exact-host lookups.
func NormalizeHost(host string) string {
	return strings.ToLower(stripTrailingDot(trimPort(stripUserinfo(host))))
}

// stripUserinfo removes a "user@" / "user:pass@" prefix from an authority so a
// host-scoped policy can't be dodged by prepending userinfo (e.g.
// "evil@api.example.com"). Defense-in-depth; Envoy normally rejects userinfo.
func stripUserinfo(host string) string {
	if i := strings.LastIndexByte(host, '@'); i >= 0 {
		return host[i+1:]
	}
	return host
}

// stripTrailingDot removes a single fully-qualified trailing dot ("example.com."
// → "example.com") so a client that sends an absolute domain still matches a
// policy written without the dot. The bare root "." is left as-is.
func stripTrailingDot(host string) string {
	if len(host) > 1 && host[len(host)-1] == '.' {
		return host[:len(host)-1]
	}
	return host
}

// trimPort removes a trailing ":port" from an authority, leaving the host.
func trimPort(host string) string {
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		// Avoid trimming inside IPv6 literals like "[::1]"; only trim when the
		// remainder after ':' is a port (no ']' present after it).
		if !strings.Contains(host[i:], "]") {
			return host[:i]
		}
	}
	return host
}

// hasSuffixFold reports whether s ends with suffix, case-insensitively, without
// allocating.
func hasSuffixFold(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return strings.EqualFold(s[len(s)-len(suffix):], suffix)
}
