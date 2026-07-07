// Package sensitive provides a built-in detector for high-confidence sensitive
// data (PII / secrets) in request and response bodies. It satisfies the body
// stage's SensitiveDataDetector hook so the `detect_sensitive_data` policy knob
// maps to a real control rather than a no-op. Patterns are deliberately
// high-precision (low false-positive) and all matching is linear-time (RE2).
package sensitive

import (
	"context"
	"regexp"
	"slices"
	"sort"
)

// pattern is one named, precompiled detector rule.
type pattern struct {
	kind string
	re   *regexp.Regexp
}

// Detector scans bodies for sensitive data. It is immutable after New and safe
// for concurrent use on the hot path (regexes are precompiled).
type Detector struct {
	patterns []pattern
	// luhn enables the structural credit-card check (digit groups validated with
	// the Luhn algorithm) to avoid matching arbitrary long digit strings.
	luhn *regexp.Regexp
}

// New builds the default detector with the built-in high-confidence patterns.
func New() *Detector {
	return &Detector{
		patterns: []pattern{
			{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
			// Generic key-type token so ENCRYPTED (PKCS#8) and PGP ... BLOCK armor are
			// also caught, not just RSA/EC/OPENSSH/DSA.
			{"private_key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)},
			{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
			{"slack_token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
			// Classic (ghp_/gho_/…) AND fine-grained (github_pat_) personal access tokens.
			{"github_token", regexp.MustCompile(`\b(?:gh[pousr]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{22,})\b`)},
			{"stripe_key", regexp.MustCompile(`\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b`)},
			{"jwt", regexp.MustCompile(`\beyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\b`)},
			{"ssn", regexp.MustCompile(`\b\d{3}[- ]\d{2}[- ]\d{4}\b`)},
			{"email", regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
		},
		// 13–19 digit runs, optionally grouped by spaces/dashes; Luhn-validated.
		luhn: regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`),
	}
}

// Match is a located sensitive-data finding: the [Start,End) byte range in the
// scanned body and its kind. Used by the DLP redaction path.
type Match struct {
	Start int
	End   int
	Kind  string
}

// Matches returns ALL sensitive-data findings with their byte offsets, sorted by
// start (and longer-first at the same start). Overlapping matches are NOT dropped
// here: a caller deciding whether to BLOCK must see every finding (otherwise an
// overlapping redact-kind match could hide a block-kind one and a hard secret
// would be forwarded). Single-pass redaction de-overlaps as it rewrites.
func (d *Detector) Matches(body []byte) []Match {
	if d == nil || len(body) == 0 {
		return nil
	}
	var ms []Match
	for _, p := range d.patterns {
		for _, loc := range p.re.FindAllIndex(body, -1) {
			ms = append(ms, Match{Start: loc[0], End: loc[1], Kind: p.kind})
		}
	}
	for _, loc := range d.luhn.FindAllIndex(body, -1) {
		if luhnValid(body[loc[0]:loc[1]]) {
			ms = append(ms, Match{Start: loc[0], End: loc[1], Kind: "credit_card"})
		}
	}
	if len(ms) < 2 {
		return ms
	}
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].Start != ms[j].Start {
			return ms[i].Start < ms[j].Start
		}
		return ms[i].End > ms[j].End // prefer the longer match at the same start
	})
	return ms
}

// Scan implements the body stage's SensitiveDataDetector. It returns whether a
// sensitive pattern was found and a short kind label for attribution. The
// content type is currently unused (patterns are content-agnostic) but kept for
// interface compatibility and future content-aware rules.
func (d *Detector) Scan(_ context.Context, _ string, body []byte) (bool, string) {
	if d == nil || len(body) == 0 {
		return false, ""
	}
	for _, p := range d.patterns {
		if p.re.Match(body) {
			return true, p.kind
		}
	}
	if slices.ContainsFunc(d.luhn.FindAll(body, -1), luhnValid) {
		return true, "credit_card"
	}
	return false, ""
}

// luhnValid reports whether the digits in b satisfy the Luhn checksum, ignoring
// spaces and dashes. Non-digit, non-separator bytes make it invalid.
func luhnValid(b []byte) bool {
	sum := 0
	alt := false
	count := 0
	var first byte // leftmost digit — backward iteration leaves it here last
	for _, c := range slices.Backward(b) {
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		first = c
		n := int(c - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
		count++
	}
	// Major card networks all start with 2–6 (Amex/Diners 3, Visa 4, MC 2/5,
	// Discover/UnionPay 6). Requiring a valid leading IIN digit drops benign
	// Luhn-passing numbers (all-zeros, sequential IDs) without missing real cards.
	return count >= 13 && count <= 19 && sum%10 == 0 && first >= '2' && first <= '6'
}
