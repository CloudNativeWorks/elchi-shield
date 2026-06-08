// Package sensitive provides a built-in detector for high-confidence sensitive
// data (PII / secrets) in request and response bodies. It satisfies the body
// stage's SensitiveDataDetector hook so the `detect_sensitive_data` policy knob
// maps to a real control rather than a no-op. Patterns are deliberately
// high-precision (low false-positive) and all matching is linear-time (RE2).
package sensitive

import (
	"context"
	"regexp"
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
			{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
			{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
			{"slack_token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`)},
			{"github_token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,}\b`)},
			{"jwt", regexp.MustCompile(`\beyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\b`)},
			{"ssn", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
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

// Matches returns all sensitive-data findings with their byte offsets, sorted by
// start and de-overlapped (the first match of any overlapping pair wins), so a
// caller can rewrite the body in a single left-to-right pass.
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
	out := ms[:1]
	for _, m := range ms[1:] {
		if m.Start >= out[len(out)-1].End { // non-overlapping
			out = append(out, m)
		}
	}
	return out
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
	for _, m := range d.luhn.FindAll(body, -1) {
		if luhnValid(m) {
			return true, "credit_card"
		}
	}
	return false, ""
}

// luhnValid reports whether the digits in b satisfy the Luhn checksum, ignoring
// spaces and dashes. Non-digit, non-separator bytes make it invalid.
func luhnValid(b []byte) bool {
	sum := 0
	alt := false
	count := 0
	for i := len(b) - 1; i >= 0; i-- {
		c := b[i]
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
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
	return count >= 13 && count <= 19 && sum%10 == 0
}
