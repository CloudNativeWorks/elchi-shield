package matcher

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
)

// HeaderSource provides case-insensitive header lookup. It is satisfied by the
// pipeline Transaction (and by test fakes) without the matcher package needing
// to import them.
type HeaderSource interface {
	Header(name string) (value string, ok bool)
}

type headerKind uint8

const (
	headerPresent headerKind = iota // match on presence/absence
	headerExact
	headerContains
	headerRegex
)

// Header matches a single request header by exact value, substring, regex, or
// presence/absence. The regex is compiled once at config load.
type Header struct {
	name    string
	kind    headerKind
	value   string
	re      *regexp.Regexp
	present bool // for headerPresent: required presence (true) or absence (false)
}

// CompileHeader builds a header matcher from config. Exactly one of
// exact/contains/regex/present should be set (validated upstream); when none is
// set it defaults to "must be present".
func CompileHeader(hm config.HeaderMatch) (Header, error) {
	h := Header{name: hm.Name}
	switch {
	case hm.Exact != "":
		h.kind, h.value = headerExact, hm.Exact
	case hm.Contains != "":
		h.kind, h.value = headerContains, hm.Contains
	case hm.Regex != "":
		re, err := regexp.Compile(hm.Regex)
		if err != nil {
			return Header{}, fmt.Errorf("compile header regex %q: %w", hm.Regex, err)
		}
		h.kind, h.re = headerRegex, re
	case hm.Present != nil:
		h.kind, h.present = headerPresent, *hm.Present
	default:
		h.kind, h.present = headerPresent, true
	}
	return h, nil
}

// CompileHeaders compiles a slice of header matchers.
func CompileHeaders(hms []config.HeaderMatch) ([]Header, error) {
	if len(hms) == 0 {
		return nil, nil
	}
	out := make([]Header, 0, len(hms))
	for _, hm := range hms {
		h, err := CompileHeader(hm)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// Match reports whether src satisfies this header matcher.
func (h Header) Match(src HeaderSource) bool {
	v, ok := src.Header(h.name)
	switch h.kind {
	case headerPresent:
		return ok == h.present
	case headerExact:
		return ok && v == h.value
	case headerContains:
		return ok && strings.Contains(v, h.value)
	case headerRegex:
		return ok && h.re.MatchString(v)
	default:
		return false
	}
}

// MatchAll reports whether src satisfies every matcher in hs.
func MatchAll(hs []Header, src HeaderSource) bool {
	for i := range hs {
		if !hs[i].Match(src) {
			return false
		}
	}
	return true
}
