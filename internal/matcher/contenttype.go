package matcher

import "strings"

// ContentType matches a request/response Content-Type against a set of patterns.
// Patterns may be exact ("application/json"), subtype wildcards
// ("application/*"), or full wildcards ("*/*"). An empty set matches any content
// type. Header parameters (e.g. "; charset=utf-8") are ignored.
type ContentType struct {
	patterns []ctPattern // nil/empty => match any
}

type ctPattern struct {
	typ    string // lowercased; "*" means any type
	sub    string // lowercased; "*" means any subtype
	anyTyp bool
	anySub bool
}

// CompileContentTypes builds a content-type matcher.
func CompileContentTypes(values []string) ContentType {
	if len(values) == 0 {
		return ContentType{}
	}
	pats := make([]ctPattern, 0, len(values))
	for _, v := range values {
		typ, sub := splitMedia(v)
		pats = append(pats, ctPattern{
			typ:    typ,
			sub:    sub,
			anyTyp: typ == "*",
			anySub: sub == "*",
		})
	}
	return ContentType{patterns: pats}
}

// Match reports whether ct satisfies any configured pattern.
func (c ContentType) Match(ct string) bool {
	if len(c.patterns) == 0 {
		return true
	}
	typ, sub := splitMedia(ct)
	for i := range c.patterns {
		p := c.patterns[i]
		if (p.anyTyp || p.typ == typ) && (p.anySub || p.sub == sub) {
			return true
		}
	}
	return false
}

// Any reports whether this matcher imposes no content-type restriction.
func (c ContentType) Any() bool { return len(c.patterns) == 0 }

// splitMedia normalizes a media type into lowercased (type, subtype), dropping
// any parameters after ';'.
func splitMedia(v string) (typ, sub string) {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	v = strings.ToLower(strings.TrimSpace(v))
	if t, s, ok := strings.Cut(v, "/"); ok {
		return t, s
	}
	return v, ""
}
