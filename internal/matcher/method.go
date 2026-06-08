package matcher

import "strings"

// Methods matches an HTTP method against an allowlist. An empty Methods matches
// any method. Methods are stored uppercased; matching is case-insensitive but
// allocation-free for the common already-uppercase case.
type Methods struct {
	set map[string]struct{} // nil/empty => match any
}

// CompileMethods builds a method matcher. Duplicate and mixed-case entries are
// normalized.
func CompileMethods(methods []string) Methods {
	if len(methods) == 0 {
		return Methods{}
	}
	set := make(map[string]struct{}, len(methods))
	for _, m := range methods {
		set[strings.ToUpper(strings.TrimSpace(m))] = struct{}{}
	}
	return Methods{set: set}
}

// Match reports whether method is allowed.
func (m Methods) Match(method string) bool {
	if len(m.set) == 0 {
		return true
	}
	if _, ok := m.set[method]; ok { // fast path: already uppercase
		return true
	}
	_, ok := m.set[strings.ToUpper(method)]
	return ok
}

// Any reports whether this matcher imposes no method restriction.
func (m Methods) Any() bool { return len(m.set) == 0 }
