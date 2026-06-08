package matcher

import (
	"fmt"
	"regexp"
	"strings"
)

// PathKind classifies how a path is matched, which also drives precedence:
// exact > regex > prefix > any.
type PathKind uint8

// Path match kinds, ordered by increasing specificity (used for precedence).
const (
	PathAny PathKind = iota
	PathPrefix
	PathRegex
	PathExact
)

// Path matches a request path. The regex is compiled once during config load;
// Match performs no compilation on the hot path.
type Path struct {
	kind  PathKind
	value string         // exact value or prefix
	re    *regexp.Regexp // set for PathRegex
}

// CompilePath builds a Path from the three mutually-exclusive forms. At most one
// of exact/prefix/regex may be non-empty (validated upstream); if all are empty
// the matcher matches any path.
func CompilePath(exact, prefix, regex string) (Path, error) {
	switch {
	case exact != "":
		return Path{kind: PathExact, value: exact}, nil
	case regex != "":
		re, err := regexp.Compile(regex)
		if err != nil {
			return Path{}, fmt.Errorf("compile path regex %q: %w", regex, err)
		}
		return Path{kind: PathRegex, re: re}, nil
	case prefix != "":
		return Path{kind: PathPrefix, value: prefix}, nil
	default:
		return Path{kind: PathAny}, nil
	}
}

// Match reports whether path satisfies this matcher.
func (p Path) Match(path string) bool {
	switch p.kind {
	case PathExact:
		return path == p.value
	case PathPrefix:
		return strings.HasPrefix(path, p.value)
	case PathRegex:
		return p.re.MatchString(path)
	default: // PathAny
		return true
	}
}

// Kind returns the path match kind.
func (p Path) Kind() PathKind { return p.kind }

// Specificity ranks how specific this path matcher is for precedence
// (exact > regex > prefix > any).
func (p Path) Specificity() int { return int(p.kind) }

// PrefixLen returns the prefix length for prefix matchers (used to break ties
// between competing prefixes — longer prefix wins). Zero for other kinds.
func (p Path) PrefixLen() int {
	if p.kind == PathPrefix {
		return len(p.value)
	}
	return 0
}
