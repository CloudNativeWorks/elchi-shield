package policy

import (
	"errors"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/matcher"
)

// Input is the request data used to resolve a policy. It is a value type built
// per request from the pipeline Transaction; Headers is satisfied by the
// Transaction directly so no copy is needed.
type Input struct {
	Host        string
	Path        string
	Method      string
	ContentType string
	Headers     matcher.HeaderSource
}

// compiledRoute is a precompiled route: matchers plus the resolved policy that
// applies when the route wins.
type compiledRoute struct {
	path        matcher.Path
	methods     matcher.Methods
	contentType matcher.ContentType
	headers     []matcher.Header
	policy      *CompiledPolicy
}

func (r *compiledRoute) matches(in *Input) bool {
	return r.path.Match(in.Path) &&
		r.methods.Match(in.Method) &&
		r.contentType.Match(in.ContentType) &&
		matcher.MatchAll(r.headers, in.Headers)
}

// compiledDomain is a precompiled domain: its host matchers (the domain matches
// if any matches), its routes (ordered most-specific first), and a domain default
// policy used when no route matches.
type compiledDomain struct {
	hosts         []matcher.Host
	routes        []*compiledRoute
	defaultPolicy *CompiledPolicy
}

// hostSpecificity returns the specificity of the most-specific host matcher that
// matches host, or -1 when none match. Allocation-free.
func (cd *compiledDomain) hostSpecificity(host string) int {
	best := -1
	for i := range cd.hosts {
		if cd.hosts[i].Match(host) {
			if s := cd.hosts[i].Specificity(); s > best {
				best = s
			}
		}
	}
	return best
}

// passThroughPolicy is the shared mode-off policy assigned to an excluded path so
// the rest of the pipeline treats it as a terminal allow (no inspection, no body
// buffering, response phase skipped) regardless of the default posture.
var passThroughPolicy = &CompiledPolicy{ID: "exclude", Mode: config.ModeOff}

// Resolver maps a request to its most-specific CompiledPolicy. It is immutable
// after Compile and safe for concurrent, lock-free use on the hot path.
//
// Precedence (most → least specific):
//  1. Host: exact host beats a leading-wildcard ("*.example.com"), which beats a
//     bare "*" catch-all. A domain matching via its most-specific host wins.
//  2. Path within the winning domain: exact > regex > longest prefix.
//
// If the winning domain has no matching route, its domain-level default policy
// applies (the resolver does not fall back to a less-specific domain).
type Resolver struct {
	exact    map[string][]*compiledDomain // normalized exact host -> domains (exact-only domains)
	wildcard []*compiledDomain            // domains with a wildcard/catch-all host
	excludes map[string]struct{}          // normalized paths that bypass all inspection
}

// Excluded reports whether the (already normalized) request path is on the
// inspection-bypass list. A cheap map lookup checked before policy resolution.
func (r *Resolver) Excluded(normalizedPath string) bool {
	if r == nil || len(r.excludes) == 0 {
		return false
	}
	_, ok := r.excludes[normalizedPath]
	return ok
}

// PassThroughPolicy returns the shared mode-off policy used for an excluded path.
func PassThroughPolicy() *CompiledPolicy { return passThroughPolicy }

// Resolve returns the effective CompiledPolicy for in, or nil when no domain
// matches (the caller then applies the default posture). It allocates nothing
// beyond any regex-internal cost.
func (r *Resolver) Resolve(in *Input) *CompiledPolicy {
	if r == nil {
		return nil
	}

	var best *compiledDomain
	bestScore := -1

	// Exact-only domains via the O(1) map; wildcard/catch-all domains scanned. A
	// domain is in exactly one bucket, so it's scored at most once. The winning
	// domain is the one whose most-specific matching host beats all others
	// (exact > "*.x" > "*").
	for _, cd := range r.exact[matcher.NormalizeHost(in.Host)] {
		if s := cd.hostSpecificity(in.Host); s > bestScore {
			best, bestScore = cd, s
		}
	}
	for _, cd := range r.wildcard {
		if s := cd.hostSpecificity(in.Host); s > bestScore {
			best, bestScore = cd, s
		}
	}

	if best == nil {
		return nil
	}
	for _, rt := range best.routes {
		if rt.matches(in) {
			return rt.policy
		}
	}
	return best.defaultPolicy
}

// Close releases the engines compiled into every policy in the resolver. It is
// called on a retired snapshot after a grace period so resources (e.g. Coraza
// rulesets) are freed deterministically. Engine sets are deduplicated by pointer
// so a set shared across policies (see engineCache) is closed exactly once.
func (r *Resolver) Close() error {
	if r == nil {
		return nil
	}
	var errs []error
	seen := make(map[*engine.Set]struct{})
	closeP := func(p *CompiledPolicy) {
		if p == nil || p.Engines == nil {
			return
		}
		if _, done := seen[p.Engines]; done {
			return
		}
		seen[p.Engines] = struct{}{}
		if err := p.Engines.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	closeDomain := func(cd *compiledDomain) {
		closeP(cd.defaultPolicy)
		for _, rt := range cd.routes {
			closeP(rt.policy)
		}
	}
	for _, doms := range r.exact {
		for _, cd := range doms {
			closeDomain(cd)
		}
	}
	for _, cd := range r.wildcard {
		closeDomain(cd)
	}
	return errors.Join(errs...)
}
