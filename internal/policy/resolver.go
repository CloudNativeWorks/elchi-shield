package policy

import (
	"errors"

	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/matcher"
)

// Input is the request data used to resolve a policy. It is a value type built
// per request from the pipeline Transaction; Headers is satisfied by the
// Transaction directly so no copy is needed.
type Input struct {
	ListenerID  string
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

// compiledDomain is a precompiled domain: a host matcher, optional listener
// scope, its routes (ordered most-specific first), and a domain default policy
// used when no route matches.
type compiledDomain struct {
	host          matcher.Host
	hostExact     bool
	listenerID    string // "" = applies to any listener
	routes        []*compiledRoute
	defaultPolicy *CompiledPolicy
}

// Resolver maps a request to its most-specific CompiledPolicy. It is immutable
// after Compile and safe for concurrent, lock-free use on the hot path.
//
// Precedence (most → least specific), matching docs/ARCHITECTURE §8:
//  1. Host: exact host beats wildcard.
//  2. Listener scope: a domain bound to the request listener beats an unscoped
//     domain for the same host (tiebreaker after host).
//  3. Path within the winning domain: exact > regex > longest prefix.
//
// A domain scoped to a different listener is never a candidate. If the winning
// domain has no matching route, its domain-level default policy applies (the
// resolver does not fall back to a less-specific domain).
type Resolver struct {
	exact    map[string][]*compiledDomain // normalized exact host -> domains
	wildcard []*compiledDomain            // wildcard-host domains
}

// Resolve returns the effective CompiledPolicy for in, or nil when no domain
// matches (the caller then applies the default posture). It allocates nothing
// beyond any regex-internal cost.
func (r *Resolver) Resolve(in *Input) *CompiledPolicy {
	if r == nil {
		return nil
	}

	var best *compiledDomain
	bestScore := -1

	for _, cd := range r.exact[matcher.NormalizeHost(in.Host)] {
		if s, ok := domainScore(cd, in); ok && s > bestScore {
			best, bestScore = cd, s
		}
	}
	for _, cd := range r.wildcard {
		if !cd.host.Match(in.Host) {
			continue
		}
		if s, ok := domainScore(cd, in); ok && s > bestScore {
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

// domainScore ranks a candidate domain for a request. It returns (score, true)
// when the domain is a candidate, or (_, false) when scoped to a different
// listener. Host specificity dominates (exact > longer wildcard suffix > shorter
// wildcard); a listener-scoped match breaks ties between equally specific hosts.
//
// Host specificity is doubled so its smallest meaningful difference (1) outweighs
// the at-most-1 listener bonus, keeping host the primary key and listener a pure
// tiebreaker.
func domainScore(cd *compiledDomain, in *Input) (int, bool) {
	if cd.listenerID != "" && cd.listenerID != in.ListenerID {
		return 0, false
	}
	score := cd.host.Specificity() * 2
	if cd.listenerID != "" && cd.listenerID == in.ListenerID {
		score++
	}
	return score, true
}
