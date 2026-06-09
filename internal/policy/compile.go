package policy

import (
	"fmt"
	"sort"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/matcher"
)

// Compile builds an immutable Resolver from a validated merged config. All
// matchers and regexes are compiled here (cold path); the resulting Resolver is
// used lock-free on the hot path. The config is assumed already validated, but
// Compile still returns errors defensively if a matcher fails to compile.
func Compile(cfg *config.MergedConfig) (*Resolver, error) {
	r := &Resolver{exact: make(map[string][]*compiledDomain)}
	base := config.DefaultPolicy()

	// engineCache deduplicates engine construction within this reload: policies
	// that inherit the same *EnginesSpec (the common case — routes inheriting a
	// domain's engines) share one engine.Set instead of recompiling identical,
	// possibly expensive (Coraza ruleset) engines per policy.
	ec := newEngineCache()

	for _, md := range cfg.Domains {
		d := md.Domain

		// A domain is selected by host and/or listener_id (validation guarantees at
		// least one). With no host, it is listener-only: it matches any host on its
		// listener, so it carries no host matcher.
		hostAny := d.Host == ""
		var host matcher.Host
		if !hostAny {
			h, err := matcher.CompileHost(d.Host)
			if err != nil {
				return nil, fmt.Errorf("%s: domain %q: %w", md.Source, d.Host, err)
			}
			host = h
		}

		domainResolved := config.Resolve(base, cfg.FileDefaults, d.Policy)
		domainPolicy, err := compilePolicy(domainID(d), domainResolved, ec)
		if err != nil {
			return nil, fmt.Errorf("%s: domain %q: %w", md.Source, d.Host, err)
		}
		cd := &compiledDomain{
			host:          host,
			hostExact:     !hostAny && host.Exact(),
			listenerID:    d.ListenerID,
			hostAny:       hostAny,
			defaultPolicy: domainPolicy,
		}

		for ri, rt := range d.Routes {
			path, err := matcher.CompilePath(rt.Match.PathExact, rt.Match.PathPrefix, rt.Match.PathRegex)
			if err != nil {
				return nil, fmt.Errorf("%s: domain %q route %d: %w", md.Source, d.Host, ri, err)
			}
			headers, err := matcher.CompileHeaders(rt.Match.Headers)
			if err != nil {
				return nil, fmt.Errorf("%s: domain %q route %d: %w", md.Source, d.Host, ri, err)
			}
			routeResolved := config.Resolve(base, cfg.FileDefaults, d.Policy, rt.Policy)
			routePolicy, err := compilePolicy(routeID(d, ri), routeResolved, ec)
			if err != nil {
				return nil, fmt.Errorf("%s: domain %q route %d: %w", md.Source, d.Host, ri, err)
			}
			cd.routes = append(cd.routes, &compiledRoute{
				path:        path,
				methods:     matcher.CompileMethods(rt.Match.Methods),
				contentType: matcher.CompileContentTypes(rt.Match.ContentType),
				headers:     headers,
				policy:      routePolicy,
			})
		}

		sortRoutes(cd.routes)

		switch {
		case hostAny:
			r.listenerOnly = append(r.listenerOnly, cd)
		case cd.hostExact:
			key := matcher.NormalizeHost(d.Host)
			r.exact[key] = append(r.exact[key], cd)
		default:
			r.wildcard = append(r.wildcard, cd)
		}
	}

	// Inspection-bypass paths, normalized the same way request paths are so an
	// exact entry matches regardless of query string / encoding.
	if len(cfg.Excludes) > 0 {
		r.excludes = make(map[string]struct{}, len(cfg.Excludes))
		for _, ex := range cfg.Excludes {
			r.excludes[matcher.NormalizePath(ex)] = struct{}{}
		}
	}

	return r, nil
}

// compilePolicy builds a CompiledPolicy from a resolved policy, including its
// engines (which may fail to construct, aborting the reload). Engines are shared
// through ec so policies inheriting the same spec reuse one engine.Set.
func compilePolicy(id string, resolved config.ResolvedPolicy, ec *engineCache) (*CompiledPolicy, error) {
	cp := FromResolved(id, resolved)
	engines, err := ec.get(resolved.Engines)
	if err != nil {
		return nil, err
	}
	cp.Engines = engines
	return cp, nil
}

// sortRoutes orders routes most-specific first: exact > regex > prefix > any;
// among prefixes, the longer prefix wins. The sort is stable so config order
// breaks remaining ties deterministically.
func sortRoutes(routes []*compiledRoute) {
	sort.SliceStable(routes, func(i, j int) bool {
		si, sj := routes[i].path.Specificity(), routes[j].path.Specificity()
		if si != sj {
			return si > sj
		}
		return routes[i].path.PrefixLen() > routes[j].path.PrefixLen()
	})
}

// domainID builds a stable identifier for a domain's default policy.
func domainID(d config.Domain) string {
	if d.ListenerID != "" {
		return d.Host + "|" + d.ListenerID + "|*"
	}
	return d.Host + "|*"
}

// routeID builds a stable identifier for a route's policy.
func routeID(d config.Domain, idx int) string {
	scope := d.Host
	if d.ListenerID != "" {
		scope += "|" + d.ListenerID
	}
	return fmt.Sprintf("%s|route[%d]", scope, idx)
}
