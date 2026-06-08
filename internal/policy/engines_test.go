package policy

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

type emptyHeaders struct{}

func (emptyHeaders) Header(string) (string, bool)           { return "", false }
func (emptyHeaders) RangeHeaders(func(string, string) bool) {}

func TestCompileBuildsJWTEngine(t *testing.T) {
	cfg := merged(config.Domain{
		Host: "a.com",
		Policy: config.PolicySpec{
			Engines: &config.EnginesSpec{JWT: &config.JWTSpec{
				Algorithms: []string{"HS256"},
				HMACSecret: "secret",
				Audience:   "api",
			}},
		},
	})
	r := mustCompile(t, cfg)
	p := r.Resolve(in("a.com", "/", "GET", ""))
	if p == nil || p.Engines == nil || p.Engines.Len() != 1 {
		t.Fatalf("jwt engine should be compiled into the policy: %+v", p)
	}
	// A request with no token must be blocked by the engine.
	v, err := p.Engines.Inspect(context.Background(), &engine.Request{
		Direction: engine.DirectionRequest,
		Headers:   emptyHeaders{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != decision.Block {
		t.Fatalf("missing JWT should block: %+v", v)
	}
}

func TestCompileSharesEnginesAcrossInheritingPolicies(t *testing.T) {
	// A domain-level engine spec inherited by a route must compile to ONE shared
	// engine.Set (deduplicated by spec pointer), not two identical sets.
	cfg := merged(config.Domain{
		Host: "a.com",
		Policy: config.PolicySpec{
			Engines: &config.EnginesSpec{JWT: &config.JWTSpec{
				Algorithms: []string{"HS256"}, HMACSecret: "secret", Audience: "api",
			}},
		},
		Routes: []config.Route{
			{Match: config.Match{PathPrefix: "/v1/"}}, // inherits domain engines
		},
	})
	r := mustCompile(t, cfg)
	domainPol := r.Resolve(in("a.com", "/", "GET", ""))    // domain default
	routePol := r.Resolve(in("a.com", "/v1/x", "GET", "")) // route
	if domainPol == nil || routePol == nil {
		t.Fatal("both policies should resolve")
	}
	if domainPol.ID == routePol.ID {
		t.Fatalf("expected distinct policies, both %q", domainPol.ID)
	}
	if domainPol.Engines != routePol.Engines {
		t.Fatalf("inheriting policies must share one engine.Set: %p vs %p", domainPol.Engines, routePol.Engines)
	}
	// A route that OVERRIDES engines must get its own set.
	cfg2 := merged(config.Domain{
		Host: "b.com",
		Policy: config.PolicySpec{
			Engines: &config.EnginesSpec{JWT: &config.JWTSpec{Algorithms: []string{"HS256"}, HMACSecret: "s1"}},
		},
		Routes: []config.Route{
			{Match: config.Match{PathPrefix: "/v1/"}, Policy: config.PolicySpec{
				Engines: &config.EnginesSpec{JWT: &config.JWTSpec{Algorithms: []string{"HS256"}, HMACSecret: "s2"}},
			}},
		},
	})
	r2 := mustCompile(t, cfg2)
	dp := r2.Resolve(in("b.com", "/", "GET", ""))
	rp := r2.Resolve(in("b.com", "/v1/x", "GET", ""))
	if dp.Engines == rp.Engines {
		t.Fatal("overriding route must not share the domain engine set")
	}
}

func TestResolverCloseClosesSharedSetOnce(t *testing.T) {
	// Build a resolver whose policies share one engine set, then Close it. Close
	// must succeed (no double-close error) and dedup by pointer.
	cfg := merged(config.Domain{
		Host: "a.com",
		Policy: config.PolicySpec{
			Engines: &config.EnginesSpec{JWT: &config.JWTSpec{Algorithms: []string{"HS256"}, HMACSecret: "secret"}},
		},
		Routes: []config.Route{{Match: config.Match{PathPrefix: "/v1/"}}},
	})
	r := mustCompile(t, cfg)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestCompileCorazaNotBuiltErrors(t *testing.T) {
	if corazaBuilt() {
		t.Skip("coraza adapter is built in")
	}
	cfg := merged(config.Domain{
		Host: "a.com",
		Policy: config.PolicySpec{
			Engines: &config.EnginesSpec{Coraza: &config.CorazaSpec{IncludeOWASP: true}},
		},
	})
	_, err := Compile(cfg)
	if err == nil || !strings.Contains(err.Error(), "coraza") {
		t.Fatalf("coraza without build tag should fail compile: %v", err)
	}
}

func corazaBuilt() bool {
	_, err := engine.NewCoraza(engine.CorazaConfig{IncludeOWASP: true})
	return err == nil
}

// TestRateLimitSharingFollowsInheritance pins the documented state-sharing model:
// a domain-level rate_limit inherited by two routes is ONE combined limiter
// (shared buckets), while a route that defines its OWN rate_limit is independent.
func TestRateLimitSharingFollowsInheritance(t *testing.T) {
	burst := 2
	cfg := merged(config.Domain{
		Host: "a.com",
		// Domain-level rate_limit: inherited by routes that don't override engines.
		Policy: config.PolicySpec{
			Engines: &config.EnginesSpec{RateLimit: &config.RateLimitSpec{
				RequestsPerSecond: 1, Burst: burst, Key: "host",
			}},
		},
		Routes: []config.Route{
			{Match: config.Match{PathPrefix: "/v1/"}}, // inherits domain rate_limit
			{Match: config.Match{PathPrefix: "/v2/"}}, // inherits domain rate_limit
			{Match: config.Match{PathPrefix: "/own/"}, Policy: config.PolicySpec{
				Engines: &config.EnginesSpec{RateLimit: &config.RateLimitSpec{
					RequestsPerSecond: 1, Burst: burst, Key: "host",
				}},
			}},
		},
	})
	r := mustCompile(t, cfg)
	req := &engine.Request{Direction: engine.DirectionRequest, Host: "a.com", Headers: emptyHeaders{}}
	consume := func(p *CompiledPolicy) decision.Action {
		v, _ := p.Engines.Inspect(context.Background(), req)
		return v.Action
	}

	v1 := r.Resolve(in("a.com", "/v1/x", "GET", ""))
	v2 := r.Resolve(in("a.com", "/v2/x", "GET", ""))
	own := r.Resolve(in("a.com", "/own/x", "GET", ""))

	// Inherited routes share ONE limiter: 2 requests across v1+v2 exhaust the
	// combined burst, so the 3rd (on either) is blocked.
	if consume(v1) == decision.Block || consume(v2) == decision.Block {
		t.Fatal("first two combined requests should pass the shared limiter")
	}
	if consume(v1) != decision.Block {
		t.Fatal("inherited routes must share buckets — combined burst should be exhausted")
	}

	// The route with its OWN rate_limit is independent (its burst is untouched).
	if consume(own) == decision.Block {
		t.Fatal("a route with its own rate_limit must have an independent bucket")
	}
}
