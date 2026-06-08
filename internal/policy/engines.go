package policy

import (
	"fmt"
	"os"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/engine/jwt"
	"github.com/cloudnativeworks/elchi-shield/internal/engine/ratelimit"
)

// engineCache deduplicates engine.Set construction within a single reload. It is
// keyed by the *EnginesSpec pointer: config.Resolve assigns the inherited spec
// by reference (out.Engines = s.Engines), so two policies sharing a spec share
// the exact pointer and therefore one engine.Set. It is not safe for concurrent
// use; Compile drives it single-threaded on the cold path.
//
// State-sharing semantics (matters for STATEFUL engines like rate-limit):
// because inherited policies share one engine.Set instance, they also share that
// engine's mutable state. The rule is "sharing follows inheritance":
//   - a rate_limit defined at the DOMAIN level and inherited by N routes is ONE
//     combined limiter across those routes (shared token buckets) — a domain-wide
//     limit;
//   - a rate_limit defined on a ROUTE (overriding/standalone) is independent;
//   - two separately-written identical blocks are independent (different
//     pointers).
//
// So: define the limit at the scope it should apply. Stateless engines (JWT,
// Coraza) are unaffected by this sharing.
type engineCache struct {
	byPtr map[*config.EnginesSpec]*engine.Set
}

func newEngineCache() *engineCache {
	return &engineCache{byPtr: make(map[*config.EnginesSpec]*engine.Set)}
}

// get returns the engine.Set for spec, building it once and reusing it for any
// later policy that inherits the same spec pointer. A nil spec yields a nil Set.
func (c *engineCache) get(spec *config.EnginesSpec) (*engine.Set, error) {
	if spec == nil {
		return nil, nil
	}
	if set, ok := c.byPtr[spec]; ok {
		return set, nil
	}
	set, err := buildEngines(spec)
	if err != nil {
		return nil, err
	}
	c.byPtr[spec] = set
	return set, nil
}

// buildEngines compiles a policy's engine specification into an engine.Set
// during the cold path. It returns nil when no engines are configured. Errors
// (bad key file, Coraza requested on a binary without the build tag) abort the
// reload so the last-good snapshot stays active.
func buildEngines(spec *config.EnginesSpec) (*engine.Set, error) {
	if spec == nil {
		return nil, nil
	}

	var engines []engine.SecurityEngine

	if j := spec.JWT; j != nil {
		e, err := buildJWT(j)
		if err != nil {
			return nil, fmt.Errorf("jwt engine: %w", err)
		}
		engines = append(engines, e)
	}

	if c := spec.Coraza; c != nil {
		directives := c.Directives
		if c.DirectivesFile != "" {
			data, err := os.ReadFile(c.DirectivesFile)
			if err != nil {
				return nil, fmt.Errorf("coraza directives_file: %w", err)
			}
			directives += "\n" + string(data)
		}
		e, err := engine.NewCoraza(engine.CorazaConfig{
			Directives:     directives,
			IncludeOWASP:   c.IncludeOWASP,
			ExcludeRuleIDs: c.ExcludeRuleIDs,
		})
		if err != nil {
			return nil, fmt.Errorf("coraza engine: %w", err)
		}
		engines = append(engines, e)
	}

	if rl := spec.RateLimit; rl != nil {
		e, err := buildRateLimit(rl)
		if err != nil {
			return nil, fmt.Errorf("rate_limit engine: %w", err)
		}
		engines = append(engines, e)
	}

	if len(engines) == 0 {
		return nil, nil
	}
	return engine.NewSet(engines...), nil
}

// buildRateLimit constructs the rate-limit engine from its config.
func buildRateLimit(rl *config.RateLimitSpec) (engine.SecurityEngine, error) {
	key := ratelimit.KeyIP
	switch rl.Key {
	case "host":
		key = ratelimit.KeyHost
	case "header":
		key = ratelimit.KeyHeader
	}
	return ratelimit.New(ratelimit.Config{
		RequestsPerSecond: rl.RequestsPerSecond,
		Burst:             rl.Burst,
		Key:               key,
		Header:            rl.Header,
	})
}

// buildJWT constructs the JWT engine, reading the public key file when set.
func buildJWT(j *config.JWTSpec) (engine.SecurityEngine, error) {
	cfg := jwt.Config{
		Issuer:         j.Issuer,
		Audience:       j.Audience,
		Algorithms:     j.Algorithms,
		RequiredClaims: j.RequiredClaims,
		HeaderName:     j.HeaderName,
		Leeway:         j.Leeway.AsDuration(),
	}
	if j.HMACSecret != "" {
		cfg.HMACSecret = []byte(j.HMACSecret)
	}
	if j.PublicKeyFile != "" {
		pem, err := os.ReadFile(j.PublicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("public_key_file: %w", err)
		}
		cfg.PublicKeyPEM = pem
	}
	return jwt.New(cfg)
}
