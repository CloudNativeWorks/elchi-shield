package policy

import (
	"fmt"
	"os"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/engine/apikey"
	"github.com/cloudnativeworks/elchi-shield/internal/engine/bot"
	"github.com/cloudnativeworks/elchi-shield/internal/engine/hmacsign"
	"github.com/cloudnativeworks/elchi-shield/internal/engine/httpsig"
	"github.com/cloudnativeworks/elchi-shield/internal/engine/ipreputation"
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

	if ir := spec.IPReputation; ir != nil {
		e, err := buildIPReputation(ir)
		if err != nil {
			return nil, fmt.Errorf("ip_reputation engine: %w", err)
		}
		engines = append(engines, e)
	}

	if b := spec.Bot; b != nil {
		e, err := buildBot(b)
		if err != nil {
			return nil, fmt.Errorf("bot engine: %w", err)
		}
		engines = append(engines, e)
	}

	if ak := spec.APIKey; ak != nil {
		e, err := buildAPIKey(ak)
		if err != nil {
			return nil, fmt.Errorf("api_key engine: %w", err)
		}
		engines = append(engines, e)
	}

	if h := spec.HMACSign; h != nil {
		e, err := buildHMACSign(h)
		if err != nil {
			return nil, fmt.Errorf("hmac_sign engine: %w", err)
		}
		engines = append(engines, e)
	}

	if hs := spec.HTTPSignature; hs != nil {
		e, err := httpsig.New(httpsig.Config{
			Secret:            hs.Secret,
			SignatureName:     hs.SignatureName,
			CoveredComponents: hs.CoveredComponents,
			MaxAge:            hs.MaxAge.AsDuration(),
		})
		if err != nil {
			return nil, fmt.Errorf("http_signature engine: %w", err)
		}
		engines = append(engines, e)
	}

	if len(engines) == 0 {
		return nil, nil
	}
	return engine.NewSet(engines...), nil
}

// buildIPReputation constructs the IP-reputation engine, loading its feed files
// from disk (cold path). A bad CIDR or unreadable feed aborts the reload.
func buildIPReputation(ir *config.IPReputationSpec) (engine.SecurityEngine, error) {
	feeds := make([]ipreputation.FeedConfig, 0, len(ir.Feeds))
	for _, f := range ir.Feeds {
		feeds = append(feeds, ipreputation.FeedConfig{
			Name:     f.Name,
			File:     f.File,
			Format:   f.Format,
			Severity: parseSeverity(f.Severity),
		})
	}
	var geo *ipreputation.GeoConfig
	if g := ir.GeoIP; g != nil {
		geo = &ipreputation.GeoConfig{
			CountryDBFile:  g.DatabaseFile,
			ASNDBFile:      g.ASNDatabaseFile,
			BlockCountries: g.BlockCountries,
			AllowCountries: g.AllowCountries,
			BlockASNs:      g.BlockASNs,
			BlockOnMissing: g.OnMissing == "block",
		}
	}
	return ipreputation.New(ipreputation.Config{
		AllowCIDRs: ir.AllowCIDRs,
		DenyCIDRs:  ir.DenyCIDRs,
		Feeds:      feeds,
		Geo:        geo,
	})
}

// buildBot constructs the bot-detection engine, loading any verified-bot IP
// feeds from disk (cold path).
func buildBot(b *config.BotSpec) (engine.SecurityEngine, error) {
	cfg := bot.Config{ScoreThreshold: b.ScoreThreshold}
	if ua := b.UserAgent; ua != nil {
		cfg.UA = bot.UAConfig{
			DenySubstrings: ua.DenySubstrings,
			BlockEmpty:     ua.BlockEmpty,
			ScoreKnownBot:  ua.ScoreKnownBot,
		}
	}
	for _, vb := range b.VerifiedBots {
		cfg.VerifiedBots = append(cfg.VerifiedBots, bot.VerifiedBotConfig{
			Name:    vb.Name,
			File:    vb.File,
			Format:  vb.Format,
			UAMatch: vb.UAMatch,
		})
	}
	if t := b.TLSFingerprint; t != nil {
		cfg.TLS = bot.TLSConfig{
			JA4Header: t.JA4Header,
			JA3Header: t.JA3Header,
			DenyJA4:   t.DenyJA4,
			DenyJA3:   t.DenyJA3,
			ScoreJA4:  t.ScoreJA4,
			ToolJA4:   t.ToolJA4,
		}
	}
	if h := b.Heuristics; h != nil {
		cfg.Heuristics = bot.HeuristicsConfig{
			RequireAccept:         h.RequireAccept,
			RequireAcceptLanguage: h.RequireAcceptLanguage,
			RequireAcceptEncoding: h.RequireAcceptEncoding,
			ScorePerAnomaly:       h.ScorePerAnomaly,
		}
	}
	return bot.New(cfg)
}

// buildAPIKey constructs the API-key engine.
func buildAPIKey(ak *config.APIKeySpec) (engine.SecurityEngine, error) {
	keys := make([]apikey.KeyEntry, 0, len(ak.Keys))
	for _, k := range ak.Keys {
		keys = append(keys, apikey.KeyEntry{SHA256: k.SHA256, Key: k.Key, Subject: k.Subject, Scopes: k.Scopes})
	}
	bindings := make([]apikey.ScopeBinding, 0, len(ak.Bindings))
	for _, b := range ak.Bindings {
		bindings = append(bindings, apikey.ScopeBinding{PathPrefix: b.PathPrefix, Scope: b.Scope})
	}
	return apikey.New(apikey.Config{Source: ak.Source, Name: ak.Name, Keys: keys, Bindings: bindings})
}

// buildHMACSign constructs the HMAC request-signing engine.
func buildHMACSign(h *config.HMACSignSpec) (engine.SecurityEngine, error) {
	return hmacsign.New(hmacsign.Config{
		Secret:            h.Secret,
		Secrets:           h.Secrets,
		SignatureHeader:   h.SignatureHeader,
		TimestampHeader:   h.TimestampHeader,
		NonceHeader:       h.NonceHeader,
		KeyIDHeader:       h.KeyIDHeader,
		Algorithm:         h.Algorithm,
		Window:            h.Window.AsDuration(),
		NonceTTL:          h.NonceTTL.AsDuration(),
		RequireNonce:      h.RequireNonce,
		RequireBodyDigest: h.RequireBodyDigest,
	})
}

// parseSeverity maps a config severity string to a decision.Severity (default
// medium).
func parseSeverity(s string) decision.Severity {
	switch s {
	case "low":
		return decision.SeverityLow
	case "high":
		return decision.SeverityHigh
	case "critical":
		return decision.SeverityCritical
	default:
		return decision.SeverityMedium
	}
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
