// Package ipreputation implements a header-phase security engine that blocks
// requests by source IP: static CIDR allow/deny lists plus threat-intelligence
// feeds loaded from disk. It is pure-Go and ships in the lean binary.
//
// All compilation (parsing feeds, building the prefix tries) happens once on the
// cold path in New; the hot path parses the source IP once and does
// allocation-free longest-prefix lookups. Evaluation order, cheapest decisive
// signal first:
//
//  1. deny CIDRs        — explicit block
//  2. allow CIDRs       — if any are configured, the list is default-DENY: an IP
//     not in the allow set is blocked
//  3. threat feeds      — block if the IP is in a feed whose action is "block"
//
// The engine is stateless (no per-request mutation), so it needs no lock and is
// not shared by *EnginesSpec identity beyond the engine.Set dedup.
package ipreputation

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/feed"
	"github.com/cloudnativeworks/elchi-shield/internal/geoip"
	"github.com/cloudnativeworks/elchi-shield/internal/netmatch"
)

const engineName = "ipreputation"

// FeedConfig describes one threat-intelligence feed file.
type FeedConfig struct {
	Name     string // identifier surfaced in the block reason/metric
	File     string // path to the feed file (operator/management-plane controlled)
	Format   string // feed.Format* (cidr_lines | firehol_netset | spamhaus_json)
	Severity decision.Severity
}

// GeoConfig configures GeoIP-based blocking. CountryDBFile and/or ASNDBFile are
// MaxMind .mmdb paths. BlockOnMissing blocks a source IP absent from the
// database (e.g. private/unroutable ranges) when true.
type GeoConfig struct {
	CountryDBFile  string
	ASNDBFile      string
	BlockCountries []string // ISO codes to block
	AllowCountries []string // when non-empty: any other country is blocked (default-deny)
	BlockASNs      []uint
	BlockOnMissing bool
}

// Config configures the IP-reputation engine. All slices are parsed once in New.
type Config struct {
	// AllowCIDRs, when non-empty, switches the engine to default-DENY: a source
	// IP that matches no allow prefix is blocked.
	AllowCIDRs []string
	// DenyCIDRs are explicitly blocked prefixes.
	DenyCIDRs []string
	// Feeds are threat-intelligence feed files (all treated as block lists).
	Feeds []FeedConfig
	// Geo, when set, enables GeoIP/ASN-based blocking.
	Geo *GeoConfig
}

// feedMeta is the value stored per prefix in the feed trie.
type feedMeta struct {
	name     string
	severity decision.Severity
}

// geoMatch holds the compiled GeoIP block/allow sets.
type geoMatch struct {
	reader         *geoip.Reader
	blockCountries map[string]struct{}
	allowCountries map[string]struct{}
	blockASNs      map[uint]struct{}
	hasAllow       bool
	blockOnMissing bool
}

// Engine is the compiled, immutable IP-reputation matcher.
type Engine struct {
	allow    *netmatch.Set[struct{}]
	deny     *netmatch.Set[struct{}]
	feeds    *netmatch.Set[feedMeta]
	geo      *geoMatch
	hasAllow bool
	hasDeny  bool
	hasFeeds bool
}

// New compiles the configuration into an Engine. Parse/load errors are returned
// so a bad config aborts the reload and the last-good snapshot stays active.
func New(cfg Config) (*Engine, error) {
	e := &Engine{
		allow: netmatch.New[struct{}](),
		deny:  netmatch.New[struct{}](),
		feeds: netmatch.New[feedMeta](),
	}

	for _, c := range cfg.AllowCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("allow_cidrs: invalid CIDR %q: %w", c, err)
		}
		e.allow.Insert(p, struct{}{})
	}
	for _, c := range cfg.DenyCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("deny_cidrs: invalid CIDR %q: %w", c, err)
		}
		e.deny.Insert(p, struct{}{})
	}
	for _, fc := range cfg.Feeds {
		prefixes, err := feed.Load(fc.File, fc.Format)
		if err != nil {
			return nil, fmt.Errorf("feed %q: %w", fc.Name, err)
		}
		sev := fc.Severity
		if sev == decision.SeverityNone {
			sev = decision.SeverityMedium
		}
		meta := feedMeta{name: fc.Name, severity: sev}
		for _, p := range prefixes {
			e.feeds.Insert(p, meta)
		}
	}

	if cfg.Geo != nil {
		g, err := buildGeo(cfg.Geo)
		if err != nil {
			return nil, err
		}
		e.geo = g
	}

	e.hasAllow = e.allow.Len() > 0
	e.hasDeny = e.deny.Len() > 0
	e.hasFeeds = e.feeds.Len() > 0
	return e, nil
}

// buildGeo opens the GeoIP databases and compiles the block/allow sets.
func buildGeo(c *GeoConfig) (*geoMatch, error) {
	reader, err := geoip.Open(c.CountryDBFile, c.ASNDBFile)
	if err != nil {
		return nil, fmt.Errorf("geoip: %w", err)
	}
	g := &geoMatch{
		reader:         reader,
		blockCountries: make(map[string]struct{}, len(c.BlockCountries)),
		allowCountries: make(map[string]struct{}, len(c.AllowCountries)),
		blockASNs:      make(map[uint]struct{}, len(c.BlockASNs)),
		hasAllow:       len(c.AllowCountries) > 0,
		blockOnMissing: c.BlockOnMissing,
	}
	for _, cc := range c.BlockCountries {
		g.blockCountries[strings.ToUpper(cc)] = struct{}{}
	}
	for _, cc := range c.AllowCountries {
		g.allowCountries[strings.ToUpper(cc)] = struct{}{}
	}
	for _, n := range c.BlockASNs {
		g.blockASNs[n] = struct{}{}
	}
	return g, nil
}

// Name implements engine.SecurityEngine.
func (*Engine) Name() string { return engineName }

// RequiresBody implements engine.SecurityEngine: IP reputation reads only the
// source IP, so it runs at the cheap header phase and never buffers the body.
func (*Engine) RequiresBody() bool { return false }

// Close implements engine.SecurityEngine, releasing any GeoIP database readers.
func (e *Engine) Close() error {
	if e.geo != nil && e.geo.reader != nil {
		return e.geo.reader.Close()
	}
	return nil
}

// Inspect evaluates the request's source IP against the deny/allow/feed sets.
// Responses pass through (reputation is a request-side control). A request with
// no parseable source IP is not blocked by deny/feed rules, but IS blocked by a
// default-deny allow list (an unidentifiable client cannot be on the allowlist).
func (e *Engine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	if req.Direction != engine.DirectionRequest {
		return decision.Verdict{}, nil
	}
	ip, err := netip.ParseAddr(req.SourceIP)
	if err != nil || !ip.IsValid() {
		// No usable source IP. Default-deny allow lists must still reject it.
		if e.hasAllow {
			return block("ipreputation.not_allowlisted", "source IP not in allow list (unidentifiable client)", decision.SeverityHigh), nil
		}
		return decision.Verdict{}, nil
	}

	if e.hasDeny && e.deny.Contains(ip) {
		return block("ipreputation.deny_cidr", "source IP in deny list", decision.SeverityHigh), nil
	}
	if e.hasAllow && !e.allow.Contains(ip) {
		return block("ipreputation.not_allowlisted", "source IP not in allow list", decision.SeverityHigh), nil
	}
	if e.hasFeeds {
		if m, hit := e.feeds.Lookup(ip); hit {
			return block("ipreputation.feed:"+m.name, "source IP in threat feed "+m.name, m.severity), nil
		}
	}
	if e.geo != nil {
		if v, blocked := e.geo.inspect(ip); blocked {
			return v, nil
		}
	}
	return decision.Verdict{}, nil
}

// inspect evaluates the GeoIP block/allow rules for ip. A lookup error or a miss
// is treated per blockOnMissing (default: continue).
func (g *geoMatch) inspect(ip netip.Addr) (decision.Verdict, bool) {
	rec, err := g.reader.Lookup(ip)
	if err != nil {
		// A database error is fail-open at the engine; the policy fail posture
		// still governs the request via the executor if configured fail_close.
		return decision.Verdict{}, false
	}
	if rec.Country == "" && rec.ASN == 0 {
		if g.blockOnMissing {
			return block("ipreputation.geo_unknown", "source IP not found in GeoIP database", decision.SeverityLow), true
		}
		return decision.Verdict{}, false
	}
	if rec.Country != "" {
		if _, deny := g.blockCountries[rec.Country]; deny {
			return block("ipreputation.geo_country:"+rec.Country, "source country blocked: "+rec.Country, decision.SeverityMedium), true
		}
		if g.hasAllow {
			if _, ok := g.allowCountries[rec.Country]; !ok {
				return block("ipreputation.geo_country:"+rec.Country, "source country not allowed: "+rec.Country, decision.SeverityMedium), true
			}
		}
	}
	if rec.ASN != 0 {
		if _, deny := g.blockASNs[rec.ASN]; deny {
			return block(fmt.Sprintf("ipreputation.geo_asn:%d", rec.ASN), fmt.Sprintf("source ASN blocked: %d", rec.ASN), decision.SeverityMedium), true
		}
	}
	return decision.Verdict{}, false
}

func block(ruleID, reason string, sev decision.Severity) decision.Verdict {
	return decision.Verdict{
		Action:     decision.Block,
		Reason:     reason,
		RuleID:     ruleID,
		Engine:     engineName,
		Severity:   sev,
		StatusCode: decision.DefaultBlockStatus,
	}
}
