// Package bot implements a header-phase, block-capable bot/scanner/automation
// detection engine. It is pure-Go and ships in the lean binary. Detection is a
// layered scorer, cheapest decisive signal first; any layer may hard-block, and
// the accumulated score blocks when it reaches the configured threshold.
//
// Layers (in evaluation order):
//
//  1. Verified bots — a request whose User-Agent claims a known crawler
//     (Googlebot/Bingbot/…) is verified against that crawler's published IP
//     ranges (loaded from a feed file): a match short-circuits to ALLOW (so real
//     crawlers are never collateral-damaged); a claim from an IP outside the
//     ranges is impersonation and is hard-blocked.
//  2. User-Agent — empty UA (optional) and a deny-substring list (RE2) hard-block;
//     a known-bot UA contributes to the score.
//  3. TLS fingerprint — JA3/JA4 hashes that Envoy computes and forwards as request
//     headers (e.g. x-shield-ja4). Deny sets hard-block; a score map contributes;
//     a "tool" JA4 (curl/python/…) presented with a browser User-Agent is an
//     inconsistency and is hard-blocked.
//  4. Header heuristics — missing Accept / Accept-Language / Accept-Encoding each
//     contribute to the score (automation clients routinely omit them).
//
// All compilation (regexes, feed tries, hash sets) happens once in New on the
// cold path; the hot path parses the UA once and does map/prefix lookups.
package bot

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	ua "github.com/mileusna/useragent"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/feed"
	"github.com/cloudnativeworks/elchi-shield/internal/netmatch"
)

const engineName = "bot"

// UAConfig configures the User-Agent layer.
type UAConfig struct {
	DenySubstrings []string // case-insensitive substrings that hard-block
	BlockEmpty     bool     // block a missing/empty User-Agent
	ScoreKnownBot  int      // score added when the UA parses as a known bot
}

// VerifiedBotConfig declares a crawler whose claim is verified against an IP feed.
type VerifiedBotConfig struct {
	Name    string // identifier (e.g. "googlebot")
	File    string // feed file of the crawler's published CIDRs
	Format  string // feed.Format* parser
	UAMatch string // regex matched against the User-Agent to detect the claim
}

// TLSConfig configures the JA3/JA4 fingerprint layer (fingerprints arrive as
// Envoy-supplied request headers).
type TLSConfig struct {
	JA4Header string         // header carrying the JA4 hash (default "x-shield-ja4")
	JA3Header string         // header carrying the JA3 hash (default "x-shield-ja3")
	DenyJA4   []string       // JA4 hashes that hard-block
	DenyJA3   []string       // JA3 hashes that hard-block
	ScoreJA4  map[string]int // JA4 hash → score contribution
	ToolJA4   []string       // JA4 hashes of CLI tools: block if UA claims a browser
}

// HeuristicsConfig configures the header-anomaly layer.
type HeuristicsConfig struct {
	RequireAccept         bool
	RequireAcceptLanguage bool
	RequireAcceptEncoding bool
	ScorePerAnomaly       int
}

// Config configures the bot engine.
type Config struct {
	ScoreThreshold int
	UA             UAConfig
	VerifiedBots   []VerifiedBotConfig
	TLS            TLSConfig
	Heuristics     HeuristicsConfig
	// EmitScore, when true, makes the engine contribute its computed score to the
	// policy's collaborative anomaly score (returning a non-blocking verdict)
	// instead of blocking at its own ScoreThreshold. Hard-block layers (UA deny,
	// impersonation, JA4 deny / consistency) still block.
	EmitScore bool
}

type verifiedBot struct {
	name string
	ua   *regexp.Regexp
	ips  *netmatch.Set[struct{}]
}

// Engine is the compiled, immutable bot detector.
type Engine struct {
	threshold     int
	denyUA        *regexp.Regexp
	blockEmpty    bool
	scoreKnownBot int
	verified      []verifiedBot

	ja4Header string
	ja3Header string
	denyJA4   map[string]struct{}
	denyJA3   map[string]struct{}
	scoreJA4  map[string]int
	toolJA4   map[string]struct{}

	hRequireAccept bool
	hRequireAL     bool
	hRequireAE     bool
	hScore         int

	emitScore bool
}

// New compiles the configuration into an Engine. Parse/load errors are returned
// so a bad config aborts the reload and the last-good snapshot stays active.
func New(cfg Config) (*Engine, error) {
	e := &Engine{
		threshold:     cfg.ScoreThreshold,
		blockEmpty:    cfg.UA.BlockEmpty,
		scoreKnownBot: cfg.UA.ScoreKnownBot,
		ja4Header:     orDefault(cfg.TLS.JA4Header, "x-shield-ja4"),
		ja3Header:     orDefault(cfg.TLS.JA3Header, "x-shield-ja3"),
		denyJA4:       toSet(cfg.TLS.DenyJA4),
		denyJA3:       toSet(cfg.TLS.DenyJA3),
		toolJA4:       toSet(cfg.TLS.ToolJA4),
		scoreJA4:      cfg.TLS.ScoreJA4,

		hRequireAccept: cfg.Heuristics.RequireAccept,
		hRequireAL:     cfg.Heuristics.RequireAcceptLanguage,
		hRequireAE:     cfg.Heuristics.RequireAcceptEncoding,
		hScore:         cfg.Heuristics.ScorePerAnomaly,
		emitScore:      cfg.EmitScore,
	}

	if len(cfg.UA.DenySubstrings) > 0 {
		quoted := make([]string, len(cfg.UA.DenySubstrings))
		for i, s := range cfg.UA.DenySubstrings {
			quoted[i] = regexp.QuoteMeta(s)
		}
		re, err := regexp.Compile("(?i)" + strings.Join(quoted, "|"))
		if err != nil {
			return nil, fmt.Errorf("bot: deny_substrings: %w", err)
		}
		e.denyUA = re
	}

	for _, vb := range cfg.VerifiedBots {
		re, err := regexp.Compile(vb.UAMatch)
		if err != nil {
			return nil, fmt.Errorf("bot: verified_bots %q ua_match: %w", vb.Name, err)
		}
		prefixes, err := feed.Load(vb.File, vb.Format)
		if err != nil {
			return nil, fmt.Errorf("bot: verified_bots %q feed: %w", vb.Name, err)
		}
		set := netmatch.New[struct{}]()
		for _, p := range prefixes {
			set.Insert(p, struct{}{})
		}
		e.verified = append(e.verified, verifiedBot{name: vb.Name, ua: re, ips: set})
	}

	return e, nil
}

// Name implements engine.SecurityEngine.
func (*Engine) Name() string { return engineName }

// RequiresBody implements engine.SecurityEngine: bot detection reads only headers.
func (*Engine) RequiresBody() bool { return false }

// Close implements engine.SecurityEngine.
func (*Engine) Close() error { return nil }

// Inspect runs the layered detection. Responses pass through.
func (e *Engine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	if req.Direction != engine.DirectionRequest {
		return decision.Verdict{}, nil
	}
	uaStr, _ := req.Headers.Header("user-agent")
	parsed := ua.Parse(uaStr)

	// Layer 1: verified bots (ALLOW short-circuit or impersonation hard-block).
	for i := range e.verified {
		vb := &e.verified[i]
		if vb.ua.MatchString(uaStr) {
			if ip, err := netip.ParseAddr(req.SourceIP); err == nil && vb.ips.Contains(ip) {
				return decision.Verdict{}, nil // verified crawler → allow
			}
			return block("bot.impersonation:"+vb.name,
				"claims "+vb.name+" but source IP is not in its published ranges", decision.SeverityHigh), nil
		}
	}

	// Layer 2: User-Agent hard blocks.
	if e.blockEmpty && strings.TrimSpace(uaStr) == "" {
		return block("bot.ua_empty", "missing User-Agent", decision.SeverityMedium), nil
	}
	if e.denyUA != nil && e.denyUA.MatchString(uaStr) {
		return block("bot.ua_deny", "User-Agent matches a denied client", decision.SeverityHigh), nil
	}

	// Layer 3: TLS fingerprint hard blocks + JA4↔UA consistency.
	ja4, _ := req.Headers.Header(e.ja4Header)
	ja3, _ := req.Headers.Header(e.ja3Header)
	if ja4 != "" {
		if _, ok := e.denyJA4[ja4]; ok {
			return block("bot.ja4_deny", "TLS fingerprint (JA4) is denied", decision.SeverityHigh), nil
		}
		if _, ok := e.toolJA4[ja4]; ok && isBrowserClaim(parsed) {
			return block("bot.ja4_ua_mismatch",
				"TLS fingerprint is an automation tool but User-Agent claims a browser", decision.SeverityHigh), nil
		}
	}
	if ja3 != "" {
		if _, ok := e.denyJA3[ja3]; ok {
			return block("bot.ja3_deny", "TLS fingerprint (JA3) is denied", decision.SeverityHigh), nil
		}
	}

	// Scoring layers.
	score := 0
	if e.scoreKnownBot > 0 && parsed.Bot {
		score += e.scoreKnownBot
	}
	if ja4 != "" && e.scoreJA4 != nil {
		score += e.scoreJA4[ja4]
	}
	if e.hScore > 0 {
		if e.hRequireAccept && !hasHeader(req, "accept") {
			score += e.hScore
		}
		if e.hRequireAL && !hasHeader(req, "accept-language") {
			score += e.hScore
		}
		if e.hRequireAE && !hasHeader(req, "accept-encoding") {
			score += e.hScore
		}
	}
	// In emit-score mode, contribute the score to the policy's anomaly aggregator
	// (non-blocking) rather than blocking at the engine's own threshold.
	if e.emitScore {
		return decision.Verdict{Score: score}, nil
	}
	if e.threshold > 0 && score >= e.threshold {
		return block("bot.score", fmt.Sprintf("bot score %d >= threshold %d", score, e.threshold), decision.SeverityMedium), nil
	}
	return decision.Verdict{}, nil
}

// isBrowserClaim reports whether the parsed UA claims a mainstream browser (and
// is not itself a declared bot).
func isBrowserClaim(p ua.UserAgent) bool {
	if p.Bot {
		return false
	}
	return p.IsChrome() || p.IsFirefox() || p.IsSafari() || p.IsEdge() || p.IsOpera()
}

func hasHeader(req *engine.Request, name string) bool {
	v, ok := req.Headers.Header(name)
	return ok && v != ""
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func toSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(items))
	for _, s := range items {
		m[s] = struct{}{}
	}
	return m
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
