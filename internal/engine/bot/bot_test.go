package bot

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

type hdrs map[string]string

func (h hdrs) Header(name string) (string, bool) {
	for k, v := range h {
		if equalFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func (h hdrs) RangeHeaders(fn func(string, string) bool) {
	for k, v := range h {
		if !fn(k, v) {
			return
		}
	}
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func reqWith(ip string, h hdrs) *engine.Request {
	return &engine.Request{Direction: engine.DirectionRequest, SourceIP: ip, Headers: h}
}

func inspect(t *testing.T, e *Engine, ip string, h hdrs) decision.Verdict {
	t.Helper()
	v, err := e.Inspect(context.Background(), reqWith(ip, h))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return v
}

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

func TestUADenyAndEmpty(t *testing.T) {
	e, err := New(Config{UA: UAConfig{DenySubstrings: []string{"sqlmap", "python-requests", "curl/"}, BlockEmpty: true}})
	if err != nil {
		t.Fatal(err)
	}
	if v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": "python-requests/2.28"}); v.Action != decision.Block {
		t.Fatal("python-requests UA should be blocked")
	}
	if v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": "curl/8.1.2"}); v.Action != decision.Block {
		t.Fatal("curl UA should be blocked")
	}
	if v := inspect(t, e, "1.2.3.4", hdrs{}); v.Action != decision.Block || v.RuleID != "bot.ua_empty" {
		t.Fatalf("empty UA should be blocked, got %+v", v)
	}
	if v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": chromeUA}); v.Action == decision.Block {
		t.Fatal("normal browser UA should pass")
	}
}

func writeFeed(t *testing.T, lines string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "googlebot.txt")
	if err := os.WriteFile(p, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifiedBotAndImpersonation(t *testing.T) {
	feedFile := writeFeed(t, "66.249.64.0/19\n")
	e, err := New(Config{VerifiedBots: []VerifiedBotConfig{{
		Name: "googlebot", File: feedFile, Format: "cidr_lines", UAMatch: "(?i)googlebot",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	gUA := hdrs{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
	// Verified: Googlebot UA from a Google IP → allow (pass).
	if v := inspect(t, e, "66.249.64.10", gUA); v.Action == decision.Block {
		t.Fatal("verified Googlebot should pass")
	}
	// Impersonation: Googlebot UA from a non-Google IP → block.
	v := inspect(t, e, "1.2.3.4", gUA)
	if v.Action != decision.Block || v.RuleID != "bot.impersonation:googlebot" {
		t.Fatalf("Googlebot impersonation should be blocked, got %+v", v)
	}
}

func TestJA4DenyAndConsistency(t *testing.T) {
	e, err := New(Config{TLS: TLSConfig{
		DenyJA4: []string{"t13d_bad_hash"},
		ToolJA4: []string{"t13d_curl_hash"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	// Denied JA4 → block.
	if v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": chromeUA, "x-shield-ja4": "t13d_bad_hash"}); v.RuleID != "bot.ja4_deny" {
		t.Fatalf("denied JA4 should block, got %+v", v)
	}
	// Tool JA4 + browser UA → consistency block.
	if v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": chromeUA, "x-shield-ja4": "t13d_curl_hash"}); v.RuleID != "bot.ja4_ua_mismatch" {
		t.Fatalf("tool-JA4 with browser UA should block, got %+v", v)
	}
	// Tool JA4 + non-browser (curl) UA → no inconsistency (passes this layer).
	if v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": "curl/8.0", "x-shield-ja4": "t13d_curl_hash"}); v.Action == decision.Block {
		t.Fatal("tool JA4 with a matching non-browser UA should not hard-block on consistency")
	}
}

func TestScoringThreshold(t *testing.T) {
	e, err := New(Config{
		ScoreThreshold: 100,
		Heuristics:     HeuristicsConfig{RequireAcceptLanguage: true, ScorePerAnomaly: 100},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Missing Accept-Language → one anomaly → score 100 ≥ threshold → block.
	if v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": chromeUA}); v.Action != decision.Block || v.RuleID != "bot.score" {
		t.Fatalf("missing Accept-Language should reach threshold, got %+v", v)
	}
	// Present Accept-Language → no anomaly → pass.
	if v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": chromeUA, "Accept-Language": "en-US"}); v.Action == decision.Block {
		t.Fatal("request with Accept-Language should pass")
	}
}

func TestKnownBotScore(t *testing.T) {
	e, err := New(Config{ScoreThreshold: 50, UA: UAConfig{ScoreKnownBot: 50}})
	if err != nil {
		t.Fatal(err)
	}
	// A generic bot UA (parsed as bot) reaches the threshold.
	if v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": "SomeCrawler/1.0 (+http://example.com/bot)"}); v.Action != decision.Block {
		t.Fatal("known-bot UA should reach threshold and block")
	}
	if v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": chromeUA}); v.Action == decision.Block {
		t.Fatal("browser UA should not be scored as a bot")
	}
}

func TestResponseDirectionPasses(t *testing.T) {
	e, _ := New(Config{UA: UAConfig{BlockEmpty: true}})
	v, err := e.Inspect(context.Background(), &engine.Request{Direction: engine.DirectionResponse, Headers: hdrs{}})
	if err != nil {
		t.Fatal(err)
	}
	if v.Action == decision.Block {
		t.Fatal("bot engine must not run on the response direction")
	}
}

func TestBadConfig(t *testing.T) {
	if _, err := New(Config{VerifiedBots: []VerifiedBotConfig{{Name: "x", File: "/nonexistent", Format: "cidr_lines", UAMatch: "(?i)bot"}}}); err == nil {
		t.Fatal("expected error for missing verified-bot feed file")
	}
	if _, err := New(Config{VerifiedBots: []VerifiedBotConfig{{Name: "x", File: "/x", Format: "cidr_lines", UAMatch: "("}}}); err == nil {
		t.Fatal("expected error for invalid ua_match regex")
	}
}

func TestMetadata(t *testing.T) {
	e, _ := New(Config{UA: UAConfig{BlockEmpty: true}})
	if e.Name() != "bot" {
		t.Errorf("name = %q", e.Name())
	}
	if e.RequiresBody() {
		t.Error("bot engine must be header-phase")
	}
	if err := e.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestEmitScoreMode(t *testing.T) {
	// In emit-score mode the bot contributes its score (Continue) instead of
	// blocking at its own threshold, but hard layers still block.
	e, err := New(Config{
		ScoreThreshold: 50,
		EmitScore:      true,
		UA:             UAConfig{ScoreKnownBot: 40, DenySubstrings: []string{"sqlmap"}},
		Heuristics:     HeuristicsConfig{RequireAcceptLanguage: true, ScorePerAnomaly: 40},
	})
	if err != nil {
		t.Fatal(err)
	}
	// A bot UA missing Accept-Language → 40 (bot) + 40 (heuristic) = 80, but NOT
	// a block — the score is emitted for the anomaly aggregator.
	v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": "SomeCrawler/1.0 (+http://x/bot)"})
	if v.Action == decision.Block {
		t.Fatalf("emit-score mode must not block on score, got %+v", v)
	}
	if v.Score != 80 {
		t.Fatalf("expected score 80, got %d", v.Score)
	}
	// Hard layer (UA deny) still blocks even in emit-score mode.
	if v := inspect(t, e, "1.2.3.4", hdrs{"User-Agent": "sqlmap/1.0"}); v.Action != decision.Block {
		t.Fatal("hard UA-deny must still block in emit-score mode")
	}
}
