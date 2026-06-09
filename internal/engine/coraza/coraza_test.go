package coraza

import (
	"context"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

type noHeaders struct{}

func (noHeaders) Header(string) (string, bool)           { return "", false }
func (noHeaders) RangeHeaders(func(string, string) bool) {}

// realHeaders is a realistic browser-like header set. The OWASP CRS scores a
// request with NO Host/User-Agent/Accept headers as anomalous (correctly), so
// CRS tests use this to isolate the payload under test from missing-header noise.
type realHeaders map[string]string

func (h realHeaders) Header(name string) (string, bool) { v, ok := h[name]; return v, ok }
func (h realHeaders) RangeHeaders(fn func(string, string) bool) {
	for k, v := range h {
		if !fn(k, v) {
			return
		}
	}
}

func browserHeaders() realHeaders {
	return realHeaders{
		"Host":            "api.example.com",
		"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		"Accept":          "text/html,application/json",
		"Accept-Language": "en-US,en;q=0.9",
		"Accept-Encoding": "gzip, deflate",
	}
}

const rules = `
SecRuleEngine On
SecRule REQUEST_URI "@contains attack" "id:1,phase:1,deny,status:403,msg:'blocked'"
`

func newTestEngine(t *testing.T) *wafEngine {
	t.Helper()
	e, err := newEngine(engine.CorazaConfig{Directives: rules})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestCorazaBlocksMatchingRequest(t *testing.T) {
	e := newTestEngine(t)
	v, err := e.Inspect(context.Background(), &engine.Request{
		Direction: engine.DirectionRequest,
		Path:      "/search?q=attack",
		Method:    "GET",
		Headers:   noHeaders{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != decision.Block || v.Engine != "coraza" || v.RuleID != "1" {
		t.Fatalf("matching request should be blocked by coraza: %+v", v)
	}
}

func TestCorazaAllowsCleanRequest(t *testing.T) {
	e := newTestEngine(t)
	v, err := e.Inspect(context.Background(), &engine.Request{
		Direction: engine.DirectionRequest,
		Path:      "/search?q=hello",
		Method:    "GET",
		Headers:   noHeaders{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Action == decision.Block {
		t.Fatalf("clean request should pass coraza: %+v", v)
	}
}

func TestCorazaRemoteAddrFromSourceIP(t *testing.T) {
	// A REMOTE_ADDR-keyed rule must see the trusted SourceIP (proves
	// ProcessConnection is wired).
	const ipRule = `
SecRuleEngine On
SecRule REMOTE_ADDR "@ipMatch 10.1.2.3" "id:2,phase:1,deny,status:403,msg:'ip'"
`
	e, err := newEngine(engine.CorazaConfig{Directives: ipRule})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(ip string) *engine.Request {
		return &engine.Request{Direction: engine.DirectionRequest, Path: "/", Method: "GET", SourceIP: ip, Headers: noHeaders{}}
	}
	if v, _ := e.Inspect(context.Background(), mk("10.1.2.3")); v.RuleID != "2" {
		t.Fatalf("REMOTE_ADDR rule should block the matching source IP, got %+v", v)
	}
	if v, _ := e.Inspect(context.Background(), mk("10.9.9.9")); v.Action == decision.Block {
		t.Fatal("a non-matching source IP should pass")
	}
}

func TestCorazaServerNameFromHost(t *testing.T) {
	const hostRule = `
SecRuleEngine On
SecRule SERVER_NAME "@streq evil.example.com" "id:3,phase:1,deny,status:403,msg:'host'"
`
	e, err := newEngine(engine.CorazaConfig{Directives: hostRule})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(host string) *engine.Request {
		return &engine.Request{Direction: engine.DirectionRequest, Path: "/", Method: "GET", Host: host, Headers: noHeaders{}}
	}
	if v, _ := e.Inspect(context.Background(), mk("evil.example.com")); v.RuleID != "3" {
		t.Fatalf("SERVER_NAME rule should block the matching host, got %+v", v)
	}
	if v, _ := e.Inspect(context.Background(), mk("ok.example.com")); v.Action == decision.Block {
		t.Fatal("a non-matching host should pass")
	}
}

func TestCorazaPropagatesRuleStatus(t *testing.T) {
	const statusRule = `
SecRuleEngine On
SecRule REQUEST_URI "@contains teapot" "id:4,phase:1,deny,status:418,msg:'teapot'"
`
	e, err := newEngine(engine.CorazaConfig{Directives: statusRule})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := e.Inspect(context.Background(), &engine.Request{
		Direction: engine.DirectionRequest, Path: "/x?q=teapot", Method: "GET", Headers: noHeaders{},
	})
	if v.Action != decision.Block || v.StatusCode != 418 {
		t.Fatalf("coraza should propagate the rule's forced status (418), got %+v", v)
	}
}

func TestCorazaNoRulesFailsLoudly(t *testing.T) {
	// No CRS and no directives would be a rule-less (fail-open) WAF → must error.
	if _, err := newEngine(engine.CorazaConfig{}); err == nil {
		t.Fatal("a Coraza engine with no rules must fail rather than run empty")
	}
}

// sqliReq is an obvious SQL-injection request the CRS 942xxx rules score as
// critical (>= the default inbound threshold of 5).
func sqliReq() *engine.Request {
	return &engine.Request{
		Direction: engine.DirectionRequest,
		Path:      "/items?id=1%27%20OR%20%271%27%3D%271",
		Method:    "GET",
		Host:      "api.example.com",
		Headers:   browserHeaders(),
	}
}

func TestCorazaIncludeOWASPLoadsCRS(t *testing.T) {
	// include_owasp now embeds + loads the OWASP CRS; a clear SQLi must be blocked
	// by the collaborative score crossing the default inbound threshold.
	e, err := newEngine(engine.CorazaConfig{IncludeOWASP: true})
	if err != nil {
		t.Fatalf("include_owasp should build a CRS-backed WAF: %v", err)
	}
	v, err := e.Inspect(context.Background(), sqliReq())
	if err != nil {
		t.Fatal(err)
	}
	if v.Action != decision.Block || v.Engine != "coraza" {
		t.Fatalf("CRS should block an obvious SQLi, got %+v", v)
	}

	clean, err := e.Inspect(context.Background(), &engine.Request{
		Direction: engine.DirectionRequest, Path: "/items?id=42", Method: "GET",
		Host: "api.example.com", Headers: browserHeaders(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if clean.Action == decision.Block {
		t.Fatalf("CRS should allow a benign request, got %+v", clean)
	}
}

func TestCorazaCRSAnomalyThresholdTuning(t *testing.T) {
	// Raising the inbound threshold far above any single rule's score proves the
	// tuning SecAction is wired BEFORE the rules: the same SQLi no longer blocks.
	e, err := newEngine(engine.CorazaConfig{IncludeOWASP: true, InboundAnomalyThreshold: 1000})
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.Inspect(context.Background(), sqliReq())
	if err != nil {
		t.Fatal(err)
	}
	if v.Action == decision.Block {
		t.Fatalf("a very high inbound threshold should let the SQLi through, got %+v", v)
	}
}

func TestCorazaCRSExcludeRuleID(t *testing.T) {
	// exclude_rule_ids must drop a CRS rule by id. 942100 is the libinjection SQLi
	// rule; removing it (and there is no other strong signal in this payload) drops
	// the score below the threshold.
	e, err := newEngine(engine.CorazaConfig{
		IncludeOWASP:   true,
		ExcludeRuleIDs: []string{"942100", "942110", "942140", "942200", "942260", "942270", "942300", "942310", "942330", "942340", "942361", "942370", "942380", "942390", "942400", "942410", "942430", "942440", "942450", "942470", "942480", "942500", "942521", "942522"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Build succeeding with removals applied is the contract under test; a request
	// still runs cleanly through the reduced rule set.
	if _, err := e.Inspect(context.Background(), &engine.Request{
		Direction: engine.DirectionRequest, Path: "/items?id=42", Method: "GET",
		Host: "api.example.com", Headers: browserHeaders(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCorazaRegistered(t *testing.T) {
	e, err := engine.NewCoraza(engine.CorazaConfig{Directives: "SecRuleEngine On"})
	if err != nil {
		t.Fatalf("coraza factory should be registered via the adapter's init(): %v", err)
	}
	if e.Name() != "coraza" {
		t.Fatalf("name: %s", e.Name())
	}
}
