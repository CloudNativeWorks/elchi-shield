//go:build coraza

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

func TestCorazaIncludeOWASPFailsLoudly(t *testing.T) {
	// include_owasp is unsupported → must error, never silently run an empty WAF.
	if _, err := newEngine(engine.CorazaConfig{IncludeOWASP: true}); err == nil {
		t.Fatal("include_owasp:true must fail rather than run a rule-less WAF")
	}
}

func TestCorazaRegistered(t *testing.T) {
	e, err := engine.NewCoraza(engine.CorazaConfig{Directives: "SecRuleEngine On"})
	if err != nil {
		t.Fatalf("coraza factory should be registered under the build tag: %v", err)
	}
	if e.Name() != "coraza" {
		t.Fatalf("name: %s", e.Name())
	}
}
