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
