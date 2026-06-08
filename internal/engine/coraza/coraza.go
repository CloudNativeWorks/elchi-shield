//go:build coraza

// Package coraza adapts the Coraza WAF to the SecurityEngine interface. It is
// compiled only when the `coraza` build tag is set, keeping the heavy dependency
// out of the default binary. On init it registers itself with the engine package
// so a policy that configures `engines.coraza` is served by this adapter.
//
// Build with: go build -tags coraza ./cmd/elchi-shield
package coraza

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	czrules "github.com/corazawaf/coraza/v3"
	cztypes "github.com/corazawaf/coraza/v3/types"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

func init() {
	engine.RegisterCoraza(func(cfg engine.CorazaConfig) (engine.SecurityEngine, error) {
		return newEngine(cfg)
	})
}

// wafHolder boxes the compiled WAF so it can live in an atomic.Pointer (the WAF
// is an interface; atomic.Pointer needs a concrete element type).
type wafHolder struct{ waf czrules.WAF }

// wafEngine wraps a compiled Coraza WAF. The WAF is built once at config-compile
// time; each Inspect creates and closes a short-lived transaction. The reference
// is held in an atomic.Pointer so Close (on a retired snapshot) can never race a
// concurrent Inspect reading it — a defense beyond the retirement grace period.
type wafEngine struct {
	waf atomic.Pointer[wafHolder]
}

func newEngine(cfg engine.CorazaConfig) (*wafEngine, error) {
	// include_owasp is not supported by this adapter (the OWASP CRS is not
	// bundled). Fail loudly rather than silently running a WAF with no rules,
	// which would be a fail-open security control.
	if cfg.IncludeOWASP {
		return nil, errors.New("coraza: include_owasp is not supported by this build; provide directives or directives_file with explicit rules")
	}
	var b strings.Builder
	if cfg.Directives == "" {
		b.WriteString("SecRuleEngine On")
	} else {
		b.WriteString(cfg.Directives)
	}
	for _, id := range cfg.ExcludeRuleIDs {
		b.WriteString("\nSecRuleRemoveById ")
		b.WriteString(id)
	}
	waf, err := czrules.NewWAF(czrules.NewWAFConfig().WithDirectives(b.String()))
	if err != nil {
		return nil, fmt.Errorf("coraza: build waf: %w", err)
	}
	e := &wafEngine{}
	e.waf.Store(&wafHolder{waf: waf})
	return e, nil
}

func (*wafEngine) Name() string       { return "coraza" }
func (*wafEngine) RequiresBody() bool { return true }

// Close drops the reference to the compiled WAF so its rule set (which can be
// large) becomes eligible for GC and any later Inspect fails fast rather than
// running with stale state. The atomic store makes it safe even if it races a
// concurrent Inspect (which would simply observe the engine as closed).
func (e *wafEngine) Close() error {
	e.waf.Store(nil)
	return nil
}

// errClosed is returned if Inspect runs after Close (a misuse the retirement
// grace period prevents in practice).
var errClosed = errors.New("coraza: engine closed")

// Inspect runs the request or response phases against a fresh Coraza transaction
// and translates any interruption into a block verdict.
func (e *wafEngine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	h := e.waf.Load()
	if h == nil {
		return decision.Verdict{}, errClosed
	}
	tx := h.waf.NewTransaction()
	defer func() { _ = tx.Close() }()

	if req.Direction == engine.DirectionResponse {
		return e.inspectResponse(tx, req)
	}
	return e.inspectRequest(tx, req)
}

func (e *wafEngine) inspectRequest(tx cztypes.Transaction, req *engine.Request) (decision.Verdict, error) {
	req.Headers.RangeHeaders(func(name, value string) bool {
		tx.AddRequestHeader(name, value)
		return true
	})
	tx.ProcessURI(req.Path, req.Method, "HTTP/1.1")
	if it := tx.ProcessRequestHeaders(); it != nil {
		return verdict(it), nil
	}
	if len(req.Body) > 0 {
		// Errors are propagated (not swallowed) so the WAF stage applies the
		// policy fail posture instead of treating a body-write failure as clean.
		it, _, err := tx.WriteRequestBody(req.Body)
		if err != nil {
			return decision.Verdict{}, fmt.Errorf("coraza: write request body: %w", err)
		}
		if it != nil {
			return verdict(it), nil
		}
	}
	it, err := tx.ProcessRequestBody()
	if err != nil {
		return decision.Verdict{}, fmt.Errorf("coraza: process request body: %w", err)
	}
	if it != nil {
		return verdict(it), nil
	}
	return decision.Verdict{}, nil
}

func (e *wafEngine) inspectResponse(tx cztypes.Transaction, req *engine.Request) (decision.Verdict, error) {
	req.Headers.RangeHeaders(func(name, value string) bool {
		tx.AddResponseHeader(name, value)
		return true
	})
	// Use the real response status so response-phase rules keyed on RESPONSE_STATUS
	// (e.g. CRS data-leakage rules that fire on 5xx) evaluate correctly, instead of
	// a hardcoded 200.
	status := 200
	if v, ok := req.Headers.Header(":status"); ok {
		if code, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && code >= 100 && code <= 599 {
			status = code
		}
	}
	if it := tx.ProcessResponseHeaders(status, "HTTP/1.1"); it != nil {
		return verdict(it), nil
	}
	if len(req.Body) > 0 {
		it, _, err := tx.WriteResponseBody(req.Body)
		if err != nil {
			return decision.Verdict{}, fmt.Errorf("coraza: write response body: %w", err)
		}
		if it != nil {
			return verdict(it), nil
		}
	}
	it, err := tx.ProcessResponseBody()
	if err != nil {
		return decision.Verdict{}, fmt.Errorf("coraza: process response body: %w", err)
	}
	if it != nil {
		return verdict(it), nil
	}
	return decision.Verdict{}, nil
}

func verdict(it *cztypes.Interruption) decision.Verdict {
	return decision.Verdict{
		Action:   decision.Block,
		Reason:   fmt.Sprintf("coraza rule %d (%s)", it.RuleID, it.Action),
		RuleID:   strconv.Itoa(it.RuleID),
		Engine:   "coraza",
		Severity: decision.SeverityHigh,
	}
}
