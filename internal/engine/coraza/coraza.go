// Package coraza adapts the Coraza WAF to the SecurityEngine interface. It is
// always compiled into the binary. On init it registers itself with the engine
// package (triggered by a blank import in cmd/elchi-shield) so a policy that
// configures `engines.coraza` is served by this adapter.
package coraza

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
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
	wafCfg := czrules.NewWAFConfig()
	var b strings.Builder

	if cfg.IncludeOWASP {
		// The OWASP Core Rule Set is embedded in the binary via the
		// coraza-coreruleset module (an io/fs.FS holding @coraza.conf-recommended,
		// @crs-setup.conf.example, and @owasp_crs/*). Point Coraza at that RootFS so
		// the Include directives resolve from memory — no files to ship.
		wafCfg = wafCfg.WithRootFS(coreruleset.FS)
		// Recommended Coraza base (SecRuleEngine On, body access, limits) then the
		// CRS setup. crs-setup.conf.example leaves paranoia/thresholds commented, so
		// CRS uses its built-in defaults (PL1, inbound 5, outbound 4) unless we
		// override them below — BEFORE the rules load, so REQUEST-901-INITIALIZATION
		// sees them already set and skips its defaults.
		b.WriteString("Include @coraza.conf-recommended\n")
		// @coraza.conf-recommended ships SecRuleEngine DetectionOnly (a safe default
		// for a standalone WAF). Force it On so the CRS blocking-evaluation rule
		// actually raises an interruption — shield expresses detect/shadow/off via
		// the policy mode (the executor maps a Block verdict accordingly), so the
		// engine itself must always be enforcing.
		b.WriteString("SecRuleEngine On\n")
		b.WriteString("Include @crs-setup.conf.example\n")
		writeCRSTuning(&b, cfg)
		b.WriteString("Include @owasp_crs/*.conf\n")
	} else if cfg.Directives == "" {
		// No CRS and no explicit rules would be a fail-open WAF; refuse it. (The
		// config layer already enforces this, but defend the engine boundary too.
		// directives_file is folded into Directives by the builder before we see it.)
		return nil, errors.New("coraza: no rules configured (set directives, directives_file, or include_owasp)")
	}

	// User directives (inline + directives_file, already concatenated by the
	// builder) run AFTER the CRS so an operator can tune/override it. Rule
	// removals run last so they can drop CRS rules by id.
	if cfg.Directives != "" {
		b.WriteString(cfg.Directives)
		b.WriteString("\n")
	}
	for _, id := range cfg.ExcludeRuleIDs {
		b.WriteString("SecRuleRemoveById ")
		b.WriteString(id)
		b.WriteString("\n")
	}

	waf, err := czrules.NewWAF(wafCfg.WithDirectives(b.String()))
	if err != nil {
		return nil, fmt.Errorf("coraza: build waf: %w", err)
	}
	e := &wafEngine{}
	e.waf.Store(&wafHolder{waf: waf})
	return e, nil
}

// writeCRSTuning emits a single phase-1 SecAction that overrides the CRS
// collaborative-scoring knobs the operator set (a zero value leaves the CRS
// default in place). It must be included after @crs-setup but before the rules.
func writeCRSTuning(b *strings.Builder, cfg engine.CorazaConfig) {
	var sv []string
	if cfg.ParanoiaLevel > 0 {
		sv = append(sv, fmt.Sprintf("setvar:tx.blocking_paranoia_level=%d", cfg.ParanoiaLevel))
	}
	// Detection PL defaults to the blocking PL (CRS convention); only emit it when
	// the operator wants a higher detection level than they block on.
	if dpl := cfg.DetectionParanoiaLevel; dpl > 0 {
		sv = append(sv, fmt.Sprintf("setvar:tx.detection_paranoia_level=%d", dpl))
	} else if cfg.ParanoiaLevel > 0 {
		sv = append(sv, fmt.Sprintf("setvar:tx.detection_paranoia_level=%d", cfg.ParanoiaLevel))
	}
	if cfg.InboundAnomalyThreshold > 0 {
		sv = append(sv, fmt.Sprintf("setvar:tx.inbound_anomaly_score_threshold=%d", cfg.InboundAnomalyThreshold))
	}
	if cfg.OutboundAnomalyThreshold > 0 {
		sv = append(sv, fmt.Sprintf("setvar:tx.outbound_anomaly_score_threshold=%d", cfg.OutboundAnomalyThreshold))
	}
	if len(sv) == 0 {
		return
	}
	b.WriteString(`SecAction "id:900000,phase:1,nolog,pass,t:none,`)
	b.WriteString(strings.Join(sv, ","))
	b.WriteString("\"\n")
}

func (*wafEngine) Name() string       { return "coraza" }
func (*wafEngine) RequiresBody() bool { return true }

// InspectsResponse implements engine.ResponseInspector: Coraza runs response-phase
// rules (phase 3/4), so its policies must keep the ext_proc response phase enabled.
func (*wafEngine) InspectsResponse() bool { return true }

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
	// ProcessLogging runs the phase-5 (logging) rules and finalizes the audit
	// accounting; Coraza's documented teardown is ProcessLogging then Close.
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	if req.Direction == engine.DirectionResponse {
		return e.inspectResponse(tx, req)
	}
	return e.inspectRequest(tx, req)
}

func (e *wafEngine) inspectRequest(tx cztypes.Transaction, req *engine.Request) (decision.Verdict, error) {
	// ProcessConnection populates REMOTE_ADDR from the trusted, pre-derived client
	// IP so IP-keyed rules (and the audit log) evaluate against the real source
	// rather than an empty address. ProcessURI must precede the header phase.
	tx.ProcessConnection(req.SourceIP, 0, "", 0)
	tx.ProcessURI(req.Path, req.Method, "HTTP/1.1")
	req.Headers.RangeHeaders(func(name, value string) bool {
		tx.AddRequestHeader(name, value)
		return true
	})
	// SetServerName must run before ProcessRequestHeaders for SERVER_NAME-keyed
	// rules to see the host in phase 1.
	tx.SetServerName(req.Host)
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
	// REMOTE_ADDR / SERVER_NAME are still wanted on the response path (IP- and
	// host-keyed response rules, audit log). Request-phase variables are absent by
	// design — request and response are separate pipelines/transactions here.
	tx.ProcessConnection(req.SourceIP, 0, "", 0)
	tx.SetServerName(req.Host)
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
	// Honor the status the WAF rule forces (e.g. a custom status:N or
	// SecDefaultAction); an out-of-range/zero value falls back to the default
	// block status (403) downstream.
	status := it.Status
	if status < 100 || status > 599 {
		status = 0
	}
	return decision.Verdict{
		Action:     decision.Block,
		Reason:     fmt.Sprintf("coraza rule %d (%s)", it.RuleID, it.Action),
		RuleID:     strconv.Itoa(it.RuleID),
		Engine:     "coraza",
		Severity:   decision.SeverityHigh,
		StatusCode: status,
	}
}
