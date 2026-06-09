// Package stages provides the concrete filter-chain stages that implement
// elchi-shield's request/response inspection. They are composed into the default
// request and response pipelines (see build.go). Each stage is small, stateless
// (its only state is injected deps), direction-aware via tx.Direction, and keeps
// all per-request data on the pipeline.Transaction.
package stages

import (
	"context"
	"net/netip"
	"net/url"
	"path"
	"strings"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/matcher"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/policy"
)

// Built-in check names, usable in a policy's skip_checks list.
const (
	CheckHost             = "host"
	CheckForbiddenHeaders = "forbidden_headers"
	CheckRequiredHeaders  = "required_headers"
	CheckOversizedHeaders = "oversized_headers"
	CheckJSON             = "json"
	CheckSensitiveData    = "sensitive_data"
)

const (
	builtinEngine    = "builtin"
	engineDLP        = "dlp"         // sensitive-data detection / DLP block
	engineBodySize   = "body_size"   // truncation guard (over-limit body)
	engineBodyDecode = "body_decode" // undecodable / decode-budget block
)

// contextInit derives request attributes (host, path, method, content-type) from
// the (pseudo-)headers if the transport layer did not already set them. It is
// idempotent so the ext_proc server may pre-fill fields. trustedHops is the
// number of trusted reverse proxies in front of this Envoy, used to pick the
// real client IP from X-Forwarded-For.
type contextInit struct{ trustedHops int }

// ContextInit returns the context-initialization stage. trustedHops controls how
// the client IP is read from X-Forwarded-For (0 = the rightmost/immediate hop,
// the secure default; N = the Nth hop in from the right).
func ContextInit(trustedHops int) pipeline.Stage { return contextInit{trustedHops: trustedHops} }

func (contextInit) Name() string          { return "context_init" }
func (contextInit) Phase() pipeline.Phase { return pipeline.PhasePreCheck }

func (ci contextInit) Process(_ context.Context, tx *pipeline.Transaction) pipeline.StageResult {
	if tx.ContentType == "" {
		if v, ok := tx.Header("content-type"); ok {
			tx.ContentType = v
		}
	}
	if tx.Direction == pipeline.DirectionResponse {
		return pipeline.Continue()
	}
	if tx.Host == "" {
		if v, ok := tx.Header(":authority"); ok {
			tx.Host = v
		} else if v, ok := tx.Header("host"); ok {
			tx.Host = v
		}
	}
	if tx.Path == "" {
		if v, ok := tx.Header(":path"); ok {
			tx.Path = v
		}
	}
	if tx.Method == "" {
		if v, ok := tx.Header(":method"); ok {
			tx.Method = v
		}
	}
	if tx.SourceIP == "" {
		tx.SourceIP = clientIP(tx, ci.trustedHops)
	}
	return pipeline.Continue()
}

// clientIP derives the originating client IP and returns it in canonical form.
// It is the single source of truth for the client IP (engines read tx.SourceIP,
// not raw headers).
//
// SECURITY: X-Forwarded-For is a list — each proxy APPENDS the address it
// received the connection from, so the rightmost entries are added by trusted
// infrastructure and the leftmost is attacker-controlled. With trustedHops=N
// (the number of trusted proxies in front of this Envoy) we take the entry N
// positions in from the right; the secure default (0) is the rightmost hop, the
// address Envoy itself appended via use_remote_address. Reading the leftmost
// token (the old behavior) lets a client spoof its source IP by sending its own
// X-Forwarded-For header, bypassing every source-IP control.
func clientIP(tx *pipeline.Transaction, trustedHops int) string {
	if v, ok := tx.Header("x-forwarded-for"); ok && v != "" {
		toks := strings.Split(v, ",")
		idx := len(toks) - 1 - trustedHops
		if idx < 0 {
			idx = 0
		}
		if ip := canonIP(strings.TrimSpace(toks[idx])); ip != "" {
			return ip
		}
	}
	if v, ok := tx.Header("x-real-ip"); ok {
		if ip := canonIP(strings.TrimSpace(v)); ip != "" {
			return ip
		}
	}
	return ""
}

// canonIP returns the canonical string form of an IP: it tolerates an ip:port
// form, strips an IPv6 zone, and UNMAPS an IPv4-in-IPv6 address (::ffff:1.2.3.4 →
// 1.2.3.4) so a 4-in-6 source can't dodge an IPv4 deny/allow rule. Returns ""
// for anything that isn't a valid IP.
func canonIP(s string) string {
	if s == "" {
		return ""
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().WithZone("").String()
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return a.Unmap().WithZone("").String()
}

// policyResolve looks up the effective policy from the pinned snapshot and
// assigns it to tx. On no match it leaves tx.Policy nil for EarlyDecision to
// apply the default posture.
type policyResolve struct{}

// PolicyResolve returns the policy-resolution stage.
func PolicyResolve() pipeline.Stage { return policyResolve{} }

func (policyResolve) Name() string          { return "policy_resolve" }
func (policyResolve) Phase() pipeline.Phase { return pipeline.PhasePreCheck }

func (policyResolve) Process(_ context.Context, tx *pipeline.Transaction) pipeline.StageResult {
	if tx.Snapshot == nil {
		return pipeline.Continue()
	}
	tx.Policy = tx.Snapshot.Resolver().Resolve(&policy.Input{
		ListenerID: tx.ListenerID,
		Host:       tx.Host,
		// Match on the path component only; an attacker must not dodge an exact/
		// regex path policy by appending a query string.
		Path:        matchPath(tx.Path),
		Method:      tx.Method,
		ContentType: tx.ContentType,
		Headers:     tx,
	})
	return pipeline.Continue()
}

// NormalizePath exposes the route-matching path normalization for introspection
// (the /policyz explainer) so it reports the same resolution the request path uses.
func NormalizePath(p string) string { return matchPath(p) }

// matchPath returns the normalized path used for route matching: the query is
// stripped, the path is percent-decoded once, and dot-segments / duplicate
// slashes are collapsed. This prevents trivial evasion of an exact/prefix/regex
// path policy via encodings or traversal (e.g. "/%61dmin", "/foo/../admin",
// "//admin") that a downstream server would normalize to the same resource.
// The original tx.Path is preserved for audit/logging.
func matchPath(raw string) string {
	p := raw
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	// Percent-decode once (best effort: keep the raw form if it is malformed).
	if dec, err := url.PathUnescape(p); err == nil {
		p = dec
	}
	if p == "" {
		return raw
	}
	// Collapse "." / ".." / "//". path.Clean drops a trailing slash, so restore it
	// to keep prefix semantics (a "/v1/" prefix should still match "/v1/").
	cleaned := path.Clean(p)
	if cleaned == "." {
		cleaned = "/"
	}
	if strings.HasSuffix(p, "/") && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}
	return cleaned
}

// fastPreChecks runs the cheap, body-free header checks. It short-circuits on the
// first violation; the executor maps the deny through the policy mode so
// detect/shadow only record.
type fastPreChecks struct{}

// FastPreChecks returns the fast pre-checks stage.
func FastPreChecks() pipeline.Stage { return fastPreChecks{} }

func (fastPreChecks) Name() string          { return config.StageFastPreChecks }
func (fastPreChecks) Phase() pipeline.Phase { return pipeline.PhasePreCheck }

func (fastPreChecks) Process(_ context.Context, tx *pipeline.Transaction) pipeline.StageResult {
	p := tx.Policy
	if p == nil || !p.Enforcing() {
		return pipeline.Continue()
	}
	// The checks.headers rules (host, forbidden, required, oversized) describe the
	// REQUEST: a request-required header is not present on the response, so running
	// them on the response phase would wrongly block legitimate responses. Response
	// inspection is the body checks + engines, not these request header checks.
	if tx.Direction != pipeline.DirectionRequest {
		return pipeline.Continue()
	}
	c := p.Checks

	// Host checks.
	if !p.SkipsCheck(CheckHost) {
		// A disagreeing :authority and Host is a host-smuggling signal: the WAF
		// would resolve policy on one while the backend routes on the other. Reject
		// it regardless of EnforceValidHost.
		if auth, ok1 := tx.Header(":authority"); ok1 {
			if host, ok2 := tx.Header("host"); ok2 &&
				!strings.EqualFold(matcher.NormalizeHost(auth), matcher.NormalizeHost(host)) {
				return deny(tx, "header.host_mismatch", "host and :authority disagree", decision.SeverityHigh)
			}
		}
		if c.EnforceValidHost && strings.TrimSpace(tx.Host) == "" {
			return deny(tx, "header.invalid_host", "missing or empty host", decision.SeverityHigh)
		}
	}

	// Forbidden headers.
	if !p.SkipsCheck(CheckForbiddenHeaders) {
		for _, name := range c.ForbiddenHeaders {
			if _, ok := tx.Header(name); ok {
				return deny(tx, "header.forbidden", "forbidden header present: "+name, decision.SeverityHigh)
			}
		}
	}

	// Required headers.
	if !p.SkipsCheck(CheckRequiredHeaders) {
		for _, name := range c.RequiredHeaders {
			if _, ok := tx.Header(name); !ok {
				return deny(tx, "header.required_missing", "required header missing: "+name, decision.SeverityMedium)
			}
		}
	}

	// Oversized header value.
	if c.MaxHeaderValueBytes > 0 && !p.SkipsCheck(CheckOversizedHeaders) {
		for _, h := range tx.Headers {
			if int64(len(h.Value)) > c.MaxHeaderValueBytes {
				return deny(tx, "header.oversized", "header value too large: "+h.Name, decision.SeverityMedium)
			}
		}
	}

	return pipeline.Continue()
}

// earlyDecision short-circuits the no-inspection cases as early as possible: no
// matching policy (default posture) and mode off (skip everything).
type earlyDecision struct {
	defaultAllow bool
	denyAll      *policy.CompiledPolicy
}

// EarlyDecision returns the early-decision stage. defaultAllow chooses the
// posture when no policy matches: allow (fail-open) or deny.
func EarlyDecision(defaultAllow bool) pipeline.Stage {
	return &earlyDecision{defaultAllow: defaultAllow, denyAll: policy.DenyAll()}
}

func (*earlyDecision) Name() string          { return "early_decision" }
func (*earlyDecision) Phase() pipeline.Phase { return pipeline.PhasePreCheck }

func (e *earlyDecision) Process(_ context.Context, tx *pipeline.Transaction) pipeline.StageResult {
	if tx.Policy == nil {
		if e.defaultAllow {
			return pipeline.SkipRemaining()
		}
		// Default-deny: assign a blocking policy so the executor enforces it.
		tx.Policy = e.denyAll
		d := decision.Decision{Action: decision.Block, Reason: "default_deny_no_policy", StatusCode: decision.DefaultBlockStatus}
		return pipeline.Deny(&d)
	}
	if !tx.Policy.Enforcing() { // mode off
		return pipeline.SkipRemaining()
	}
	return pipeline.Continue()
}

// deny builds a block decision attributed to the built-in checks and returns a
// Deny result.
func deny(tx *pipeline.Transaction, ruleID, reason string, sev decision.Severity) pipeline.StageResult {
	return denyEngine(tx, builtinEngine, ruleID, reason, sev)
}

// denyEngine is deny with an explicit engine/source label, so structural body
// checks (DLP, truncation, decode) are attributed to their own findings_total
// bucket instead of collapsing into "builtin".
func denyEngine(tx *pipeline.Transaction, engine, ruleID, reason string, sev decision.Severity) pipeline.StageResult {
	d := decision.Decision{
		Action:     decision.Block,
		Reason:     reason,
		RuleID:     ruleID,
		PolicyID:   tx.PolicyID(),
		Engine:     engine,
		Severity:   sev,
		StatusCode: decision.DefaultBlockStatus,
	}
	return pipeline.Deny(&d)
}
