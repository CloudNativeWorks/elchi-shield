package policy

import (
	"slices"
	"sync"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

// CompiledPolicy is the hot-path representation of a fully-resolved policy. It is
// immutable and built during the cold path (config compile); the hot path only
// reads it. Phase 2 adds the matchers/index that select which CompiledPolicy
// applies to a request; this type holds the per-policy behavior the pipeline
// executor and stages consult.
//
// It exposes semantic helpers (Blocking, FailOpen, ...) so consumers such as the
// pipeline executor need not import the config enum constants.
type CompiledPolicy struct {
	ID                   string
	Mode                 config.Mode
	FailMode             config.FailMode
	InspectRequestBody   bool
	InspectResponseBody  bool
	MaxRequestBodyBytes  int64
	MaxResponseBodyBytes int64
	Timeout              time.Duration
	SamplingRate         float64
	AnomalyThreshold     int
	Checks               CompiledChecks
	Engines              *engine.Set
	// RequestOrder/ResponseOrder are the per-policy inspector stage orders (nil
	// means use the default canonical order). They are plain names so policy
	// does not import the pipeline/stages packages.
	RequestOrder  []string
	ResponseOrder []string
	skipChecks    []string

	// compiled caches the per-policy compiled pipelines (an opaque type owned by
	// the stages package) so they are built once, lazily, on first use and then
	// reused. Storing them here (not in stages) keeps the build cycle-free and
	// ties their lifetime to the snapshot's policy (GC'd together).
	once        sync.Once
	compiled    any
	compiledErr error
}

// Compiled returns the policy's lazily-built compiled artifact, constructing it
// once via build on first call. The artifact type is opaque to this package
// (the caller type-asserts it); this is how per-policy pipelines attach to a
// policy without an import cycle.
func (p *CompiledPolicy) Compiled(build func() (any, error)) (any, error) {
	if p == nil {
		return nil, nil
	}
	p.once.Do(func() { p.compiled, p.compiledErr = build() })
	return p.compiled, p.compiledErr
}

// CompiledChecks is the hot-path form of a policy's built-in checks, consumed by
// the native FastPreChecks and BodyChecks stages. Header-name sets are kept as
// slices (small, cache-friendly) and compared case-insensitively by the stages.
type CompiledChecks struct {
	ForbiddenHeaders    []string
	RequiredHeaders     []string
	MaxHeaderValueBytes int64
	EnforceValidHost    bool
	RequireJSON         bool
	DetectSensitiveData bool
	DLP                 *CompiledDLP
}

// CompiledDLP is the hot-path form of the DLP config: which directions it runs
// on and the per-kind block/redact sets.
type CompiledDLP struct {
	OnRequest  bool
	OnResponse bool
	Block      map[string]struct{}
	Redact     map[string]struct{}
}

// compileChecks flattens config.Checks into the hot-path CompiledChecks.
func compileChecks(c config.Checks) CompiledChecks {
	out := CompiledChecks{}
	if c.Headers != nil {
		out.ForbiddenHeaders = slices.Clone(c.Headers.Forbidden)
		out.RequiredHeaders = slices.Clone(c.Headers.Required)
		out.MaxHeaderValueBytes = c.Headers.MaxHeaderValueBytes
		out.EnforceValidHost = c.Headers.EnforceValidHost
	}
	if c.Body != nil {
		out.RequireJSON = c.Body.RequireJSON
		out.DetectSensitiveData = c.Body.DetectSensitiveData
		if d := c.Body.DLP; d != nil {
			out.DLP = compileDLP(d)
		}
	}
	return out
}

// compileDLP flattens a config.DLPSpec into the hot-path CompiledDLP.
func compileDLP(d *config.DLPSpec) *CompiledDLP {
	cd := &CompiledDLP{
		OnResponse: d.Direction == "" || d.Direction == "response" || d.Direction == "both",
		OnRequest:  d.Direction == "request" || d.Direction == "both",
		Block:      make(map[string]struct{}, len(d.Block)),
		Redact:     make(map[string]struct{}, len(d.Redact)),
	}
	for _, k := range d.Block {
		cd.Block[k] = struct{}{}
	}
	for _, k := range d.Redact {
		cd.Redact[k] = struct{}{}
	}
	return cd
}

// FromResolved builds a CompiledPolicy from a fully-resolved config policy. The
// id should uniquely identify the policy's scope (e.g. host[/listener]/route)
// for attribution in decisions and audit events.
func FromResolved(id string, r config.ResolvedPolicy) *CompiledPolicy {
	checks := compileChecks(r.Checks)
	// The policy-level MaxHeaderBytes (default 8 KiB) is the effective per-header
	// value cap when a route's checks don't set a tighter one, so the default
	// actually protects rather than being inert config.
	if checks.MaxHeaderValueBytes == 0 && r.MaxHeaderBytes > 0 {
		checks.MaxHeaderValueBytes = r.MaxHeaderBytes
	}
	return &CompiledPolicy{
		ID:                   id,
		Mode:                 r.Mode,
		FailMode:             r.FailMode,
		InspectRequestBody:   r.InspectRequestBody,
		InspectResponseBody:  r.InspectResponseBody,
		MaxRequestBodyBytes:  r.MaxRequestBodyBytes,
		MaxResponseBodyBytes: r.MaxResponseBodyBytes,
		Timeout:              r.Timeout,
		SamplingRate:         r.SamplingRate,
		AnomalyThreshold:     r.AnomalyThreshold,
		Checks:               checks,
		RequestOrder:         slices.Clone(r.RequestOrder),
		ResponseOrder:        slices.Clone(r.ResponseOrder),
		skipChecks:           slices.Clone(r.SkipChecks),
	}
}

// DenyAll returns a synthetic blocking policy used as the default posture when
// no configured policy matches and the operator chose a deny-by-default stance.
// It blocks and fails closed so neither a match-miss nor an error lets traffic
// through.
func DenyAll() *CompiledPolicy {
	return &CompiledPolicy{ID: "__deny_all__", Mode: config.ModeBlock, FailMode: config.FailClose}
}

// Blocking reports whether the policy enforces block decisions. In detect/shadow
// /off modes a would-block is recorded but the request is allowed.
func (p *CompiledPolicy) Blocking() bool { return p.Mode == config.ModeBlock }

// Enforcing reports whether the policy evaluates checks at all (everything
// except mode off).
func (p *CompiledPolicy) Enforcing() bool { return p.Mode != config.ModeOff }

// NeedsResponseInspection reports whether this policy inspects the HTTP response
// (response-body checks, DLP on the response, or a response-inspecting engine
// like Coraza). When false, the server tells Envoy to SKIP the response phase,
// eliminating a wasted ext_proc round-trip per request. Conservative by
// construction: anything that could touch the response keeps the phase enabled.
func (p *CompiledPolicy) NeedsResponseInspection() bool {
	if p == nil || !p.Enforcing() {
		return false
	}
	if p.InspectResponseBody {
		return true
	}
	if dlp := p.Checks.DLP; dlp != nil && dlp.OnResponse {
		return true
	}
	return p.Engines.InspectsResponse()
}

// Shadowing reports whether the policy is in shadow mode.
func (p *CompiledPolicy) Shadowing() bool { return p.Mode == config.ModeShadow }

// FailOpen reports whether the policy allows traffic on engine error/timeout.
func (p *CompiledPolicy) FailOpen() bool { return p.FailMode == config.FailOpen }

// SkipsCheck reports whether the named check is exempted by this policy.
func (p *CompiledPolicy) SkipsCheck(name string) bool {
	return slices.Contains(p.skipChecks, name)
}
