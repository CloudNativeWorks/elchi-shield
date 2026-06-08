package config

import (
	"slices"
	"time"
)

// ResolvedPolicy is a fully-concrete policy with every field populated. It is
// produced by resolving a chain of sparse PolicySpec values (route → domain →
// file defaults → built-in defaults). Downstream packages compile this into the
// hot-path representation; nothing on the hot path uses pointers.
type ResolvedPolicy struct {
	Mode                 Mode
	FailMode             FailMode
	InspectRequestBody   bool
	InspectResponseBody  bool
	MaxRequestBodyBytes  int64
	MaxResponseBodyBytes int64
	MaxHeaderBytes       int64
	Timeout              time.Duration
	LogLevel             string
	SamplingRate         float64
	SkipChecks           []string
	RequestOrder         []string // inspector order for requests (nil = default)
	ResponseOrder        []string // inspector order for responses (nil = default)
	Checks               Checks
	Engines              *EnginesSpec
}

// DefaultPolicy returns the built-in baseline used when nothing overrides a
// field. The defaults are deliberately conservative: block mode, fail-open so a
// WAF bug never blackholes traffic, no body inspection, and a tight timeout.
func DefaultPolicy() ResolvedPolicy {
	return ResolvedPolicy{
		Mode:                 ModeBlock,
		FailMode:             FailOpen,
		InspectRequestBody:   false,
		InspectResponseBody:  false,
		MaxRequestBodyBytes:  1 << 20, // 1 MiB
		MaxResponseBodyBytes: 0,       // 0 = do not inspect
		MaxHeaderBytes:       8 << 10, // 8 KiB per header value
		Timeout:              50 * time.Millisecond,
		LogLevel:             "info",
		SamplingRate:         1.0,
	}
}

// Resolve folds the given specs onto base, in order, so that later specs win.
// Callers pass them least-specific first, e.g.:
//
//	Resolve(DefaultPolicy(), fileDefaults, domainPolicy, routePolicy)
//
// SkipChecks accumulates (union) across the chain rather than replacing, so a
// broader scope can exempt a check and a narrower scope can add more.
func Resolve(base ResolvedPolicy, specs ...PolicySpec) ResolvedPolicy {
	out := base
	skip := map[string]struct{}{}
	for _, c := range base.SkipChecks {
		skip[c] = struct{}{}
	}

	for _, s := range specs {
		if s.Mode != nil {
			out.Mode = *s.Mode
		}
		if s.FailMode != nil {
			out.FailMode = *s.FailMode
		}
		if s.InspectRequestBody != nil {
			out.InspectRequestBody = *s.InspectRequestBody
		}
		if s.InspectResponseBody != nil {
			out.InspectResponseBody = *s.InspectResponseBody
		}
		if s.MaxRequestBodyBytes != nil {
			out.MaxRequestBodyBytes = *s.MaxRequestBodyBytes
		}
		if s.MaxResponseBodyBytes != nil {
			out.MaxResponseBodyBytes = *s.MaxResponseBodyBytes
		}
		if s.MaxHeaderBytes != nil {
			out.MaxHeaderBytes = *s.MaxHeaderBytes
		}
		if s.Timeout != nil {
			out.Timeout = s.Timeout.AsDuration()
		}
		if s.LogLevel != nil {
			out.LogLevel = *s.LogLevel
		}
		if s.SamplingRate != nil {
			out.SamplingRate = *s.SamplingRate
		}
		for _, c := range s.SkipChecks {
			skip[c] = struct{}{}
		}
		// Pipeline ordering replaces wholesale per direction when set.
		if s.Pipeline != nil {
			if s.Pipeline.Request != nil {
				out.RequestOrder = s.Pipeline.Request
			}
			if s.Pipeline.Response != nil {
				out.ResponseOrder = s.Pipeline.Response
			}
		}
		// Checks merge by replacement of whichever sub-block is set.
		if s.Checks.Headers != nil {
			out.Checks.Headers = s.Checks.Headers
		}
		if s.Checks.Body != nil {
			out.Checks.Body = s.Checks.Body
		}
		// Engines replace wholesale when set (narrower scope wins).
		if s.Engines != nil {
			out.Engines = s.Engines
		}
	}

	if len(skip) > 0 {
		out.SkipChecks = out.SkipChecks[:0:0]
		for c := range skip {
			out.SkipChecks = append(out.SkipChecks, c)
		}
	}
	return out
}

// SkipsCheck reports whether the named check is exempted by this policy.
func (p ResolvedPolicy) SkipsCheck(name string) bool {
	return slices.Contains(p.SkipChecks, name)
}
