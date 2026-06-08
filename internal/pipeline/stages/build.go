package stages

import (
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
)

// Deps are the dependencies injected into the default pipelines. The zero value
// is usable: fail-open default posture, no sensitive-data detector. Engines are
// per-policy (compiled into the snapshot), not injected here.
type Deps struct {
	// DefaultAllow chooses the posture when no policy matches a request: allow
	// (fail-open, the safe default) when true, deny when false.
	DefaultAllow bool
	// Detector enables sensitive-data detection in bodies when non-nil.
	Detector SensitiveDataDetector
	// Observer receives per-stage metrics/latency (nil → no-op).
	Observer pipeline.Observer
	// TrustedHops is the number of trusted reverse proxies in front of Envoy; it
	// controls how the client IP is read from X-Forwarded-For (0 = the secure
	// rightmost/immediate hop).
	TrustedHops int
}

// DefaultRequestPipeline assembles the standard request filter chain in the
// canonical cheap→expensive order: context init → policy resolve → fast
// pre-checks → early decision → body gate → body checks → WAF engine.
// Final-decision aggregation is performed by the executor and the terminal
// audit/metrics are emitted at the ext_proc boundary (not as stages, because a
// short-circuited block never reaches a trailing stage).
func DefaultRequestPipeline(d Deps) (*pipeline.Pipeline, error) {
	return pipeline.NewBuilder("request").
		WithObserver(d.Observer).
		Add(
			ContextInit(0),
			PolicyResolve(),
			FastPreChecks(),
			EarlyDecision(d.DefaultAllow),
			BodyGate(),
			BodyChecks(d.Detector),
			WAFEngine(),
		).
		Build()
}

// DefaultResponsePipeline assembles the response filter chain. It reuses the
// same direction-aware stages; the pinned request policy is read from tx. There
// is no policy-resolution stage here — the response is governed by the request's
// policy.
func DefaultResponsePipeline(d Deps) (*pipeline.Pipeline, error) {
	return pipeline.NewBuilder("response").
		WithObserver(d.Observer).
		Add(
			ContextInit(0),
			FastPreChecks(),
			BodyGate(),
			BodyChecks(d.Detector),
			WAFEngine(),
		).
		Build()
}

// The ext_proc server does NOT use the full pipelines above. Because the
// effective policy (and thus its stage order) is only known after policy
// resolution, the server runs a fixed prelude (Catalog.RequestPrelude /
// ResponsePrelude) and then the per-policy inspect pipelines built by
// Catalog.BuildPolicyPipelines. See catalog.go.
