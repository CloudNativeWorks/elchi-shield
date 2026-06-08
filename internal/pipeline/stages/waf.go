package stages

import (
	"context"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
)

// engineInspect is the shared inspection function a WAF stage runs against the
// policy's engine set (header-phase or body-phase subset).
type engineInspect func(*engine.Set, context.Context, *engine.Request) (decision.Verdict, error)

// wafEngine runs the body-phase engines (those that need the buffered body, e.g.
// Coraza). It runs in PhaseWAF, gated on by the body gate. A Block verdict
// short-circuits via Deny; an engine error triggers the policy fail posture.
type wafEngine struct{}

// WAFEngine returns the body-phase WAF-engine stage. With no body engines it is a
// no-op.
func WAFEngine() pipeline.Stage { return wafEngine{} }

func (wafEngine) Name() string          { return config.StageWAFEngine }
func (wafEngine) Phase() pipeline.Phase { return pipeline.PhaseWAF }

func (wafEngine) Process(ctx context.Context, tx *pipeline.Transaction) pipeline.StageResult {
	return runEngines(ctx, tx, (*engine.Set).InspectBodyPhase)
}

// wafHeaderEngine runs the header-phase engines (those that do not need the body,
// e.g. JWT) at header time, so a header-only policy never forces the body to be
// buffered. It runs in PhasePreCheck within the header pipeline.
type wafHeaderEngine struct{}

// WAFHeaderEngine returns the header-phase WAF-engine stage. With no header
// engines it is a no-op.
func WAFHeaderEngine() pipeline.Stage { return wafHeaderEngine{} }

// StageWAFHeaderEngine is the metrics/observer name for the header-phase WAF
// stage. It is not a config vocabulary word: a policy's order lists the single
// "waf_engine", which the catalog expands into header- and body-phase stages.
const StageWAFHeaderEngine = config.StageWAFEngine + "_headers"

func (wafHeaderEngine) Name() string          { return StageWAFHeaderEngine }
func (wafHeaderEngine) Phase() pipeline.Phase { return pipeline.PhasePreCheck }

func (wafHeaderEngine) Process(ctx context.Context, tx *pipeline.Transaction) pipeline.StageResult {
	return runEngines(ctx, tx, (*engine.Set).InspectHeaderPhase)
}

// runEngines builds the read-only engine request from tx and runs the given
// engine-set inspection (header- or body-phase subset), mapping the verdict to a
// stage result. A confirmed block wins even if another engine errored.
func runEngines(ctx context.Context, tx *pipeline.Transaction, inspect engineInspect) pipeline.StageResult {
	p := tx.Policy
	if p == nil || !p.Enforcing() || p.Engines.Len() == 0 {
		return pipeline.Continue()
	}

	// Fill the pooled engine request (every field) to avoid a per-stage alloc.
	req := tx.EngineRequest()
	*req = engine.Request{
		Direction:   engineDirection(tx.Direction),
		Host:        tx.Host,
		Path:        tx.Path,
		Method:      tx.Method,
		ContentType: tx.ContentType,
		SourceIP:    tx.SourceIP,
		Body:        tx.Body(),
		Headers:     tx,
	}
	v, err := inspect(p.Engines, ctx, req)
	if v.Action == decision.Block {
		d := decision.Blocked(tx.PolicyID(), v)
		return pipeline.Deny(&d)
	}
	if err != nil {
		return pipeline.Fail(err)
	}
	return pipeline.Continue()
}

// engineDirection maps a pipeline direction to the engine's.
func engineDirection(d pipeline.Direction) engine.Direction {
	if d == pipeline.DirectionResponse {
		return engine.DirectionResponse
	}
	return engine.DirectionRequest
}
