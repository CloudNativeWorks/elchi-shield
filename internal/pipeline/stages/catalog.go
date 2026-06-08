package stages

import (
	"fmt"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/policy"
)

// Catalog is the registry of available stages plus the fixed structural stages.
// It is built once from Deps and is the single extensibility point: registering
// a new inspector here (and adding its name to config.knownInspectors) makes it
// orderable per policy without touching the executor or the server.
//
// The request/response pipelines are split into a fixed PRELUDE (context init,
// policy resolution, early decision) and a per-policy INSPECT sequence, because
// the effective policy — and therefore its stage order — is only known after
// policy resolution.
type Catalog struct {
	inspectors map[string]pipeline.Stage // name → reorderable inspector
	wafHeader  pipeline.Stage            // header-phase half of waf_engine
	bodyGate   pipeline.Stage            // structural, prepended to header pipeline
	bodyGuard  pipeline.Stage            // structural truncation guard, prepended to body pipeline
	bodyDecode pipeline.Stage            // structural content-decode, after the guard
	reqPrelude *pipeline.Pipeline
	respPre    *pipeline.Pipeline
	obs        pipeline.Observer
}

// NewCatalog builds the catalog and the fixed prelude pipelines from deps.
func NewCatalog(deps Deps) *Catalog {
	c := &Catalog{
		inspectors: map[string]pipeline.Stage{
			config.StageFastPreChecks: FastPreChecks(),
			config.StageBodyChecks:    BodyChecks(deps.Detector),
			config.StageWAFEngine:     WAFEngine(),
		},
		wafHeader:  WAFHeaderEngine(),
		bodyGate:   BodyGate(),
		bodyGuard:  BodyTruncationGuard(),
		bodyDecode: BodyContentDecode(),
		obs:        deps.Observer,
	}
	// Preludes are phase-ordered, so the validated constructor is used.
	c.reqPrelude, _ = pipeline.New("request_prelude",
		[]pipeline.Stage{ContextInit(deps.TrustedHops), PolicyResolve(), EarlyDecision(deps.DefaultAllow)}, deps.Observer)
	c.respPre, _ = pipeline.New("response_prelude",
		[]pipeline.Stage{ContextInit(deps.TrustedHops)}, deps.Observer)
	return c
}

// StageNames returns every stage name the catalog can run (structural +
// inspectors), so observers (metrics) can pre-register them for lock-free
// recording.
func (c *Catalog) StageNames() []string {
	names := make([]string, 0, 7+len(c.inspectors))
	names = append(names, ContextInit(0).Name(), PolicyResolve().Name(), EarlyDecision(false).Name(),
		c.bodyGate.Name(), c.bodyGuard.Name(), c.bodyDecode.Name(), c.wafHeader.Name())
	for name := range c.inspectors {
		names = append(names, name)
	}
	return names
}

// RequestPrelude returns the fixed request prelude (context init → policy
// resolve → early decision). After it runs, tx.Policy is set (or the request is
// terminated).
func (c *Catalog) RequestPrelude() *pipeline.Pipeline { return c.reqPrelude }

// ResponsePrelude returns the fixed response prelude (context init). Responses
// reuse the pinned request policy.
func (c *Catalog) ResponsePrelude() *pipeline.Pipeline { return c.respPre }

// PolicyPipelines holds the inspect pipelines compiled for one policy.
type PolicyPipelines struct {
	RequestHeader  *pipeline.Pipeline // header-phase inspectors + body gate
	RequestBody    *pipeline.Pipeline // body/WAF-phase inspectors (policy order)
	ResponseHeader *pipeline.Pipeline
	ResponseBody   *pipeline.Pipeline
}

// BuildPolicyPipelines compiles a policy's inspect pipelines from its ordered
// stage names (defaulting to the canonical order). Header-phase inspectors run
// at header time; body/WAF-phase inspectors run at body time in the policy's
// order. Unknown stage names error (aborting the lazy build → request fails per
// policy fail posture; config validation already rejects unknown names earlier).
func (c *Catalog) BuildPolicyPipelines(p *policy.CompiledPolicy) (*PolicyPipelines, error) {
	reqHdr, reqBody, err := c.split("request", orderOrDefault(p.RequestOrder))
	if err != nil {
		return nil, err
	}
	respHdr, respBody, err := c.split("response", orderOrDefault(p.ResponseOrder))
	if err != nil {
		return nil, err
	}
	return &PolicyPipelines{
		RequestHeader:  reqHdr,
		RequestBody:    reqBody,
		ResponseHeader: respHdr,
		ResponseBody:   respBody,
	}, nil
}

// split partitions an ordered inspector list into a header pipeline (pre-check
// inspectors + the structural body gate) and a body pipeline (body/WAF
// inspectors, in the given order).
func (c *Catalog) split(dir string, order []string) (header, body *pipeline.Pipeline, err error) {
	var headerStages, bodyStages []pipeline.Stage
	for _, name := range order {
		// waf_engine is one config word but two physical stages: header-only
		// engines (e.g. JWT) run at header time, body engines (e.g. Coraza) at body
		// time. Its position in the order sets the relative order within each phase.
		if name == config.StageWAFEngine {
			headerStages = append(headerStages, c.wafHeader)
			bodyStages = append(bodyStages, c.inspectors[config.StageWAFEngine])
			continue
		}
		st, ok := c.inspectors[name]
		if !ok {
			return nil, nil, fmt.Errorf("unknown stage %q", name)
		}
		if st.Phase() == pipeline.PhasePreCheck {
			headerStages = append(headerStages, st)
		} else {
			bodyStages = append(bodyStages, st)
		}
	}
	headerStages = append(headerStages, c.bodyGate) // structural, decides body need
	// Structural body-phase prefix, non-skippable and always first in this order:
	//  1. truncation guard — an over-limit body can never reach inspectors as "clean";
	//  2. content-decode — decompress Content-Encoded bodies so inspectors see the
	//     real payload, not opaque compressed bytes (or block if undecodable).
	bodyStages = append([]pipeline.Stage{c.bodyGuard, c.bodyDecode}, bodyStages...)
	return pipeline.NewUnordered(dir+"_header", headerStages, c.obs),
		pipeline.NewUnordered(dir+"_body", bodyStages, c.obs), nil
}

func orderOrDefault(order []string) []string {
	if order == nil {
		return config.DefaultPipelineOrder
	}
	return order
}
