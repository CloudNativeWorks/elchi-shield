package metrics

import (
	"testing"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/runtime"
)

// gather sums all samples for the named metric family.
func gather(t *testing.T, m *Metrics, name string) float64 {
	t.Helper()
	fams, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	full := namespace + "_" + name
	for _, f := range fams {
		if f.GetName() != full {
			continue
		}
		var sum float64
		for _, mm := range f.GetMetric() {
			if c := mm.GetCounter(); c != nil {
				sum += c.GetValue()
			}
			if g := mm.GetGauge(); g != nil {
				sum += g.GetValue()
			}
		}
		return sum
	}
	return 0
}

func TestRecordDecisionCounters(t *testing.T) {
	m := New("")
	lm := m.ForListener("lst-1")
	lm.RecordDecision(&decision.Decision{Action: decision.Block}, "request_headers", time.Millisecond)
	lm.RecordDecision(&decision.Decision{Action: decision.Allow}, "request_body", time.Millisecond)
	lm.RecordDecision(&decision.Decision{Action: decision.Shadow}, "response_headers", time.Millisecond)
	lm.RecordDecision(&decision.Decision{Action: decision.Detect}, "unknown_phase", time.Millisecond)

	if got := gather(t, m, "requests_total"); got != 4 {
		t.Errorf("requests_total = %v, want 4", got)
	}
	if got := gather(t, m, "requests_blocked_total"); got != 1 {
		t.Errorf("blocked = %v, want 1", got)
	}
	if got := gather(t, m, "shadow_detections_total"); got != 1 {
		t.Errorf("shadow = %v, want 1", got)
	}
	if got := gather(t, m, "detections_total"); got != 1 {
		t.Errorf("detect = %v, want 1", got)
	}
	// allow + shadow + detect all count as allowed.
	if got := gather(t, m, "requests_allowed_total"); got != 3 {
		t.Errorf("allowed = %v, want 3", got)
	}
}

func TestRecordDecisionPhaseLabeledZeroAlloc(t *testing.T) {
	m := New("")
	lm := m.ForListener("lst-1")
	d := &decision.Decision{Action: decision.Allow}
	// The pre-curried per-phase observer lookup must not allocate on the hot path.
	if got := testing.AllocsPerRun(200, func() {
		lm.RecordDecision(d, "request_headers", time.Millisecond)
	}); got != 0 {
		t.Fatalf("RecordDecision must be 0 allocs/op, got %v", got)
	}
	// A known phase and an unknown phase (→ "other") both record a sample.
	lm.RecordDecision(d, "response_body", time.Millisecond)
	lm.RecordDecision(d, "bogus", time.Millisecond)
	fams, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	phases := map[string]bool{}
	for _, f := range fams {
		if f.GetName() != "elchi_shield_processing_latency_seconds" {
			continue
		}
		for _, mt := range f.GetMetric() {
			for _, l := range mt.GetLabel() {
				if l.GetName() == "phase" {
					phases[l.GetValue()] = true
				}
			}
		}
	}
	for _, want := range []string{"request_headers", "response_body", "other"} {
		if !phases[want] {
			t.Errorf("latency histogram missing phase=%q (got %v)", want, phases)
		}
	}
}

func TestRecordReloadAndVersion(t *testing.T) {
	m := New("")
	m.RecordReload(runtime.OutcomeApplied, "v1")
	m.RecordReload(runtime.OutcomeFailed, "v1")
	if got := gather(t, m, "config_reload_success_total"); got != 1 {
		t.Errorf("reload success = %v, want 1", got)
	}
	if got := gather(t, m, "config_reload_failure_total"); got != 1 {
		t.Errorf("reload failure = %v, want 1", got)
	}
	if got := gather(t, m, "active_config_version"); got != 1 {
		t.Errorf("active_config_version gauge = %v, want 1", got)
	}
}

func TestPostureObserver(t *testing.T) {
	m := New("")
	m.FailOpen()
	m.FailClose()
	m.Timeout()
	if gather(t, m, "fail_open_total") != 1 || gather(t, m, "fail_close_total") != 1 || gather(t, m, "timeouts_total") != 1 {
		t.Error("posture counters not recorded")
	}
}

func TestNilMetricsSafe(t *testing.T) {
	var m *Metrics
	// None of these should panic.
	m.RecordReload(runtime.OutcomeApplied, "v")
	m.FailOpen()
	m.StageObserved("s", 0, 0, 0)
	m.RecordExtprocError("panic")
	m.RegisterStages([]string{"x"})
	m.ForListener("l").RecordDecision(&decision.Decision{Action: decision.Block}, "request_headers", 0)
}

// gatherLabeled sums samples of a counter family matching the given label=value.
func gatherLabeled(t *testing.T, m *Metrics, name, label, value string) float64 {
	t.Helper()
	fams, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	full := namespace + "_" + name
	var sum float64
	for _, f := range fams {
		if f.GetName() != full {
			continue
		}
		for _, mm := range f.GetMetric() {
			for _, lp := range mm.GetLabel() {
				if lp.GetName() == label && lp.GetValue() == value {
					sum += mm.GetCounter().GetValue()
				}
			}
		}
	}
	return sum
}

func TestFindingsByEngine(t *testing.T) {
	m := New("")
	lm := m.ForListener("lst-1")
	lm.RecordDecision(&decision.Decision{Action: decision.Block, Engine: "coraza"}, "request_body", time.Millisecond)
	lm.RecordDecision(&decision.Decision{Action: decision.Block, Engine: "bot"}, "request_headers", time.Millisecond)
	lm.RecordDecision(&decision.Decision{Action: decision.Detect, Engine: "bot"}, "request_headers", time.Millisecond)
	lm.RecordDecision(&decision.Decision{Action: decision.Block, Engine: "no-such-engine"}, "request_headers", time.Millisecond)
	lm.RecordDecision(&decision.Decision{Action: decision.Allow}, "request_headers", time.Millisecond) // no finding

	if v := gatherLabeled(t, m, "findings_total", "engine", "coraza"); v != 1 {
		t.Errorf("coraza findings = %v, want 1", v)
	}
	if v := gatherLabeled(t, m, "findings_total", "engine", "bot"); v != 2 {
		t.Errorf("bot findings = %v, want 2 (1 block + 1 detect)", v)
	}
	if v := gatherLabeled(t, m, "findings_total", "action", "block"); v != 3 {
		t.Errorf("block findings = %v, want 3", v)
	}
	if v := gatherLabeled(t, m, "findings_total", "action", "detect"); v != 1 {
		t.Errorf("detect findings = %v, want 1", v)
	}
	// An unknown engine falls into the "other" bucket.
	if v := gatherLabeled(t, m, "findings_total", "engine", "other"); v != 1 {
		t.Errorf("other-engine findings = %v, want 1", v)
	}
	// Total findings = 4 (the allow produced none).
	if v := gather(t, m, "findings_total"); v != 4 {
		t.Errorf("total findings = %v, want 4", v)
	}
}
