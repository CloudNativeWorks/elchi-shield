package metrics

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/runtime"
)

const namespace = "elchi_shield"

// Metrics holds every Prometheus collector. Request-level counters carry a
// `listener` label and are pre-curried per listener (see ForListener) so the
// hot path never takes the Prometheus label-map lock. Stage metrics are frozen
// at startup via RegisterStages for the same reason. All recording methods are
// nil-safe so observability can be disabled by passing nil.
type Metrics struct {
	reg      *prometheus.Registry
	instance string

	// listenerCache memoizes the per-listener cursor by its label value (the Envoy
	// node id from ext_proc attributes, or the configured listener id) so a new
	// value is curried once on first sight (a brief sync.Map write) and every
	// subsequent record is a lock-free read. listenerCount caps distinct values as
	// a backstop against unbounded cardinality (node ids come from a trusted Envoy
	// bootstrap, so this only guards misconfiguration).
	listenerCache sync.Map // string -> *ListenerMetrics
	listenerCount atomic.Int64

	// Global (no listener dimension).
	reloadOK         prometheus.Counter
	reloadFail       prometheus.Counter
	extprocErr       *prometheus.CounterVec
	timeouts         prometheus.Counter
	failOpen         prometheus.Counter
	failClose        prometheus.Counter
	lastReloadOK     prometheus.Gauge // unix seconds of the last successful reload
	reloadFailStreak prometheus.Gauge // consecutive reload failures (0 after a success)

	activeVersion *prometheus.GaugeVec

	// Request-level, labeled by listener.
	requests         *prometheus.CounterVec
	allowed          *prometheus.CounterVec
	blocked          *prometheus.CounterVec
	detect           *prometheus.CounterVec
	shadow           *prometheus.CounterVec
	bodyBytes        *prometheus.CounterVec
	findings         *prometheus.CounterVec // by (engine, action) — which engine blocked/detected
	bodyMutations    *prometheus.CounterVec // DLP redactions (mutated bodies)
	bodyBudgetReject *prometheus.CounterVec // by reason — intake truncations from a memory bound
	latency          *prometheus.HistogramVec

	// Stage metrics, registered once (RegisterStages) → lock-free reads.
	stageLatency *prometheus.HistogramVec
	stageActions *prometheus.CounterVec
	stages       map[string]*stageMetric // immutable after RegisterStages
}

type stageMetric struct {
	latency prometheus.Observer
	actions map[string]prometheus.Counter
}

// ListenerMetrics is a per-listener cursor of the request counters: every field
// is already curried with the listener label, so recording is a lock-free atomic
// increment. The Processor resolves one of these once at construction.
type ListenerMetrics struct {
	requests          prometheus.Counter
	allowed           prometheus.Counter
	blocked           prometheus.Counter
	detect            prometheus.Counter
	shadow            prometheus.Counter
	bodyBytes         prometheus.Counter
	bodyMutations     prometheus.Counter
	budgetRejByReason map[string]prometheus.Counter // pre-curried per reason
	// latencyByPhase holds the per-phase latency observers, pre-curried at
	// construction (ForListener) so recording is a lock-free, alloc-free map read
	// + Observe — never a per-request WithLabelValues.
	latencyByPhase map[string]prometheus.Observer
	latencyOther   prometheus.Observer // fallback for an unregistered phase
	// findingsByKey is pre-curried per "engine\x00action" so RecordDecision does a
	// lock-free map read; an unknown engine maps to the "other" bucket.
	findingsByKey map[string]prometheus.Counter
}

// latencyPhases are the request/response phase labels the latency histogram is
// pre-curried for (matching the Processor's finish() phase strings).
var latencyPhases = []string{"request_headers", "request_body", "response_headers", "response_body"}

// findingEngines is the set of engine/source names the findings_total counter is
// pre-curried for (so RecordDecision is a lock-free map read, never a per-request
// WithLabelValues). The value in a Decision.Engine that isn't here falls into the
// "other" bucket. Keep in sync as engines are added (builtin = native header/body
// checks; anomaly = the cross-engine scorer).
var findingEngines = []string{
	"builtin", "anomaly", "jwt", "ratelimit", "coraza", "ipreputation", "bot",
	"apikey", "hmacsign", "httpsig", "jwks", "xfcc", "graphql", "openapi",
	// Structural body checks split out of "builtin" so they're distinguishable:
	// dlp = sensitive-data block/redaction; body_size = truncation guard;
	// body_decode = undecodable/decode-budget blocks.
	"dlp", "body_size", "body_decode", "other",
}

// findingActions are the non-allow outcomes findings are counted for.
var findingActions = []string{"block", "detect", "shadow"}

// budgetRejectReasons label body_budget_rejections_total: a per-request body cap
// hit, or the process-wide in-flight budget exhausted (a body-flood signal).
var budgetRejectReasons = []string{"per_request_cap", "inflight_budget"}

// New builds and registers all collectors. instance, when non-empty, becomes a
// constant label on every series so multi-machine metrics never collide.
func New(instance string) *Metrics {
	reg := prometheus.NewRegistry()
	var reger prometheus.Registerer = reg
	if instance != "" {
		reger = prometheus.WrapRegistererWith(prometheus.Labels{"instance": instance}, reg)
	}
	ctr := func(name, help string) prometheus.Counter {
		c := prometheus.NewCounter(prometheus.CounterOpts{Namespace: namespace, Name: name, Help: help})
		reger.MustRegister(c)
		return c
	}
	ctrVec := func(name, help string, labels ...string) *prometheus.CounterVec {
		c := prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Name: name, Help: help}, labels)
		reger.MustRegister(c)
		return c
	}
	gg := func(name, help string) prometheus.Gauge {
		g := prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: name, Help: help})
		reger.MustRegister(g)
		return g
	}

	m := &Metrics{
		reg:              reg,
		instance:         instance,
		reloadOK:         ctr("config_reload_success_total", "Successful config reloads."),
		reloadFail:       ctr("config_reload_failure_total", "Failed config reloads."),
		extprocErr:       ctrVec("extproc_errors_total", "ext_proc stream errors by kind.", "kind"),
		timeouts:         ctr("timeouts_total", "Per-request processing timeouts."),
		failOpen:         ctr("fail_open_total", "Fail-open posture applications."),
		failClose:        ctr("fail_close_total", "Fail-close posture applications."),
		lastReloadOK:     gg("config_last_reload_success_timestamp_seconds", "Unix time of the last successful config reload."),
		reloadFailStreak: gg("config_reload_failures_consecutive", "Consecutive failed config reloads (0 after a success)."),
		requests:         ctrVec("requests_total", "Total requests processed.", "listener"),
		allowed:          ctrVec("requests_allowed_total", "Requests allowed.", "listener"),
		blocked:          ctrVec("requests_blocked_total", "Requests blocked.", "listener"),
		detect:           ctrVec("detections_total", "Detect-mode would-block detections (request allowed).", "listener"),
		shadow:           ctrVec("shadow_detections_total", "Shadow-mode would-block detections.", "listener"),
		bodyBytes:        ctrVec("body_inspected_bytes_total", "Body bytes inspected.", "listener"),
		findings:         ctrVec("findings_total", "Findings by the engine that produced them and the action taken (block/detect/shadow).", "listener", "engine", "action"),
		bodyMutations:    ctrVec("body_mutations_total", "Bodies rewritten by DLP redaction (mutated for forwarding).", "listener"),
		bodyBudgetReject: ctrVec("body_budget_rejections_total", "Body chunks rejected/truncated at intake by a memory bound.", "listener", "reason"),
	}
	m.activeVersion = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "active_config_version", Help: "Active config version (value is always 1).",
	}, []string{"version"})
	m.latency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "processing_latency_seconds", Help: "Per-phase processing latency.",
		Buckets: prometheus.ExponentialBuckets(0.00005, 2, 14),
	}, []string{"listener", "phase"})
	m.stageLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: namespace, Name: "stage_latency_seconds", Help: "Per-stage processing latency.",
		Buckets: prometheus.ExponentialBuckets(0.00002, 2, 14),
	}, []string{"stage"})
	m.stageActions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace, Name: "stage_actions_total", Help: "Stage results by action.",
	}, []string{"stage", "action"})
	reger.MustRegister(m.activeVersion, m.latency, m.stageLatency, m.stageActions)

	// Go runtime + process collectors: goroutine count (leak detection), heap/GC,
	// scheduler latency (engine back-pressure visibility), and FD/CPU/RSS. These
	// are pull-based (read at scrape time) so they cost nothing on the request
	// path, and registering through reger keeps the `instance` label on every
	// series.
	reger.MustRegister(
		collectors.NewGoCollector(
			collectors.WithGoCollectorRuntimeMetrics(
				collectors.MetricsScheduler, // go_sched_latencies_seconds, ...
				collectors.MetricsGC,        // go_gc_* detail
			),
		),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Registry exposes the registry for the HTTP /metrics handler.
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// RegisterGaugeFunc registers a pull-based gauge whose value is read from f at
// scrape time (no per-request cost). Used for live gauges like queue depth,
// in-flight streams, and buffered body bytes. Safe no-op on nil.
func (m *Metrics) RegisterGaugeFunc(name, help string, f func() float64) {
	if m == nil {
		return
	}
	m.register(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Namespace: namespace, Name: name, Help: help}, f))
}

// RegisterCounterFunc registers a pull-based monotonic counter read from f at
// scrape time. Used for cumulative counters owned outside this package (e.g.
// audit events dropped). Safe no-op on nil.
func (m *Metrics) RegisterCounterFunc(name, help string, f func() float64) {
	if m == nil {
		return
	}
	m.register(prometheus.NewCounterFunc(prometheus.CounterOpts{Namespace: namespace, Name: name, Help: help}, f))
}

// register attaches an instance-labeled collector to the registry.
func (m *Metrics) register(c prometheus.Collector) {
	var reger prometheus.Registerer = m.reg
	if m.instance != "" {
		reger = prometheus.WrapRegistererWith(prometheus.Labels{"instance": m.instance}, m.reg)
	}
	reger.MustRegister(c)
}

// RegisterStages pre-creates the curried per-stage metrics for the given stage
// names. It MUST be called once at startup, before any request is served, so
// StageObserved can read the frozen map lock-free. Safe no-op on nil.
func (m *Metrics) RegisterStages(names []string) {
	if m == nil {
		return
	}
	m.stages = make(map[string]*stageMetric, len(names))
	for _, name := range names {
		actions := make(map[string]prometheus.Counter)
		for a := pipeline.StageAction(0); a <= pipeline.ActionError; a++ {
			actions[a.String()] = m.stageActions.WithLabelValues(name, a.String())
		}
		m.stages[name] = &stageMetric{
			latency: m.stageLatency.WithLabelValues(name),
			actions: actions,
		}
	}
}

// maxListenerSeries caps distinct listener label values (Envoy node ids). A
// trusted Envoy yields few; this is a backstop against a misconfigured attribute
// producing unbounded cardinality. Beyond the cap, values fold into "overflow".
const maxListenerSeries = 4096

const overflowListener = "overflow"

// ForListener returns the per-listener request-metric cursor for a label value
// (an Envoy node id or the configured listener id), memoized so each value is
// curried once and every subsequent lookup is a lock-free read.
func (m *Metrics) ForListener(id string) *ListenerMetrics {
	if m == nil {
		return nil
	}
	if v, ok := m.listenerCache.Load(id); ok {
		return v.(*ListenerMetrics)
	}
	if m.listenerCount.Load() >= maxListenerSeries && id != overflowListener {
		return m.ForListener(overflowListener)
	}
	lm := m.buildListenerMetrics(id)
	actual, loaded := m.listenerCache.LoadOrStore(id, lm)
	if !loaded {
		m.listenerCount.Add(1)
	}
	return actual.(*ListenerMetrics)
}

// buildListenerMetrics curries every per-listener series with the label value.
func (m *Metrics) buildListenerMetrics(id string) *ListenerMetrics {
	lm := &ListenerMetrics{
		requests:          m.requests.WithLabelValues(id),
		allowed:           m.allowed.WithLabelValues(id),
		blocked:           m.blocked.WithLabelValues(id),
		detect:            m.detect.WithLabelValues(id),
		shadow:            m.shadow.WithLabelValues(id),
		bodyBytes:         m.bodyBytes.WithLabelValues(id),
		bodyMutations:     m.bodyMutations.WithLabelValues(id),
		budgetRejByReason: make(map[string]prometheus.Counter, len(budgetRejectReasons)),
		latencyByPhase:    make(map[string]prometheus.Observer, len(latencyPhases)),
		latencyOther:      m.latency.WithLabelValues(id, "other"),
		findingsByKey:     make(map[string]prometheus.Counter, len(findingEngines)*len(findingActions)),
	}
	for _, r := range budgetRejectReasons {
		lm.budgetRejByReason[r] = m.bodyBudgetReject.WithLabelValues(id, r)
	}
	for _, ph := range latencyPhases {
		lm.latencyByPhase[ph] = m.latency.WithLabelValues(id, ph)
	}
	for _, eng := range findingEngines {
		for _, act := range findingActions {
			lm.findingsByKey[eng+"\x00"+act] = m.findings.WithLabelValues(id, eng, act)
		}
	}
	return lm
}

// StageObserved implements pipeline.Observer. It reads the frozen stages map
// with no lock; unregistered names are ignored.
func (m *Metrics) StageObserved(name string, _ pipeline.Phase, dur time.Duration, action pipeline.StageAction) {
	if m == nil {
		return
	}
	sm := m.stages[name]
	if sm == nil {
		return
	}
	sm.latency.Observe(dur.Seconds())
	if c := sm.actions[action.String()]; c != nil {
		c.Inc()
	}
}

// FailOpen implements pipeline.PostureObserver.
func (m *Metrics) FailOpen() {
	if m != nil {
		m.failOpen.Inc()
	}
}

// FailClose implements pipeline.PostureObserver.
func (m *Metrics) FailClose() {
	if m != nil {
		m.failClose.Inc()
	}
}

// Timeout implements pipeline.PostureObserver.
func (m *Metrics) Timeout() {
	if m != nil {
		m.timeouts.Inc()
	}
}

// RecordExtprocError records a stream error attributed to a kind ("panic",
// "transport", "build", ...) so an operator can tell a recovered panic from a
// transport drop from a pipeline-build failure.
func (m *Metrics) RecordExtprocError(kind string) {
	if m != nil {
		m.extprocErr.WithLabelValues(kind).Inc()
	}
}

// RecordReload records a reload outcome and updates the active version gauge,
// the last-success timestamp, and the consecutive-failure streak (so operators
// can alert on a stale config caused by a broken upstream config push).
func (m *Metrics) RecordReload(outcome runtime.Outcome, version string) {
	if m == nil {
		return
	}
	switch outcome {
	case runtime.OutcomeApplied:
		m.reloadOK.Inc()
		m.activeVersion.Reset()
		m.activeVersion.WithLabelValues(version).Set(1)
		m.lastReloadOK.SetToCurrentTime()
		m.reloadFailStreak.Set(0)
	case runtime.OutcomeUnchanged, runtime.OutcomeEmpty:
		// NOT an actual reload — no new config was applied. Do not count it as a reload
		// success or bump the last-reload timestamp: a periodic no-op re-scan (the
		// watcher backstop) or a management-plane reconcile re-pushing identical config
		// must not look like a config change on dashboards/alerts. Only clear the
		// failure streak — a valid unchanged config means the sidecar isn't failing.
		// (Staleness is tracked independently by config_age_seconds, off the snapshot
		// build time, which only advances on an actual apply.)
		m.reloadFailStreak.Set(0)
	case runtime.OutcomeFailed:
		m.reloadFail.Inc()
		m.reloadFailStreak.Inc()
	}
}

// SetBuildInfo registers a build_info gauge (value 1) carrying version metadata
// as labels, so dashboards/alerts can join on the running binary and confirm
// rollouts across a fleet of sidecars.
func (m *Metrics) SetBuildInfo(version, revision, goVersion, buildTime, corerulesetVersion string) {
	if m == nil {
		return
	}
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help: "Build metadata (value is always 1); join on the labels.",
	}, []string{"version", "revision", "goversion", "build_time", "coreruleset_version"})
	m.register(g)
	g.WithLabelValues(version, revision, goVersion, buildTime, corerulesetVersion).Set(1)
}

// RecordDecision records one phase decision plus its latency, labeled by phase
// (lock-free: the phase observer is pre-curried, looked up by a map read).
//
// The per-transaction tally (requests_total and the allowed counter) is recorded
// only on a REQUEST-direction phase, so a request that also has its response
// inspected isn't counted as two requests / two allows. A block counts on either
// direction (a response block is still an enforcement action). Latency and
// findings are recorded for every phase.
func (lm *ListenerMetrics) RecordDecision(d *decision.Decision, phase string, latency time.Duration) {
	if lm == nil || d == nil {
		return
	}
	isRequest := strings.HasPrefix(phase, "request")
	if isRequest {
		lm.requests.Inc()
	}
	obs := lm.latencyByPhase[phase]
	if obs == nil {
		obs = lm.latencyOther
	}
	obs.Observe(latency.Seconds())
	switch {
	case d.IsBlock():
		lm.blocked.Inc()
		lm.recordFinding(d.Engine, "block")
	case d.Action == decision.Detect:
		lm.detect.Inc()
		if isRequest {
			lm.allowed.Inc()
		}
		lm.recordFinding(d.Engine, "detect")
	case d.Action == decision.Shadow:
		lm.shadow.Inc()
		if isRequest {
			lm.allowed.Inc()
		}
		lm.recordFinding(d.Engine, "shadow")
	default:
		if isRequest {
			lm.allowed.Inc()
		}
	}
}

// RecordPhaseFindings records the detect/shadow finding metrics (the detections/
// shadow counter + per-engine findings_total) for a NON-TERMINAL phase — one whose
// finish() will not run because a later phase is terminal. It deliberately omits
// the per-request tally (requests_total / allowed): that is recorded exactly once
// by the terminal phase's RecordDecision, so a header detection on a body-
// inspecting route is counted without inflating the request count. A block never
// reaches this path (it short-circuits and finishes immediately).
func (lm *ListenerMetrics) RecordPhaseFindings(d *decision.Decision) {
	if lm == nil || d == nil {
		return
	}
	switch d.Action {
	case decision.Detect:
		lm.detect.Inc()
		lm.recordFinding(d.Engine, "detect")
	case decision.Shadow:
		lm.shadow.Inc()
		lm.recordFinding(d.Engine, "shadow")
	}
}

// RecordBodyMutation counts one DLP body redaction (the body was rewritten for
// forwarding).
func (lm *ListenerMetrics) RecordBodyMutation() {
	if lm == nil {
		return
	}
	lm.bodyMutations.Inc()
}

// RecordBodyBudgetReject counts one intake truncation caused by a memory bound
// (reason: per_request_cap or inflight_budget). An unknown reason is ignored.
func (lm *ListenerMetrics) RecordBodyBudgetReject(reason string) {
	if lm == nil {
		return
	}
	if c := lm.budgetRejByReason[reason]; c != nil {
		c.Inc()
	}
}

// recordFinding increments the per-engine/action findings counter (lock-free map
// read; an unknown or empty engine falls into the "other" bucket).
func (lm *ListenerMetrics) recordFinding(engine, action string) {
	if engine == "" {
		engine = "other"
	}
	c := lm.findingsByKey[engine+"\x00"+action]
	if c == nil {
		c = lm.findingsByKey["other\x00"+action]
	}
	if c != nil {
		c.Inc()
	}
}

// RecordBodyBytes records inspected body bytes (lock-free).
func (lm *ListenerMetrics) RecordBodyBytes(n int) {
	if lm != nil && n > 0 {
		lm.bodyBytes.Add(float64(n))
	}
}
