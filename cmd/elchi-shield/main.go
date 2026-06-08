// Command elchi-shield is a local Envoy ext_proc API-security / WAF engine.
//
// It runs as a sidecar next to Envoy on the client machine. Envoy calls it over
// ext_proc; it inspects request/response headers and (optionally) bodies and
// returns allow/block/continue decisions. Configuration is delivered as files
// written by elchi-client into a watched directory and hot-reloaded atomically.
//
// This entrypoint only parses configuration, builds shared dependencies, starts
// the long-running components, and coordinates graceful shutdown. All real logic
// lives in internal packages.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	goruntime "runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/audit"
	"github.com/cloudnativeworks/elchi-shield/internal/logging"
	"github.com/cloudnativeworks/elchi-shield/internal/metrics"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline/stages"
	"github.com/cloudnativeworks/elchi-shield/internal/policy"
	"github.com/cloudnativeworks/elchi-shield/internal/runtime"
	"github.com/cloudnativeworks/elchi-shield/internal/sensitive"
	"github.com/cloudnativeworks/elchi-shield/internal/server/extproc"
	httpserver "github.com/cloudnativeworks/elchi-shield/internal/server/http"
	"github.com/cloudnativeworks/elchi-shield/internal/watcher"
)

// version and commit are injected at build time via
// -ldflags "-X main.version=... -X main.commit=...". The release workflow reads
// the version from the VERSION file; local `make build` stamps the VCS revision
// via -buildvcs.
var (
	version = "dev"
	commit  = ""
)

// buildInfo returns the binary's version metadata: the ldflags-injected version
// and commit, the Go toolchain version, and the VCS commit time that Go embeds
// automatically (-buildvcs). Used for the build_info metric and /configz so a
// fleet of sidecars is identifiable at a glance. When commit isn't injected (a
// local build), it falls back to the embedded vcs.revision.
func buildInfo() (ver, revision, goVersion, buildTime string) {
	ver, revision, goVersion = version, commit, goruntime.Version()
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if revision == "" {
					revision = s.Value
				}
			case "vcs.time":
				buildTime = s.Value
			}
		}
	}
	return ver, revision, goVersion, buildTime
}

// snapshotRetireGrace is how long a replaced snapshot is kept before its engines
// are closed, allowing in-flight requests that pinned it to finish.
const snapshotRetireGrace = 30 * time.Second

// retireItem is a snapshot queued for delayed close, with its enqueue time.
type retireItem struct {
	snap *runtime.Snapshot
	at   time.Time
}

// appConfig holds process-level configuration sourced from flags/env. It is
// intentionally flat and immutable after parsing; component-level config lives
// in the relevant internal packages.
type appConfig struct {
	instanceID       string
	configDir        string
	extprocNetwork   string // "unix" or "tcp" (single-listener fallback)
	extprocAddr      string
	extprocListeners stringList // repeatable id=network:addr (multi-listener)
	httpAddr         string
	allowNonLoopback bool
	listenerID       string
	maxBodyBytes     int64
	maxInFlightBody  int64
	debounce         time.Duration
	defaultAllow     bool
	auditExporter    string
	auditFile        string
	auditDSN         string
	auditEndpoint    string
	auditInsecure    bool
	auditMaxPerSec   float64
	logLevel         string
	logFormat        string
	logSource        bool
	pprof            bool
	blockProfileRate int
	mutexProfileFrac int
	memLimitBytes    int64
	shutdownTimeout  time.Duration
}

func main() {
	cfg := parseFlags(os.Args[1:])

	// Stamp the instance identity on every log record so logs from many machines
	// never get confused. Source location (file:line) is enabled explicitly or
	// implicitly at debug level, where it most helps.
	logger := logging.New(logging.Options{
		Level:     cfg.logLevel,
		Format:    logging.Format(cfg.logFormat),
		AddSource: cfg.logSource || strings.EqualFold(strings.TrimSpace(cfg.logLevel), "debug"),
	}).With("instance", cfg.instanceID)

	if err := run(cfg, logger); err != nil {
		logger.Error("fatal error, exiting", logging.Err(err))
		os.Exit(1)
	}
}

// noHeaders is an empty header source for policy resolution in the /policyz
// explainer (header-predicate routes can't be evaluated without request headers).
type noHeaders struct{}

func (noHeaders) Header(string) (string, bool) { return "", false }

// explainPolicy builds the /policyz handler: it resolves a request shape to its
// policy and reports the structure (id/mode/stage order/engine names) — never
// secrets, rules, or payloads — so an operator can answer "why this verdict?".
func explainPolicy(store *runtime.Store, catalog *stages.Catalog) httpserver.PolicyExplainer {
	return func(q httpserver.PolicyQuery) httpserver.PolicyExplanation {
		res := store.Load().Resolver()
		if res == nil {
			return httpserver.PolicyExplanation{Note: "no active config"}
		}
		p := res.Resolve(&policy.Input{
			ListenerID:  q.Listener,
			Host:        q.Host,
			Path:        stages.NormalizePath(q.Path),
			Method:      q.Method,
			ContentType: q.ContentType,
			Headers:     noHeaders{},
		})
		if p == nil {
			return httpserver.PolicyExplanation{Matched: false, Note: "no policy matched; the default posture applies"}
		}
		exp := httpserver.PolicyExplanation{
			Matched:             true,
			PolicyID:            p.ID,
			Mode:                string(p.Mode),
			FailMode:            string(p.FailMode),
			TimeoutMs:           p.Timeout.Milliseconds(),
			InspectRequestBody:  p.InspectRequestBody,
			InspectResponseBody: p.InspectResponseBody,
			Engines:             p.Engines.Names(),
			Note:                "header-predicate routes are not evaluated here (no request headers)",
		}
		if pp, err := catalog.BuildPolicyPipelines(p); err == nil {
			exp.RequestHeaderStages = pp.RequestHeader.StageNames()
			exp.RequestBodyStages = pp.RequestBody.StageNames()
			exp.ResponseHeaderStages = pp.ResponseHeader.StageNames()
			exp.ResponseBodyStages = pp.ResponseBody.StageNames()
		}
		return exp
	}
}

// run wires components together and blocks until a shutdown signal is received.
// As packages land (config, runtime, watcher, servers) they are started here.
func run(cfg appConfig, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if !cfg.allowNonLoopback && !isLoopbackTCP(cfg.httpAddr) {
		return fmt.Errorf("--http-addr %q is not loopback; the health/metrics server must not be exposed externally (use 127.0.0.1, or --allow-non-loopback to override)", cfg.httpAddr)
	}

	bVer, bRev, bGo, bTime := buildInfo()
	logger.Info("starting elchi-shield",
		"version", bVer,
		"revision", bRev,
		"go_version", bGo,
		"build_time", bTime,
		"config_dir", cfg.configDir,
		"extproc_network", cfg.extprocNetwork,
		"extproc_addr", cfg.extprocAddr,
		"http_addr", cfg.httpAddr,
	)

	// Runtime tuning. GOMEMLIMIT makes the GC rein in before the kernel OOM-kills
	// the sidecar under a body-buffer burst; it must sit comfortably above the
	// in-flight body budget or the GC thrashes. Block/mutex profiling is off by
	// default (it has a small global cost) and opt-in for deep contention debugging.
	if cfg.memLimitBytes > 0 {
		debug.SetMemoryLimit(cfg.memLimitBytes)
		if cfg.maxInFlightBody > 0 && cfg.memLimitBytes < 2*cfg.maxInFlightBody {
			logger.Warn("mem-limit-bytes is close to the in-flight body budget; GC may thrash — set it well above max-inflight-body-bytes",
				"mem_limit_bytes", cfg.memLimitBytes, "inflight_body_budget", cfg.maxInFlightBody)
		}
	}
	if cfg.blockProfileRate > 0 {
		goruntime.SetBlockProfileRate(cfg.blockProfileRate)
	}
	if cfg.mutexProfileFrac > 0 {
		goruntime.SetMutexProfileFraction(cfg.mutexProfileFrac)
	}

	// Component-scoped child loggers: every record an internal subsystem emits
	// carries component=<name>, so logs are immediately attributable and filterable
	// (e.g. component=extproc) when debugging.
	auditLog := logging.Component(logger, "audit")
	configLog := logging.Component(logger, "config")
	runtimeLog := logging.Component(logger, "runtime")
	extprocLog := logging.Component(logger, "extproc")
	httpLog := logging.Component(logger, "http")
	watcherLog := logging.Component(logger, "watcher")

	// Observability: metrics registry (instance-labeled) + optional audit sink.
	m := metrics.New(cfg.instanceID)
	m.SetBuildInfo(bVer, bRev, bGo, bTime)
	auditor, auditBuf, err := buildAuditor(cfg, auditLog)
	if err != nil {
		return fmt.Errorf("build auditor: %w", err)
	}
	defer func() { _ = auditor.Close() }()
	if auditBuf != nil {
		// Surface audit back-pressure so silently-lost evidence is observable.
		m.RegisterCounterFunc("audit_events_dropped_total",
			"Audit events dropped due to a full queue or rate cap.",
			func() float64 { return float64(auditBuf.Dropped()) })
		m.RegisterGaugeFunc("audit_queue_depth",
			"Current depth of the async audit queue.",
			func() float64 { return float64(auditBuf.QueueLen()) })
	}

	// Runtime store + reloader. Start empty (safe startup with no config) and
	// attempt an initial load so a restart restores the last config from disk.
	store := runtime.NewStore(runtime.EmptySnapshot(time.Now()))
	reloader := runtime.NewReloader(store, cfg.configDir, time.Now)
	// A single retirer goroutine closes retired snapshots after a grace period
	// (so in-flight requests that pinned them finish first). Using one bounded
	// queue + one worker — instead of a goroutine per reload — keeps goroutines
	// and held snapshots bounded even under hostile config flapping.
	retireCh := make(chan retireItem, 64)
	go func() {
		for it := range retireCh {
			if d := time.Until(it.at.Add(snapshotRetireGrace)); d > 0 {
				time.Sleep(d)
			}
			if err := it.snap.Close(); err != nil {
				runtimeLog.Warn("retired snapshot close failed", logging.Err(err))
			}
		}
	}()
	reloader.OnRetire(func(old *runtime.Snapshot) {
		select {
		case retireCh <- retireItem{snap: old, at: time.Now()}:
		default: // queue full (flapping) → close now to bound memory
			if err := old.Close(); err != nil {
				runtimeLog.Warn("retired snapshot close failed", logging.Err(err))
			}
		}
	})
	doReload(reloader, configLog, m)

	// Stage catalog: fixed preludes + the reorderable inspectors. Per-policy
	// pipelines are compiled lazily from each policy's order. Metrics is the
	// stage observer; pre-register its stage names so observation is lock-free.
	catalog := stages.NewCatalog(stages.Deps{
		DefaultAllow: cfg.defaultAllow,
		Observer:     m,
		Detector:     sensitive.New(), // built-in PII/secret scanner for detect_sensitive_data
	})
	m.RegisterStages(catalog.StageNames())

	// One ext_proc server per Envoy listener (in this single process), each on its
	// own socket, sharing the lock-free Store/Catalog/Pool/Metrics/Auditor.
	base := extproc.Config{
		Store:                store,
		Pool:                 pipeline.NewPool(),
		Catalog:              catalog,
		Logger:               extprocLog,
		Metrics:              m,
		Auditor:              auditor,
		InstanceID:           cfg.instanceID,
		MaxBody:              cfg.maxBodyBytes,
		MaxInFlightBodyBytes: cfg.maxInFlightBody,
	}
	specs, err := cfg.listeners()
	if err != nil {
		return err
	}
	mgr, err := extproc.NewManager(base, specs, 0, extprocLog)
	if err != nil {
		return fmt.Errorf("build ext_proc manager: %w", err)
	}
	m.RegisterGaugeFunc("streams_in_flight", "ext_proc streams currently being served.",
		func() float64 { return float64(mgr.InFlightStreams()) })
	m.RegisterGaugeFunc("inflight_body_bytes", "Body bytes currently buffered across all streams.",
		func() float64 { return float64(mgr.InFlightBodyBytes()) })
	// config_age_seconds lets operators alert when a broken upstream config push
	// leaves the sidecar enforcing a stale policy (reloads keep the last-good one).
	m.RegisterGaugeFunc("config_age_seconds", "Seconds since the active config was built.",
		func() float64 { return time.Since(store.Load().BuiltAt()).Seconds() })
	logger.Info("scheduler", "GOMAXPROCS", goruntime.GOMAXPROCS(0), "listeners", len(specs))
	if err := mgr.Start(); err != nil {
		return fmt.Errorf("start ext_proc: %w", err)
	}

	// Ready means "has a non-empty, valid config to enforce" — a security
	// sidecar with no policy is not protecting anything, so it is not ready.
	configInfo := func() httpserver.ConfigInfo {
		s := store.Load()
		return httpserver.ConfigInfo{
			Version:   s.Version(),
			Hash:      s.Hash(),
			Sources:   s.Sources(),
			Domains:   s.DomainCount(),
			Empty:     s.IsEmpty(),
			BuiltAt:   s.BuiltAt().UTC().Format(time.RFC3339),
			AgeSec:    time.Since(s.BuiltAt()).Seconds(),
			Instance:  cfg.instanceID,
			Build:     bVer,
			Revision:  bRev,
			GoVersion: bGo,
		}
	}
	httpSrv := httpserver.NewServer(cfg.httpAddr, m.Registry(),
		func() bool { return !store.Load().IsEmpty() }, configInfo,
		explainPolicy(store, catalog), cfg.pprof, httpLog)
	go func() {
		if herr := httpSrv.Serve(); herr != nil {
			httpLog.Error("http server error", logging.Err(herr))
		}
	}()

	// Start the config watcher: each settled change triggers a reload.
	w, err := watcher.New(cfg.configDir, cfg.debounce, func() { doReload(reloader, configLog, m) }, watcherLog)
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	go func() {
		if werr := w.Run(ctx); werr != nil && !errors.Is(werr, context.Canceled) {
			watcherLog.Warn("watcher stopped", logging.Err(werr))
		}
	}()

	// Block until a shutdown signal.
	<-ctx.Done()
	logger.Info("shutdown signal received, draining", "timeout", cfg.shutdownTimeout.String())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()
	mgr.Shutdown(shutdownCtx) // drain ext_proc streams first
	httpSrv.Shutdown(shutdownCtx)
	_ = auditor.Flush(shutdownCtx)
	// Streams are drained, so close the active snapshot's engines (e.g. Coraza
	// rule sets) deterministically rather than leaking them at process exit.
	if err := store.Load().Close(); err != nil {
		runtimeLog.Warn("active snapshot close failed", logging.Err(err))
	}
	logger.Info("shutdown complete")
	return nil
}

// buildAuditor selects the audit exporter from config and wraps it in an async
// buffer so emission never blocks the request path. Remote exporters
// (clickhouse/otel) are only available when their build tag is compiled in.
// buildAuditor returns the auditor and, when an async sink is configured, the
// BufferedExporter (so its drop/queue stats can back metrics). The buffered
// exporter is nil for the "none" sink.
func buildAuditor(cfg appConfig, logger *slog.Logger) (*audit.Auditor, *audit.BufferedExporter, error) {
	name := cfg.auditExporter
	if name == "" {
		if cfg.auditFile != "" {
			name = "file"
		} else {
			name = "none"
		}
	}

	var exp audit.Exporter
	var err error
	switch name {
	case "none":
		return audit.NewAuditor(nil, logger), nil, nil
	case "file":
		if cfg.auditFile == "" {
			return nil, nil, errors.New("file audit exporter requires --audit-file")
		}
		exp, err = audit.NewFileExporter(cfg.auditFile)
	default:
		exp, err = audit.NewExporter(name, audit.ExporterOptions{
			DSN:      cfg.auditDSN,
			Endpoint: cfg.auditEndpoint,
			Insecure: cfg.auditInsecure,
		})
	}
	if err != nil {
		return nil, nil, err
	}
	// Async + bounded + multi-worker so audit never blocks the request path; the
	// rate cap is applied in the workers (off the request goroutine).
	limiter := audit.NewRateLimiter(cfg.auditMaxPerSec)
	buffered := audit.NewBufferedExporter(exp, 4096, auditWorkers, limiter)
	return audit.NewAuditor(buffered, logger), buffered, nil
}

// auditWorkers is the number of goroutines draining the audit queue.
const auditWorkers = 2

// doReload runs one reload, records metrics, and logs the outcome. Failures keep
// the last-good snapshot active and are logged with the attributed config error.
func doReload(r *runtime.Reloader, logger *slog.Logger, m *metrics.Metrics) {
	out, snap, err := r.Reload()
	m.RecordReload(out, snap.Version())
	switch out {
	case runtime.OutcomeApplied:
		logger.Info("config reloaded",
			logging.KeyConfigVersion, snap.Version(),
			"domains", snap.DomainCount(),
			"sources", snap.Sources())
	case runtime.OutcomeUnchanged:
		logger.Debug("config unchanged", logging.KeyConfigVersion, snap.Version())
	case runtime.OutcomeEmpty:
		logger.Warn("no config files found, keeping current config", logging.KeyConfigVersion, snap.Version())
	case runtime.OutcomeFailed:
		logger.Error("config reload failed, keeping last-good config",
			logging.KeyConfigVersion, snap.Version(), logging.Err(err))
	}
}

// parseFlags builds appConfig from command-line flags, falling back to
// ELCHI_SHIELD_* environment variables, then to documented defaults.
func parseFlags(args []string) appConfig {
	fs := flag.NewFlagSet("elchi-shield", flag.ExitOnError)

	cfg := appConfig{}
	fs.StringVar(&cfg.instanceID, "instance-id", env("ELCHI_SHIELD_INSTANCE_ID", defaultInstanceID()), "instance identity stamped on metrics/logs/audit (default <hostname>-shield)")
	fs.StringVar(&cfg.configDir, "config-dir", env("ELCHI_SHIELD_CONFIG_DIR", "/etc/elchi/elchi-shield/conf.d"), "directory of config files to watch")
	fs.StringVar(&cfg.extprocNetwork, "extproc-network", env("ELCHI_SHIELD_EXTPROC_NETWORK", "unix"), "ext_proc listener network: unix or tcp")
	fs.StringVar(&cfg.extprocAddr, "extproc-addr", env("ELCHI_SHIELD_EXTPROC_ADDR", "/etc/elchi/elchi-shield/extproc.sock"), "single-listener ext_proc address (host:port or socket path)")
	fs.Var(&cfg.extprocListeners, "extproc-listener", "per-listener ext_proc socket, repeatable: id=network:addr (e.g. lst1=unix:/etc/elchi/elchi-shield/lst1.sock)")
	for _, v := range splitList(env("ELCHI_SHIELD_EXTPROC_LISTENERS", "")) {
		_ = cfg.extprocListeners.Set(v)
	}
	fs.StringVar(&cfg.httpAddr, "http-addr", env("ELCHI_SHIELD_HTTP_ADDR", "127.0.0.1:9001"), "http address for health/metrics (must be loopback)")
	fs.BoolVar(&cfg.allowNonLoopback, "allow-non-loopback", envBool("ELCHI_SHIELD_ALLOW_NON_LOOPBACK", false), "DANGEROUS: permit binding TCP to non-loopback addresses (exposes the sidecar)")
	fs.StringVar(&cfg.listenerID, "listener-id", env("ELCHI_SHIELD_LISTENER_ID", ""), "Envoy listener id this instance serves (optional scope)")
	fs.Int64Var(&cfg.maxBodyBytes, "max-body-bytes", envInt64("ELCHI_SHIELD_MAX_BODY_BYTES", 1<<20), "hard fallback body cap when a policy specifies none")
	fs.Int64Var(&cfg.maxInFlightBody, "max-inflight-body-bytes", envInt64("ELCHI_SHIELD_MAX_INFLIGHT_BODY_BYTES", 256<<20), "cap on total body bytes buffered across all concurrent streams (0 = unbounded)")
	fs.DurationVar(&cfg.debounce, "watch-debounce", envDuration("ELCHI_SHIELD_WATCH_DEBOUNCE", 300*time.Millisecond), "config watcher debounce window")
	fs.BoolVar(&cfg.defaultAllow, "default-allow", envBool("ELCHI_SHIELD_DEFAULT_ALLOW", true), "posture when no policy matches: allow (true) or deny (false)")
	fs.StringVar(&cfg.auditExporter, "audit-exporter", env("ELCHI_SHIELD_AUDIT_EXPORTER", ""), "audit sink: none|file|clickhouse|otel (clickhouse/otel need their build tag)")
	fs.StringVar(&cfg.auditFile, "audit-file", env("ELCHI_SHIELD_AUDIT_FILE", ""), "path to NDJSON audit log (used by the file exporter)")
	fs.StringVar(&cfg.auditDSN, "audit-clickhouse-dsn", env("ELCHI_SHIELD_AUDIT_CLICKHOUSE_DSN", ""), "ClickHouse DSN for the clickhouse audit exporter")
	fs.StringVar(&cfg.auditEndpoint, "audit-otel-endpoint", env("ELCHI_SHIELD_AUDIT_OTEL_ENDPOINT", ""), "OTLP endpoint for the otel audit exporter")
	fs.BoolVar(&cfg.auditInsecure, "audit-otel-insecure", envBool("ELCHI_SHIELD_AUDIT_OTEL_INSECURE", false), "use an insecure (plaintext) OTLP connection")
	fs.Float64Var(&cfg.auditMaxPerSec, "audit-max-per-sec", envFloat("ELCHI_SHIELD_AUDIT_MAX_PER_SEC", 0), "dynamic-sampling cap on non-finding audit events/sec (0 = unlimited)")
	fs.StringVar(&cfg.logLevel, "log-level", env("ELCHI_SHIELD_LOG_LEVEL", "info"), "log level: debug, info, warn, error")
	fs.StringVar(&cfg.logFormat, "log-format", env("ELCHI_SHIELD_LOG_FORMAT", "json"), "log format: json or text")
	fs.BoolVar(&cfg.logSource, "log-source", envBool("ELCHI_SHIELD_LOG_SOURCE", false), "include source file:line in logs (auto-on at debug level)")
	fs.BoolVar(&cfg.pprof, "pprof", envBool("ELCHI_SHIELD_PPROF", true), "expose /debug/pprof/* on the loopback HTTP server")
	fs.IntVar(&cfg.blockProfileRate, "block-profile-rate", envInt("ELCHI_SHIELD_BLOCK_PROFILE_RATE", 0), "runtime.SetBlockProfileRate (0=off; e.g. 10000 = ~1 sample/10µs blocked)")
	fs.IntVar(&cfg.mutexProfileFrac, "mutex-profile-fraction", envInt("ELCHI_SHIELD_MUTEX_PROFILE_FRACTION", 0), "runtime.SetMutexProfileFraction (0=off; 1=every event)")
	fs.Int64Var(&cfg.memLimitBytes, "mem-limit-bytes", envInt64("ELCHI_SHIELD_MEM_LIMIT", 0), "soft memory limit (GOMEMLIMIT) in bytes; GC reins in before OOM (0=unset; honors GOMEMLIMIT env too)")
	fs.DurationVar(&cfg.shutdownTimeout, "shutdown-timeout", envDuration("ELCHI_SHIELD_SHUTDOWN_TIMEOUT", 15*time.Second), "graceful shutdown timeout")

	showVersion := fs.Bool("version", false, "print version and exit")

	// flag.ExitOnError handles parse errors; ignore the returned error.
	_ = fs.Parse(args)

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	return cfg
}

// stringList is a flag.Value that accumulates repeated string flags.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// listeners parses the ext_proc listeners. With no --extproc-listener flags it
// falls back to a single listener from --extproc-network/--extproc-addr/
// --listener-id. Each spec is "id=network:addr", e.g.
// "lst-public-443=unix:/etc/elchi/elchi-shield/lst-public-443.sock".
func (c appConfig) listeners() ([]extproc.ListenerSpec, error) {
	if len(c.extprocListeners) == 0 {
		if c.extprocNetwork == "tcp" && !c.allowNonLoopback && !isLoopbackTCP(c.extprocAddr) {
			return nil, fmt.Errorf("--extproc-addr %q binds non-loopback TCP; the sidecar must not be exposed externally (use a unix socket, or --allow-non-loopback to override)", c.extprocAddr)
		}
		return []extproc.ListenerSpec{{ID: c.listenerID, Network: c.extprocNetwork, Addr: c.extprocAddr}}, nil
	}
	out := make([]extproc.ListenerSpec, 0, len(c.extprocListeners))
	for _, raw := range c.extprocListeners {
		id, rest, ok := strings.Cut(raw, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --extproc-listener %q: want id=network:addr", raw)
		}
		network, addr, ok := strings.Cut(rest, ":")
		if !ok || (network != "unix" && network != "tcp") || addr == "" {
			return nil, fmt.Errorf("invalid --extproc-listener %q: want id=unix:/path or id=tcp:host:port", raw)
		}
		if network == "tcp" && !c.allowNonLoopback && !isLoopbackTCP(addr) {
			return nil, fmt.Errorf("ext_proc listener %q binds non-loopback TCP %q; the sidecar must not be exposed externally (use unix sockets, or --allow-non-loopback to override)", id, addr)
		}
		out = append(out, extproc.ListenerSpec{ID: strings.TrimSpace(id), Network: network, Addr: addr})
	}
	return out, nil
}

// isLoopbackTCP reports whether a "host:port" address binds a loopback interface
// only. An empty/wildcard host (":port", "0.0.0.0:port") or a non-localhost
// hostname is treated as non-loopback (exposed).
func isLoopbackTCP(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// defaultInstanceID derives "<hostname>-shield" so each machine's metrics, logs,
// and audit events are attributable and never mixed. Falls back to "shield" when
// the hostname is unavailable.
func defaultInstanceID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "shield"
	}
	return host + "-shield"
}

// splitList splits a comma-separated env value into non-empty trimmed items.
func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envFloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}
