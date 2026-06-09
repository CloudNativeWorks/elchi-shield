# elchi-shield — Architecture

`elchi-shield` (a.k.a. `elchi-api-security-agent`) is a **local Envoy `ext_proc`
API-security / WAF engine**. It runs as a sidecar on the client machine next to
Envoy. It never runs in the central management plane and never forwards
data-plane traffic anywhere — all inspection happens locally.

---

## 1. System context

```
                ┌────────────────────── client machine ──────────────────────┐
                │                                                             │
  downstream    │   ┌─────────┐   ext_proc gRPC    ┌───────────────────────┐  │
  client  ─────────▶│  Envoy  │◀──────────────────▶│      elchi-shield        │  │
                │   └────┬────┘  (headers/body)     │  (this service)       │  │
                │        │                          │                       │  │
                │        ▼ upstream                 │  - ext_proc server    │  │
                │   ┌─────────┐                     │  - http (health/      │  │
                │   │ backend │                     │     metrics) server   │  │
                │   └─────────┘                     │  - config watcher     │  │
                │                                   └──────────┬────────────┘  │
                │                                              │ reads          │
                │                            ┌─────────────────▼────────────┐  │
                │   elchi-client  ─writes──▶ │  /etc/elchi-shield/conf.d/*.yaml │  │
                │   (mgmt plane agent)       └──────────────────────────────┘  │
                └─────────────────────────────────────────────────────────────┘
```

- **Management plane distributes config only.** `elchi-client` writes/updates
  config files into a local directory. It does **not** call this service's API
  per config change.
- **Data-plane traffic stays local.** Envoy talks to `elchi-shield` over a local
  socket (UDS preferred, or loopback TCP). Nothing is exported except
  metrics/audit (optionally).

---

## 2. Component map (package responsibilities)

| Package | Responsibility | Hot path? |
|---|---|---|
| `cmd/elchi-shield` | Process entrypoint, flag/env parsing, dependency wiring, lifecycle | no |
| `internal/config` | On-disk schema types, parse (YAML/JSON), validate, merge | reload only |
| `internal/watcher` | fsnotify dir watcher + debounce; emits "reload requested" | reload only |
| `internal/runtime` | Immutable compiled `Snapshot`; `atomic.Pointer` store; version/hash | **load (read)** |
| `internal/policy` | Policy model + compiled policy representation | **yes** |
| `internal/matcher` | Compiled matchers (host, path, method, header, content-type) | **yes** |
| `internal/pipeline` | Filter-chain framework: `Stage`, `Transaction`, executor | **yes** |
| `internal/pipeline/stages` | Concrete stages (pre-checks, body gate, WAF, final, audit) | **yes** |
| `internal/engine` | `SecurityEngine` interface + built-in checks; Coraza plug point | **yes** |
| `internal/decision` | Decision value types (allow/block/continue/log/shadow) | **yes** |
| `internal/server/extproc` | ext_proc gRPC server + per-stream state machine | **yes** |
| `internal/server/http` | `/healthz`, `/readyz`, `/metrics` | no |
| `internal/audit` | Structured audit events, sampling, exporter interface (file, CH stub) | yes (async) |
| `internal/metrics` | Prometheus collectors | yes |
| `internal/logging` | `slog`-based structured logger factory | no |
| `internal/redaction` | Redact tokens/authorization/cookies/passwords/secrets | yes |
| `internal/testutil` | Shared test helpers, fixtures, fakes | tests |
| `configs/examples` | Example config files | n/a |

**Design rule:** the hot path (`extproc` → `runtime.Load` → `matcher` →
`policy` → `engine` → `decision`) touches only **immutable, pre-compiled**
data. All parsing/compilation/validation happens off the hot path during reload.

---

## 3. Core data-flow / state model

There are two strictly separated worlds:

### 3.1 Config world (cold path, mutable, off-hot-path)
`OnDiskConfig` (raw YAML/JSON) → **merge** → `MergedConfig` → **validate** →
**compile** → `runtime.Snapshot` (immutable).

### 3.2 Runtime world (hot path, immutable, lock-free reads)
A single `*runtime.Snapshot` is held in an `atomic.Pointer[Snapshot]`.
- Readers (every request) do one atomic load — no locks, no allocation.
- Writer (reload) builds a brand-new `Snapshot` and atomically swaps the
  pointer. The old snapshot keeps serving in-flight requests until GC.

This gives **atomic config reloads** with **zero reader contention** and
guarantees **invalid config never affects active traffic**.

---

## 4. Runtime flow (startup)

```
main()
 ├─ parse flags/env  ──► AppConfig (paths, listen addrs, limits)
 ├─ build logger (slog)
 ├─ build metrics registry
 ├─ runtime.Store := atomic.Pointer[Snapshot]  (initially empty Snapshot)
 ├─ try load initial config from dir:
 │     success ─► Store.Set(snapshot)         (start with last valid config)
 │     failure ─► Store stays empty + log     (safe startup with no config = fail-open default)
 ├─ start ext_proc gRPC server (UDS/TCP)
 ├─ start http server (health/metrics)
 ├─ start watcher goroutine ──► on event: reload pipeline (§5)
 └─ block until SIGINT/SIGTERM ─► graceful shutdown (drain gRPC, stop watcher, flush audit)
```

**Safe startup with no config:** service comes up `ready` but in a configurable
default posture (default: continue/allow = fail-open) so it never blackholes
traffic before the first config lands. Posture is overridable by flag.

---

## 5. Config reload flow (cold path)

```
fsnotify event(s)
   │  (create/write/rename/remove in conf.d)
   ▼
debounce window (e.g. 300ms; coalesce bursts from multi-file writes)
   ▼
ReadAll(dir)         ── read every *.yaml/*.yml/*.json
   ▼
Parse each file      ── strict decode; collect per-file errors
   ▼
Merge                ── deterministic order (sorted filename); detect domain/listener collisions
   ▼
Validate             ── schema + semantic rules; detailed, file-attributed errors
   ▼  (any error here ⇒ ABORT: keep current Snapshot, bump reload_failure metric, log why)
   ▼
Compile              ── build matchers (regex compiled once), policy index, engine instances
   ▼
Hash + Version       ── content hash → version id
   ▼
atomic swap          ── Store.Set(newSnapshot)
   ▼
metrics/version update + structured "config reloaded" log
```

**Guarantees:**
- Old valid config stays active if new config fails parse/validate/compile.
- Reload is atomic and safe under high concurrency (single-writer swap).
- Each failure is attributable to a file + reason for debuggability.

---

## 6. Request processing flow (hot path) — filter pipeline

Request processing is **not** a monolithic function. It is an ordered, Envoy-like
**security filter chain**: a request flows through composable, precompiled
*stages* that short-circuit as early as possible. Cheap checks run before
expensive ones; body and WAF inspection are gated by policy; response inspection
is a **separate** pipeline. See §6a for the framework; this section is the flow.

ext_proc is a **bidirectional stream**. One stream = one HTTP transaction. The
snapshot and a pooled `Transaction` are pinned at stream start, then the request
pipeline runs:

```
stream opened ─► snapshot := Store.Load()  (pinned) ─► tx := pool.Acquire()
   ▼
REQUEST PIPELINE (stop at the first stage that denies/allows-terminal):
  1 ContextInit    request id · extract listener/host/path/method/headers/ct · deadline
  2 PolicyResolve  match listener/domain/route → most-specific policy (else default posture)
  3 FastPreChecks  method · host · header count/size · forbidden/required · ct · IP   [no body]
  4 EarlyDecision  allow-no-inspect → continue · block → DENY · detect/shadow → record+continue
  5 BodyGate       body needed?  enforce max size BEFORE buffering · skip gRPC/large uploads
  6 BodyChecks     (gated) JSON syntax · schema hook · sensitive-data hook · size/content
  7 WAFEngine      (gated) pluggable engine(s) · mode off/detect/shadow/block · exclusions
  8 FinalDecision  aggregate verdicts · severity→action · fail-open/close · emit decision
  9 AuditMetrics   async where possible · redacted · never blocks unless configured
   ▼
decision ─► ext_proc response: DENY → ImmediateResponse(403); else CONTINUE
            (shadow/detect record a "would-block" event but CONTINUE)

RESPONSE PIPELINE (separate, reuses pinned request policy via tx):
  resp ContextInit → resp PolicyLookup → header checks → BodyGate → resp BodyChecks
  → sensitive-data leakage checks → FinalDecision → AuditMetrics
```

**Key choices:**
- Snapshot + Transaction are **pinned at stream start** so config swaps never
  tear a single transaction's decisions.
- **Reject early:** the order is cheapest-and-most-discriminating first, so bad
  traffic is denied before any body is read or any engine runs.
- **Gating:** body/WAF stages run *only* when the resolved policy (or an enabled
  engine) requires them — default is **no body buffering**, keeping the common
  path allocation-free.
- `fail_open` / `fail_close` per policy governs behavior on stage error/timeout;
  applied centrally by the executor, never per-stage.

---

## 6a. Pipeline model (the framework)

A **`Stage`** is a small, stateless, precompiled unit; all per-request state is
in the `Transaction`. Stages are reusable across request/response via
`tx.Direction`.

```go
type Stage interface {
    Name() string
    Phase() Phase   // PreCheck | BodyGate | Body | WAF | Final | Audit
    Process(ctx context.Context, tx *Transaction) StageResult
}

type StageAction uint8 // Continue, Allow, Deny, ShadowDetect, SkipBody, SkipRemaining, Error
type StageResult struct {        // tiny, returned by value
    Action   StageAction
    Decision *decision.Decision  // only on terminal/recorded decisions
    Err      error               // only on Error
}
```

Audit **events accumulate on the `Transaction`** (a pooled, request-scoped
object), not in `StageResult` — this keeps the hot-path result allocation-free
and lets the executor return `{Action: Continue}` by value.

**Executor (`Pipeline.Run`)** owns the cross-cutting concerns so stages stay
trivial:
- iterate the immutable `[]Stage` in order; short-circuit on `Deny` /
  terminal `Allow` / `SkipRemaining`;
- **phase gating:** `SkipBody` (or `!tx.bodyRequired`) skips `Body`/`WAF` stages;
- **panic recovery** around each `Process` → converted to `ActionError`;
- **deadline** check before each stage (context timeout from policy);
- **fail posture:** `ActionError` → policy `FailOpen` (continue) or `FailClose`
  (deny);
- **mode→action mapping:** `detect`/`shadow` never actually block — a would-block
  is recorded and the request continues;
- **per-stage metrics + latency** via an injected `Observer` (no-op until wired).

**Precompiled & immutable:** no per-request stage construction, regex
compilation, or policy parsing in the hot path.

**Catalog + per-policy ordering.** Because the effective policy (and thus its
stage order) is only known *after* policy resolution, the server runs a fixed
**prelude** (ContextInit → PolicyResolve → EarlyDecision), then the resolved
policy's **inspect** pipelines. Inspect pipelines are compiled from the policy's
ordered inspector names (`policy.pipeline.{request,response}`) against a
**`stages.Catalog`** (name → Stage) and cached on the `CompiledPolicy` (lazy,
once). The order is honored exactly (e.g. WAF before native body checks);
omitting a name disables that stage. Registering a new inspector in the catalog
makes it orderable per policy without touching the executor — the system's main
extension point. To avoid a policy↔pipeline import cycle, `CompiledPolicy` stores
the order as plain names plus an opaque `Compiled()` cache.

### Package layering (no cycles; hot leaves stay independent)
```
decision (leaf) · matcher (leaf)
policy   → config, matcher, decision
runtime  → config, policy
audit    → decision (+ redaction later)
pipeline → decision, audit, policy, runtime   (Stage/Result/Action/Transaction/Executor)
engine   → pipeline, decision                 (SecurityEngine over *pipeline.Transaction)
pipeline/stages → pipeline, engine, policy, matcher, runtime, decision, audit
```
`pipeline` never imports `engine`, so `engine` (which needs `Transaction`) imports
`pipeline` without a cycle. Concrete stages live in `pipeline/stages`, the only
place bridging both.

---

## 7. Core interfaces (stable contracts)

```go
// runtime: immutable snapshot, lock-free access.
type Store interface {
    Load() *Snapshot          // hot path; atomic, lock-free
    Set(*Snapshot)            // reload path; atomic swap
}

// matcher: compiled, allocation-free matching.
type Matcher interface {
    Match(req *MatchInput) bool
}

// policy: resolve the winning policy for a request.
type Resolver interface {
    Resolve(in *MatchInput) *CompiledPolicy   // nil ⇒ default policy
}

// engine: pluggable security backend. MULTIPLE engines run per request and
// aggregate ("most severe wins"). Engines are compiled PER POLICY (different
// domains/routes can run different engines). To avoid an import cycle, engines
// take a narrow read-only engine.Request (not the pipeline Transaction), which
// makes the engine package a near-leaf (only `decision`). Built-in: JWT; the
// Coraza adapter registers itself via init (blank-imported in cmd, always
// compiled). Same interface for any future engine.
type SecurityEngine interface {
    Name() string
    RequiresBody() bool                                          // drives body gating
    Inspect(ctx context.Context, req *engine.Request) (Verdict, error) // direction-aware
    Close() error
}

// audit: pluggable sink (file now; ClickHouse, Kafka, OTEL interfaces only).
type Exporter interface {
    Export(ctx context.Context, ev *Event) error
    Flush(ctx context.Context) error
    Close() error
}
```

**Multi-engine pipeline.** A request passes through every engine bound to its
policy, in order. Each returns a `Verdict`; the pipeline aggregates them with a
"most severe wins" rule (block > shadow/detect > continue). A `Decision` carries
the aggregate outcome plus attribution: `reason`, `rule_id`, `policy_id`,
`engine`, and `severity`. `Verdict` and `Decision` are small value types (no
interfaces in the inner loop) to keep the hot path allocation-free.

---

## 8. Config schema (on disk)

Kubernetes-style envelope (apiVersion/kind/metadata/spec). See
`configs/examples/`. Sketch:

```yaml
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata:
  name: api-public
  labels: {team: platform, env: prod}
spec:
  defaults:
    mode: block               # block | detect | shadow | off
    fail_mode: fail_open      # fail_open | fail_close
    max_request_body_bytes: 1048576
    max_response_body_bytes: 0        # 0 = do not inspect
    timeout: 50ms
    log_level: info
    sampling_rate: 1.0
  domains:
    - host: "api.example.com"
      listener_id: "lst-public-443"   # optional scope
      routes:
        - match:
            path_prefix: "/v1/"
            methods: [GET, POST]
          policy:
            mode: block
            inspect_request_body: true
            max_request_body_bytes: 524288
            checks:
              headers:
                forbidden: ["X-Debug"]
                required: ["X-Request-Id"]
              body:
                require_json: true
            skip_checks: ["sqli"]      # selectively disable
        - match:
            path_regex: "^/admin/.*$"
          policy:
            mode: detect
            fail_mode: fail_close
```

### Matching precedence (deterministic; documented algorithm)
Selection of the effective policy, most → least specific:

1. **Host:** exact host beats single-label wildcard (`*.example.com`).
2. **Listener scope:** a domain bound to the request's `listener_id` beats an
   unscoped domain for the same host.
3. **Path within a domain:** exact path > regex > longest matching prefix.
4. **Other predicates** (method / headers / content-type) must all match for a
   route to be eligible; among eligible routes the path rank above decides.

A route's policy is then resolved by inheritance: built-in defaults → file
`defaults` → domain `policy` → route `policy` (narrower wins; `skip_checks`
unions). All of this is computed at compile time into the immutable snapshot;
the hot path only does indexed lookups.

### Policy inheritance (sparse → concrete)
On-disk policies are **sparse** (pointer fields): only set fields override. This
distinguishes "unset" from a meaningful zero (e.g. `max_response_body_bytes: 0`
means *do not inspect*, not *no limit*). Resolution folds the chain into a fully
concrete `ResolvedPolicy` with no pointers, ready for hot-path compilation.

---

## 9. Security considerations

- **No sensitive data in logs by default.** `redaction` strips `Authorization`,
  `Cookie`/`Set-Cookie`, `Proxy-Authorization`, and configurable token/secret
  patterns; bodies are never logged unless explicitly enabled and even then
  redacted + sampled.
- **Strict config decode** (unknown fields rejected) to avoid silent misconfig.
- **Resource bounds everywhere:** header size caps, body size caps, per-policy
  timeouts, and stream-level deadlines prevent memory/CPU exhaustion via
  malicious bodies. No unbounded buffering — body accumulation stops at the cap
  and applies the configured over-limit action.
- **Local-only transport:** UDS with strict file perms preferred; if TCP, bind
  loopback only.
- **Fail posture is explicit and per-policy** so a bug in the engine can't
  silently open or close all traffic globally.
- **No global mutable state**; all shared state is the immutable snapshot.

## 10. Performance considerations

- Lock-free hot path: one `atomic.Pointer` load per stream.
- All regexes compiled once at config load; matchers pre-indexed by host.
- Host lookup via map; path matching via per-host compiled trie/ordered set.
- Zero body buffering unless a policy opts in.
- Reusable buffers via `sync.Pool` for body accumulation; bounded by policy cap.
- Value-type `Decision`/`Verdict`; avoid interface allocs in the inner loop.
- `context` deadlines from per-policy timeout.
- Benchmarks for: host/path matching, policy lookup, header processing, body
  processing — guarded against regression in CI.

## 11. Observability

- Prometheus `/metrics`: request RED (`requests_total`, blocked/detect/shadow,
  `processing_latency_seconds{phase}`), per-stage latency/action, posture
  (fail_open/close, timeouts), `extproc_errors_total{kind}`, config staleness
  (`config_last_reload_success_timestamp_seconds`, `config_age_seconds`,
  `config_reload_failures_consecutive`), live gauges (`streams_in_flight`,
  `inflight_body_bytes`, `audit_queue_depth`, `audit_events_dropped_total`),
  `build_info`, and the standard `go_*`/`process_*` collectors. All series carry
  the `instance` const label.
- `/healthz` (liveness), `/readyz` (has-valid-config), `/configz` (active
  version/hash/sources/age + build), `/policyz?host=&path=&method=...` (decision
  **explainability**: resolved policy + effective stage order + engine names,
  structure-only), `/debug/pprof/*` (loopback, `--pprof`).
- Structured `slog` with component-scoped child loggers (`component=`), a shared
  key vocabulary, and a rich per-phase `decision` log (request_id from Envoy
  `x-request-id`, host/method/path, action, rule/engine/reason/severity,
  status_code, duration_ms). `--log-source` adds file:line.

## 12. Concepts added since v1 (keep this current)

- **Body content-decode** (`stages.bodyContentDecode`): structural, non-skippable,
  runs after the truncation guard. Decompresses gzip/deflate (bomb-bounded,
  charged to the body budget) so the WAF inspects the real payload; blocks
  undecodable/stacked encodings. Closes the compression WAF-bypass.
- **In-flight body budget** (`extproc.bodyBudget`): process-wide cap on buffered
  body bytes across all streams; over-budget bodies are marked truncated → blocked.
- **Body inspected exactly once**: `inspectBufferedBody` runs the body pipeline
  whether EOS lands on headers (empty body), a body chunk, or trailers — guarded
  by `tx.BodyInspected`.
- **Derived client IP** (`tx.SourceIP`): set once in ContextInit from
  X-Forwarded-For/X-Real-IP; the single source of truth engines read (e.g.
  rate-limit), never re-parsed per engine.
- **Rate-limit engine** (`engine/ratelimit`): per-key (ip/host/header) sharded
  token-bucket, header-phase, 429 + Retry-After. Its per-shard mutex is the one
  contained lock (opt-in engine only).
- **Block response** carries `x-elchi-shield: blocked` (+ `Retry-After` on 429).
