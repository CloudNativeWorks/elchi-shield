# elchi-shield

A **local Envoy `ext_proc` API-security engine**. It runs as a sidecar next to
Envoy on the client machine, inspects request/response headers and (optionally)
bodies through an ordered, Envoy-style **security filter pipeline**, and returns
allow / block / detect / shadow decisions.

- **Local only.** It never runs in the control plane and never forwards
  data-plane traffic off-box. The management plane (Elchi Client Agent) only
  writes config **files**; this service watches the directory and hot-reloads.
- **Pluggable.** Built-in checks ship today; heavier engines (Coraza, OpenAPI
  validation, JWT policy, custom detectors) plug in behind one `SecurityEngine`
  interface and can run together per request.
- **Production-grade.** Lock-free hot path, atomic config swaps, keep-last-good
  on bad config, structured logs, Prometheus metrics, and audit.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design

## How it works

```
Elchi Client Agent ──writes──▶ /etc/elchi-shield/conf.d/*.yaml
                                        │ (watched, debounced, hot-reloaded)
downstream ─▶ Envoy ──ext_proc gRPC──▶ elchi-shield ─▶ allow / block(403)
                 │
                 ▼ upstream
              backend
```

Each request flows through a precompiled filter chain that short-circuits as
early as possible (cheapest, most-discriminating checks first):

```
context init → policy resolve → fast pre-checks → early decision
            → body gate → body checks → WAF engine(s) → decision
```

Body and WAF inspection run **only** when the matched policy (or an enabled
engine) requires them. Response inspection is a separate pipeline. The active
config snapshot is pinned per stream, so a reload never tears a decision.

## Build & test

```sh
make build        # → bin/elchi-shield (version from VERSION, commit from git)
make test         # go test ./...
make race         # go test -race ./...
make bench        # hot-path benchmarks (-benchmem)
make fuzz         # fuzz smoke (config parse, matchers, decode stage)
make vuln         # govulncheck ./...
make lint         # golangci-lint
make docker       # local from-source image (deploy/Dockerfile)
```

Requires Go 1.26+ (build/release with **1.26.4+** for the patched stdlib).

## Versioning & release

The version lives in the **`VERSION`** file (e.g. `0.1.0`) — the single source of
truth, consumed by `make build` and the release workflow (same flow as the
sibling `elchi-backend` / `elchi-collector`).

To cut a release: bump `VERSION`, commit, then run the **Create Release** GitHub
Action (manual `workflow_dispatch`). It:

1. builds the static AMD64 binary (`-ldflags "-X main.version=vX.Y.Z -X main.commit=<sha>"`),
2. tags `vX.Y.Z`, creates a GitHub Release with the binary + `.sha256` + source archive,
3. dispatches **Build and Push Image**, which bundles that exact binary into a
   distroless image (`deploy/Dockerfile-release-binary`, no recompile), pushes
   `:vX.Y.Z` and `:latest` to Docker Hub, and Trivy-scans for HIGH/CRITICAL CVEs.

The injected version/commit surface at runtime in the startup log, the
`elchi_shield_build_info` metric, and `/configz`. Required CI secrets: `GH_PAT`,
`DOCKER_USERNAME`, `DOCKER_PASSWORD`.

## Run

```sh
elchi-shield \
  --config-dir /etc/elchi/elchi-shield/conf.d \
  --extproc-network unix --extproc-addr /etc/elchi/elchi-shield/extproc.sock \
  --http-addr 127.0.0.1:9001
```

Defaults live under `/etc/elchi/elchi-shield` (the elchi stack's convention).
Key flags (all also settable via `ELCHI_SHIELD_*` env vars):

| Flag | Default | Purpose |
|---|---|---|
| `--instance-id` | `<hostname>-shield` | identity stamped on metrics/logs/audit |
| `--config-dir` | `/etc/elchi/elchi-shield/conf.d` | watched config directory |
| `--extproc-network` | `unix` | `unix` (preferred) or `tcp` (single-listener) |
| `--extproc-addr` | `/etc/elchi/elchi-shield/extproc.sock` | single-listener address / socket |
| `--extproc-listener` | — | repeatable `id=network:addr` for per-listener isolation |
| `--http-addr` | `127.0.0.1:9001` | health + metrics address |
| `--listener-id` | `""` | Envoy listener this instance serves (optional scope) |
| `--max-body-bytes` | `1048576` | fallback body cap when a policy sets none |
| `--watch-debounce` | `300ms` | config watcher debounce window |
| `--default-allow` | `true` | posture when no policy matches (`false` = deny) |
| `--audit-exporter` | `""` | `none`\|`file`\|`clickhouse`\|`otel` |
| `--audit-file` | `""` | NDJSON path for the `file` exporter |
| `--audit-clickhouse-dsn` | `""` | ClickHouse DSN (clickhouse exporter) |
| `--audit-otel-endpoint` | `""` | OTLP endpoint (otel exporter) |
| `--audit-max-per-sec` | `0` | dynamic-sampling cap on non-finding audit events/sec (0 = unlimited) |
| `--log-level` / `--log-format` | `info` / `json` | logging |

The service starts safely with **no config** (empty snapshot, default posture)
and restores the last config from disk on restart.

## Endpoints

All on the loopback HTTP server (`--http-addr`):

- `GET /healthz` — liveness
- `GET /readyz` — readiness (non-empty valid config)
- `GET /metrics` — Prometheus (namespace `elchi_shield`): `requests_total`,
  `requests_allowed_total`, `requests_blocked_total`, `detections_total`,
  `shadow_detections_total`, `config_reload_success_total`,
  `config_reload_failure_total`, `active_config_version`,
  `processing_latency_seconds{phase}`, `body_inspected_bytes_total`,
  `extproc_errors_total`, `timeouts_total`, `fail_open_total`, `fail_close_total`,
  `build_info`, `config_age_seconds`, `streams_in_flight`, `inflight_body_bytes`,
  the standard `go_*`/`process_*` collectors, plus per-stage latency/action.
- `GET /configz` — active config version/hash/sources/age + build metadata
- `GET /policyz?host=&path=&method=&content_type=&listener=` — **decision
  explainability**: which policy resolves for a request shape, its mode, and the
  exact effective inspector stage order + engine names ("why this verdict?").
  Structure only — no secrets/rules/payloads.
- `GET /debug/pprof/*` — profiling (`--pprof`, default on; loopback-only)

## Configuration

Kubernetes-style documents (`apiVersion`/`kind`/`metadata`/`spec`). Multiple
files are merged deterministically; one file may hold many domains. See
[`configs/examples/`](configs/examples/). Minimal example:

```yaml
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: api-public }
spec:
  defaults: { mode: block, fail_mode: fail_open, timeout: 50ms }
  domains:
    - host: "api.example.com"
      listener_id: "lst-public-443"
      routes:
        - match: { path_prefix: "/v1/", methods: [GET, POST] }
          policy:
            mode: block
            inspect_request_body: true
            max_request_body_bytes: 524288
            checks:
              headers: { required: ["X-Request-Id"], forbidden: ["X-Debug"] }
              body:    { require_json: true }
```

**Modes:** `block` (enforce, 403), `detect` (record + allow), `shadow` (record
would-block + allow), `off` (skip). **Precedence:** exact host > wildcard;
listener-scoped > unscoped; exact path > regex > longest prefix.

Invalid config never affects live traffic — the last valid config stays active
and the failure is logged with the offending file and field.

## Security engines (pluggable, per-policy)

Beyond the built-in header/body checks, a policy may run one or more pluggable
engines via the `SecurityEngine` interface; they run in config order and
aggregate with "most severe wins". Engines are compiled **per policy**, so
different domains/routes can run different engines (e.g. different JWT issuers).

- **JWT** (built in): validates `Authorization` JWTs — signature (HMAC/PEM
  public key), issuer, audience, expiry, required claims, clock-skew leeway.
  Configure under `policy.engines.jwt`.
- **Rate limit** (built in): per-key token-bucket (by client IP, host, or a
  header), returns `429` + `Retry-After` when exceeded. Header-phase (no body
  buffering). The client IP comes from the once-derived `X-Forwarded-For`/
  `X-Real-IP`. Configure under `policy.engines.rate_limit`:
  ```yaml
  engines:
    rate_limit: { requests_per_second: 100, burst: 200, key: ip }  # key: ip|host|header
  ```
  **State-sharing follows inheritance:** a domain-level `rate_limit` inherited by
  several routes is one combined limiter across them; a route-level one is
  independent. Define the limit at the scope it should apply.
- **Coraza WAF**: full ModSecurity-style WAF. Configure under
  `policy.engines.coraza`. Always compiled into the binary.

### Per-policy stage ordering

Each policy can set `pipeline.request` / `pipeline.response` — an ordered list of
inspector stages (`fast_pre_checks`, `body_checks`, `waf_engine`). The order is
honored exactly (e.g. run `waf_engine` before `body_checks`); **omitting** a name
disables that stage. Only physically-impossible orders are rejected (a body
inspector still needs the buffered body). New inspectors register in the stage
**catalog** and immediately become orderable — the system's main extension point.
See [`configs/examples/api-jwt.yaml`](configs/examples/api-jwt.yaml).

## Identity & performance

Each instance derives `<hostname>-shield` (override with `--instance-id`) and
stamps it on every metric (`instance=` label), log record, and audit event, so
data from many machines never mixes. See
[`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) for throughput numbers and the
bottleneck analysis (the transport, not the engine, dominates).

**Concurrency.** One process runs an isolated gRPC server per Envoy listener
(repeatable `--extproc-listener`), sharing the lock-free config. Every request is
a goroutine (parallel, M:N over `GOMAXPROCS`); the request path is lock-free and
leak-free, proven under `-race`. See
[`docs/CONCURRENCY.md`](docs/CONCURRENCY.md) — including why "a thread per
listener" is unnecessary and the gRPC 100-stream cap we remove.

## Engines and audit sinks

There are no build tags: a single full binary always compiles in every engine
(including the Coraza WAF, OpenAPI validator, and RFC 9421 httpsig) and every
audit sink (ClickHouse, OTEL). Just configure what you need; an engine or sink is
available out of the box.

## Envoy wiring

Add the ext_proc HTTP filter pointing at this service — see
[`configs/examples/envoy/envoy-extproc.yaml`](configs/examples/envoy/envoy-extproc.yaml).

**See it work end-to-end:** `make e2e` runs a **real Envoy** that proxies HTTP
through elchi-shield to an echo upstream and asserts allow(200) / block(403) /
rate-limit(429) per a sample policy (uses `func-e` to fetch Envoy, or set
`ENVOY=/path/to/envoy`). See [`test/e2e/`](test/e2e/).

## Security

- Secrets are never logged: audit events carry only decision metadata
  (no header values, no body). `internal/redaction` masks `Authorization`,
  `Cookie`/`Set-Cookie`, API keys, and bearer/JWT values for any future
  value logging.
- Resource bounds everywhere: header-size, body-size (bounded buffering with
  over-limit blocking), and per-policy timeouts.
- Explicit, per-policy fail posture (`fail_open` / `fail_close`).
- **Loopback-only by default**: non-loopback TCP binds (ext_proc and http) are
  refused unless `--allow-non-loopback` is set — the sidecar is never exposed
  externally. UDS (the default) is local by construction with `0660` perms.
- Panic-safe: a panic (incl. in a 3rd-party engine) is recovered per stream and
  never crashes the process.
- Per-request timeout from `policy.timeout`; over-limit bodies are blocked
  non-skippably; engines fail closed on inspection errors.

## Status

Phases 0–9 complete: core engine, Envoy-style filter pipeline, ext_proc server,
file-driven hot reload, observability (metrics/health/audit), hardening, plus the
pluggable JWT and Coraza engines, ClickHouse/OTEL audit sinks, and tuning
(per-policy `skip_stages`, dynamic audit sampling). Default + tagged builds are
green; `go test`/`-race`/`vet`/`golangci-lint` clean.
