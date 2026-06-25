# elchi-shield — Concurrency, parallelism & listener isolation

This document answers: *is elchi-shield safe and fast under parallel load, do
listeners block each other, and should each listener run its own thread?* Short
answer: it is parallel and lock-free on the request path by design, and one
process runs an isolated gRPC server per Envoy listener.

## "A thread per listener / per HCM?" — the Go model

You don't manage threads in Go; you write **goroutines**, which the runtime
multiplexes M:N onto `GOMAXPROCS` OS threads. gRPC already runs **one goroutine
per ext_proc stream**, i.e. one per HCM request. Goroutines are far cheaper than
OS threads (a few KB, grown on demand), so "a thread per request" is effectively
what you get — only lighter and scheduled across all cores. Requests therefore
run in parallel and do **not** wait on each other for policy evaluation.

So the useful questions are not "threads vs goroutines" but: *are there shared
locks or bounded resources that serialize requests across listeners, and are
there leaks?* Those we address explicitly below.

## Per-listener isolation (one process, separate servers)

A single elchi-shield process runs **one gRPC server per Envoy listener**
(`internal/server/extproc/manager.go`), each on its own socket with its own
accept loop and HTTP/2 connections, configured via repeatable
`--extproc-listener id=network:addr`. They share the **same lock-free** runtime
`Store`, stage `Catalog`, `Transaction` pool, `Metrics`, and `Auditor` — so there
is no config duplication and no added locks, but a busy listener's accept queue
and connection flow-control never touch another's. Request-level metrics carry a
`listener` label so per-listener load is visible.

## The request hot path is lock-free

Per request, in order:

| Step | Mechanism | Lock? |
|---|---|---|
| Pin active config | `runtime.Store` `atomic.Pointer.Load` | none |
| Acquire `Transaction` | `sync.Pool` (per-P sharded) | none |
| Resolve policy | immutable maps/slices in the snapshot | none |
| Per-policy pipelines | built once via `sync.Once`, then read | one-time only |
| Run stages | immutable, precompiled stage chain | none |
| Record metrics | per-listener **pre-curried** counters (atomic) | none |
| Audit | lock-free `Sample` + non-blocking channel send | none |

The two locks that *used* to sit on the request goroutine were removed:
- **Metrics label lookup**: stage and per-listener counters are pre-registered at
  startup (`Metrics.RegisterStages`, `Metrics.ForListener`) into frozen,
  read-only structures, so the hot path never takes the Prometheus map lock.
- **Audit rate cap**: the global events/sec cap moved off the request goroutine
  into the audit workers; the request path only does a lock-free sample + a
  non-blocking enqueue.

## gRPC tuning (the real throughput cap)

gRPC-Go defaults `MaxConcurrentStreams` to **100 per HTTP/2 connection** (a
rapid-reset CVE mitigation aimed at untrusted clients). Envoy is a local trusted
peer, so we raise it to a high value (`DefaultMaxConcurrentStreams`,
`serve.go`), preventing a busy listener from queueing its own 101st concurrent
request. We also enable a shared write-buffer pool and keepalive so connections
stay healthy instead of churning.

## Locking inventory (the whole binary)

| Lock | Where | On request path? |
|---|---|---|
| `atomic.Pointer` (Store) | hot path | yes, lock-free |
| `sync.Pool` (Transaction) | hot path | yes, lock-free |
| `sync.Once` (per-policy compile) | first request per policy | one-time |
| Prometheus internal | only at startup (pre-registration) | no |
| `RateLimiter` mutex | audit workers only | no |
| ClickHouse exporter batch mutex | audit workers + its flush ticker | no (off the request path) |
| audit channel | non-blocking send (request) / drain (workers) | send is lock-free-ish, never blocks |

## Memory & goroutine leak safety

- **Per-stream goroutines** end when the stream ends.
- **Fixed goroutines**: one `Serve` per listener, N audit workers, the watcher,
  the http server — all bounded and stopped on shutdown.
- **Snapshot retirement**: on reload the previous snapshot's engines are closed
  after a grace period via a short-lived goroutine; bounded by reload frequency.
- **Per-snapshot GC**: a retired snapshot's resolver, policies, compiled
  pipelines, and engines become unreachable together and are collected — the
  `sync.Once` pipeline cache lives on the policy, so it dies with the snapshot.
- **Bounded audit queue**: events beyond capacity are dropped (and counted), so
  the queue can't grow without bound under overload.
- **Audit close is race-free by construction**: `BufferedExporter` never closes
  its data channel (which would race a concurrent `Export` send); it signals a
  `done` channel, workers drain the buffer and exit, and `Close` is idempotent.
  `Export` checks `done` and drops rather than blocking. Verified under `-race`.

This is verified by `TestStressConcurrentListenersWithReloads`
(`internal/server/extproc/stress_test.go`): multiple listeners under concurrent
request load while snapshots are swapped continuously, asserted under `-race`
with a goroutine-count settle check (no race, no deadlock, no leak).

## Tuning knobs

- **Listeners**: give each Envoy listener its own `--extproc-listener` socket for
  full isolation.
- **GOMAXPROCS**: Go **1.25+ is cgroup-aware** — the runtime auto-derives
  `GOMAXPROCS` from the container's CPU *limit* (rounding up, min 2) and re-checks
  it periodically, so the uber `automaxprocs` dependency is unnecessary. The
  effective value is logged at startup; `NumStreamWorkers` and the audit-worker
  count derive from it. Caveat: this only triggers under a CPU *limit* (not just a
  request) — set a CPU limit or the `GOMAXPROCS` env if you need to cap it.
- **GOMEMLIMIT**: `--mem-limit-bytes` (or the `GOMEMLIMIT` env) sets a soft memory
  limit so the GC reins in before the kernel OOM-kills the sidecar under a body
  burst. Set it well above `--max-inflight-body-bytes` (≥2×) or the GC thrashes;
  startup warns if it's too close.
- **Audit**: `--audit-max-per-sec` caps the allow stream; the workers are
  multi-goroutine so export throughput scales.

See [`docs/PERFORMANCE.md`](PERFORMANCE.md) for throughput numbers and the
finding that the gRPC transport, not the engine, dominates per-request cost.
