# elchi-shield — Performance

How elchi-shield performs, how to measure it, where the cost actually is, and how
to tune for throughput. Numbers below are from an Apple M-series dev machine
(10 cores, Go 1.26); treat them as relative, not absolute — re-run on your
hardware with the commands shown.

## How to measure

```sh
make bench       # hot-path micro-benchmarks (matchers, resolver, pipeline)
make loadtest    # end-to-end gRPC throughput over an in-memory transport
make profile     # CPU + alloc profiles of the load path → cpu.prof / mem.prof
```

- **Micro-benchmarks** isolate the engine's hot path (policy resolution, stage
  execution) with no transport.
- **Load harness** (`internal/server/extproc/load_test.go`) drives the *real*
  gRPC ext_proc server over `bufconn` (in-memory), one stream per request, so it
  includes serialization and streaming overhead — the way Envoy actually calls us.

## Results

### Engine hot path (no transport) — `make bench`

| Operation | ns/op | allocs/op |
|---|---:|---:|
| Host match (exact/wildcard) | ~10 | **0** |
| Path prefix match | ~2 | **0** |
| **Policy resolve** (multi-domain, multi-route) | ~55 | **0** |
| Pipeline run, 9-stage continue | ~420 | **1** (the returned `*Decision`) |
| Transaction pool acquire/release | ~9 | **0** |

The engine touches only immutable, pre-compiled data: one atomic snapshot load,
indexed host lookup, a small matcher sweep, and a lock-free stage chain. The
single allocation per request is the returned decision.

### End-to-end gRPC — `make loadtest`

| Path | ns/op | req/s | allocs/op |
|---|---:|---:|---:|
| Baseline (no policy match, default allow) | ~9,100 | ~116k | ~161 |
| Header checks (block mode, clean request) | ~9,000 | ~118k | ~164 |

## Where the cost is (bottleneck analysis)

The engine logic (resolve + pipeline) is **sub-microsecond** — roughly
`55ns + 420ns ≈ 0.5µs`. The end-to-end cost is **~9µs**, of which ~95% is the
gRPC stream lifecycle and protobuf encode/decode of the ext_proc messages (one
bidirectional stream per HTTP request is inherent to ext_proc). The ~160
allocs/op are almost entirely gRPC framing + protobuf, **not** policy evaluation.

**Conclusion:** elchi-shield's inspection engine is not the bottleneck — the
ext_proc transport is. Adding header checks barely moves throughput (118k vs
116k req/s) because the checks are negligible next to the round-trip. This is by
design: all parsing/compilation/regex happens at config-load time, leaving the
hot path lock-free and allocation-lean.

A deliberate non-optimization: pooling the one per-request `*Decision` would save
~30ns out of ~9,000ns (<0.5%) at the cost of lifetime complexity — not worth it
until a profile says otherwise.

### Cutting ext_proc round-trips (the biggest lever)

Since the transport is the cost, the highest-leverage win is sending **fewer
ext_proc messages per request**. The static Envoy mode sends response headers to
shield for every request, but most policies inspect only the request. Shield now
sets `ResponseHeaderMode: SKIP` in the request-headers `mode_override` whenever
`CompiledPolicy.NeedsResponseInspection()` is false (no `inspect_response_body`,
no DLP on the response, no response-inspecting engine), so Envoy skips the entire
response phase — eliminating ~half the ext_proc round-trips for the common case.
Response-inspecting policies (Coraza, response DLP, response-body checks) keep the
phase (header send-modes default to `DEFAULT` = use the static config; `SKIP` is
explicit), so no inspection capability is lost.

Other capability-neutral wins on this path: the request-headers mode overrides and
the no-mutation CONTINUE responses are shared immutable singletons (no per-request
alloc); the random request-id is minted only when Envoy omits `x-request-id`; and
the gRPC server uses larger HTTP/2 windows + a 128 KiB read buffer.

A vtproto codec was evaluated and **rejected**: go-control-plane's generated
vtproto ships marshal+size but **no `UnmarshalVT`**, so it can't accelerate the
dominant `ProcessingRequest` decode — only the already-small (and now cached)
response marshal. Not worth a custom codec for that.

### Real-traffic load test — `make loadtest-real`

A REAL Envoy proxies sustained traffic through shield to an echo upstream; a
closed-loop driver reports req/s + p50/p99 (see `test/loadtest`). On a single
10-core box (Envoy + driver + upstream co-resident, so absolute numbers are
single-box end-to-end, not a per-core ceiling): passthrough ~39k req/s (p50
~0.9ms), header-only ~31k, body-inspecting ~23k. The response-phase skip lifts
passthrough ~30% over the pre-optimization baseline; the gain is larger off-box
where shield doesn't share cores with the load generator.

## Tuning for best performance

1. **Use a Unix domain socket** (`--extproc-network unix`), not loopback TCP —
   fewer syscalls per stream; it is the default.
2. **Keep body inspection off unless needed.** Body buffering is gated per
   policy; the default (headers only) avoids all body allocation and a second
   ext_proc round-trip. Only set `inspect_request_body` / engines that need the
   body where you actually inspect it.
3. **Scope WAF engines narrowly.** Coraza is the most expensive stage; bind it
   only to routes that need it (per-policy engines make this natural). Order
   cheaper inspectors first with `policy.pipeline` so the chain short-circuits
   early.
4. **Sample audit under load.** `--audit-max-per-sec` caps the non-finding audit
   stream (findings are always recorded), and the audit exporter is async +
   bounded, so it never back-pressures the request path.
5. **GOMAXPROCS is automatic.** Go 1.25+ is cgroup-aware and sizes `GOMAXPROCS`
   from the container CPU limit; no manual tuning or `automaxprocs` dependency.
   Set a CPU *limit* (not just a request) for it to apply. Concurrency is
   lock-free, so it scales with the cores it's given.
6. **Detect/shadow modes** cost the same as block to evaluate but never issue an
   ImmediateResponse, so they add no transport cost beyond a normal allow.

## Regression guarding

`make bench` numbers are the guardrail for the engine hot path; a change that
adds an allocation to the continue path or to policy resolution should be
treated as a regression and justified with a benchmark.
