# Real-traffic load test

Drives **sustained real HTTP traffic** through a **real Envoy** → elchi-shield →
echo upstream and reports throughput (req/s) and latency percentiles (p50/p90/
p99/p999) for three representative paths.

```
make loadtest-real                       # 10s/scenario, 64 conns
DURATION=30s CONNS=128 make loadtest-real
ENVOY=/path/to/envoy make loadtest-real  # use a specific Envoy binary
```

Needs a real Envoy (auto-fetched via [`func-e`](https://github.com/tetratelabs/func-e),
or set `ENVOY=`). The shield is built as the **lean binary (no build tags)** so the
numbers reflect the production default image.

## Scenarios

| Path | Policy | What it measures |
|------|--------|------------------|
| `/passthru` | `mode: off` | floor: Envoy ↔ ext_proc gRPC + prelude, no checks |
| `/bench` | header-only block (forbidden/required/host) | the common enforced hot path (no body buffering) |
| `/body` | `inspect_request_body` + sensitive-data detector | BUFFERED `mode_override` + body round-trip + body scan |

`/bench` ≈ `/passthru` (header checks are nearly free); `/body` is lower (it pays
the extra body round-trip + scan). All three share the machine's cores with Envoy,
the upstream, and the driver, so absolute numbers are single-box end-to-end — not a
per-core ceiling.

## Components

- `driver/` — stdlib-only closed-loop load generator (req/s + percentiles). Exits
  non-zero on any error or 5xx, so the test fails loudly on a broken data plane.
- `policy.yaml` — the load policy (lean-binary features only).
- `envoy.yaml` — Envoy config, dedicated ports (runs alongside the e2e harness),
  mirrors production: static body mode `NONE` + `allow_mode_override`.
- `run.sh` — brings up the stack, runs a correctness sanity check, then the load.

## In-memory micro-benchmarks

For per-path cost without the network/Envoy (clean relative numbers):

```
make loadtest   # BenchmarkProcess{Baseline,HeaderChecks,RequestBody} → ns/op, req/s, allocs
```
