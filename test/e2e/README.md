# End-to-end test (`make e2e`)

A **real Envoy** proxies HTTP through elchi-shield to a tiny echo upstream, and
the script asserts the security decisions per `policy/e2e.yaml`:

```
curl ─▶ Envoy ──ext_proc gRPC──▶ elchi-shield ─▶ allow ─▶ echo backend
                                              └─ block ─▶ 403 / 429 (no upstream)
```

Run it:

```sh
make e2e                      # uses func-e to fetch/run a real Envoy
ENVOY=/path/to/envoy make e2e # or use a system Envoy binary
```

It builds the single full `elchi-shield` binary (all engines compiled in, so the WAF is exercised),
starts the echo upstream + elchi-shield (ext_proc on loopback TCP
`127.0.0.1:9999`, health on `:9001`) and a real Envoy (listener
`127.0.0.1:10000`, `--base-id` so it never collides with another local Envoy),
then drives every capability **phase by phase** (160 assertions) against the
fields in `policy/e2e.yaml`:

| phase | covers |
|---|---|
| 1 — Routing & precedence | mode `off`, exact-beats-prefix, method/content-type match, exact + wildcard host |
| 2 — Header checks (`fast_pre_checks`) | forbidden / required / oversized headers, `x-elchi-shield` block marker |
| 3 — Body checks | `require_json` (body + content-type), sensitive-data PII, body size limit (truncation), gzip decode |
| 4 — Engine: JWT | valid / missing / wrong-signature / expired / wrong-audience |
| 5 — Engine: rate limit | per-IP `429` + `Retry-After`, per-header key, independent buckets |
| 6 — Engine: Coraza WAF | SQLi payload blocked, clean body allowed |
| 7 — Decision modes | `detect` / `shadow` allow the request but increment the detection metric |
| 8 — Response inspection | `inspect_response_body` + `require_json` on the upstream response |
| 9 — Observability | `/healthz` `/readyz` `/configz` `/policyz` `/metrics` (build_info, go_goroutines, `listener` node-id label) `/debug/pprof` |
| 10 — Config hot-reload | drop a new file in → version changes → new policy enforced live (keep-last-good) |
| 11 — Audit events (NDJSON) | stop shield (flush), then assert a block's audit event carries the parsed `project_id`/`listener` + raw `node_id` (from the `listener::project::ip` Envoy node id), the HTTP `status_code`, and a query-stripped path. Uses the `file` exporter, which serializes the **same** `Event` as the ClickHouse exporter — so this validates the audit→sink path with no ClickHouse needed. |

The echo upstream shapes its response by query (`?resp=json|badjson|pii`) so
response inspection has a concrete payload to inspect.

## Live audit → ClickHouse e2e (`make e2e-clickhouse`)

`clickhouse.sh` closes the one hop the above can't: it brings up a **real
ClickHouse** (Docker), runs the same real Envoy → elchi-shield stack but with the
**ClickHouse audit exporter**, drives blocking traffic, and then queries
ClickHouse to assert the rows landed — the table schema (incl. `node_id`/
`project_id`/`listener`/`status_code`), the parsed identity (`project_id=proj-e2e`,
`listener=e2e-envoy-node` from the `listener::project::ip` node id), the block
`status_code`, and query-stripped paths.

```sh
make e2e-clickhouse                 # needs Docker + func-e (or ENVOY=…)
CH_IMAGE=clickhouse/clickhouse-server:24.8-alpine make e2e-clickhouse
```

It **auto-skips (exit 0)** when Docker or Envoy is unavailable, so a Docker-less
CI stays green while a Docker-equipped run exercises the real sink end-to-end.

## Full production-chain e2e (`make e2e-fullchain`)

`fullchain.sh` is the most complete check — it verifies the data by reading it
back through the **real backend read API**, exactly as the UI does:

```
curl ─▶ Envoy ─▶ elchi-shield ─▶ ClickHouse ◀─ elchi-backend controller
                                              GET /api/v3/shield/events(/summary)
```

It brings up MongoDB + ClickHouse (Docker) + the **real elchi-backend controller**
+ the Envoy/shield/echo stack, drives blocking traffic, then calls the backend's
shield-events API with an owner JWT and asserts the events/summary returned from
ClickHouse (project scoping, raw node id, status code, totals) plus that an
unauthenticated call is rejected.

```sh
make e2e-fullchain                                  # needs Docker + func-e (or ENVOY=…)
ELCHI_BACKEND_DIR=/path/to/elchi-backend make e2e-fullchain
```

It **auto-skips** without Docker / Envoy / an elchi-backend checkout (sibling repo
by default). The owner JWT is minted in-script (no Mongo seeding needed — owner
bypasses project membership). Tunables: `ELCHI_BACKEND_DIR`, `API_PORT`, `GRPC_PORT`,
`CH_IMAGE`, `MG_IMAGE`.

Files: `envoy.yaml` (real Envoy config, `allow_mode_override: true` so the
service can request body buffering), `policy/e2e.yaml` (the comprehensive
multi-domain policy), `echo/main.go` (configurable upstream),
`gentoken/main.go` (HS256 JWT generator for the JWT phase), `run.sh`
(orchestrator, cleans up on exit).
