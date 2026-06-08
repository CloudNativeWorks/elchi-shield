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

It builds `elchi-shield` **with `-tags coraza`** (so the WAF is exercised),
starts the echo upstream + elchi-shield (ext_proc on loopback TCP
`127.0.0.1:9999`, health on `:9001`) and a real Envoy (listener
`127.0.0.1:10000`, `--base-id` so it never collides with another local Envoy),
then drives every capability **phase by phase** (53 assertions) against the
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
| 9 — Observability | `/healthz` `/readyz` `/configz` `/policyz` `/metrics` (build_info, go_goroutines) `/debug/pprof` |
| 10 — Config hot-reload | drop a new file in → version changes → new policy enforced live (keep-last-good) |

The echo upstream shapes its response by query (`?resp=json|badjson|pii`) so
response inspection has a concrete payload to inspect.

Files: `envoy.yaml` (real Envoy config, `allow_mode_override: true` so the
service can request body buffering), `policy/e2e.yaml` (the comprehensive
multi-domain policy), `echo/main.go` (configurable upstream),
`gentoken/main.go` (HS256 JWT generator for the JWT phase), `run.sh`
(orchestrator, cleans up on exit).
