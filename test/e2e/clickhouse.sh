#!/usr/bin/env bash
# Optional end-to-end test of the LIVE audit→ClickHouse hop:
#
#   curl ─▶ Envoy ──ext_proc──▶ elchi-shield ──(clickhouse exporter)──▶ ClickHouse
#
# A real Envoy proxies through a real elchi-shield configured with the ClickHouse
# audit exporter, writing to a real ClickHouse (Docker). It then asserts the
# blocked requests landed as rows carrying the parsed project_id/listener + raw
# node_id (from the `listener::project::ip` Envoy node id) and the HTTP
# status_code, that the table has the expected schema, and that paths are
# query-stripped (redaction). This is the one hop the unit + file-exporter e2e
# can't cover. It AUTO-SKIPS (exit 0) when Docker or Envoy is unavailable, so it
# never breaks a Docker-less CI.
#
#   bash test/e2e/clickhouse.sh        # uses func-e + Docker
#   CH_IMAGE=... ENVOY=/path make e2e-clickhouse
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
PORT=10000
HTTP=127.0.0.1:9001
CH_NAME="elchi-shield-e2e-ch"
CH_NATIVE="${CH_NATIVE:-19000}"
CH_IMAGE="${CH_IMAGE:-clickhouse/clickhouse-server:24.8-alpine}"
# Provision an explicit password for the `default` user (CLICKHOUSE_PASSWORD sets
# it on the stock image). Passwordless `default` is rejected over TCP from the
# host in recent images, so both shield (DSN) and clickhouse-client use this.
CH_PW="${CH_PW:-e2epass}"
pass=0; fail=0
P(){ echo "  PASS  $*"; pass=$((pass+1)); }
F(){ echo "  FAIL  $*"; fail=$((fail+1)); }

# ---------------- preflight (skip cleanly when prerequisites are missing) ----------------
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker not available — the live ClickHouse e2e needs it (the file-exporter e2e in run.sh already covers the audit event content)."
  exit 0
fi
if [ -z "${ENVOY:-}" ] && ! command -v func-e >/dev/null 2>&1; then
  echo "SKIP: no Envoy (install func-e or set ENVOY=/path/to/envoy)."
  exit 0
fi

PIDS=()
CFG=""
chq(){ docker exec "$CH_NAME" clickhouse-client --password "$CH_PW" -q "$1"; }   # one-shot query helper
cleanup(){
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  docker rm -f "$CH_NAME" >/dev/null 2>&1 || true
  rm -rf "${CFG:-}" "$DIR/elchi-shield.bin" "$DIR/echo.bin"
}
trap cleanup EXIT

# ---------------- build shield + echo ----------------
( cd "$ROOT" && go build -o "$DIR/elchi-shield.bin" ./cmd/elchi-shield ) || { echo "shield build failed"; exit 1; }
go build -o "$DIR/echo.bin" "$DIR/echo" || { echo "echo build failed"; exit 1; }

# ---------------- bring up ClickHouse ----------------
echo "starting ClickHouse ($CH_IMAGE) on host port ${CH_NATIVE}…"
docker rm -f "$CH_NAME" >/dev/null 2>&1 || true
if ! docker run -d --rm --name "$CH_NAME" -e CLICKHOUSE_PASSWORD="$CH_PW" -p "${CH_NATIVE}:9000" "$CH_IMAGE" >/dev/null; then
  echo "SKIP: could not start the ClickHouse container (image pull/daemon issue)."
  exit 0
fi
ready=0
for _ in $(seq 1 60); do
  if docker exec "$CH_NAME" clickhouse-client --password "$CH_PW" -q "SELECT 1" >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
[ "$ready" = 1 ] || { echo "ClickHouse did not become ready"; exit 1; }

# ---------------- minimal blocking policy ----------------
# A forbidden-header block is enough to produce an audited block event; this test
# is about the SINK, not engine coverage (run.sh covers engines).
CFG="$(mktemp -d)"
cat > "$CFG/ch.yaml" <<'YAML'
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata:
  name: ch-e2e
spec:
  defaults: { mode: block, fail_mode: fail_open, timeout: 500ms }
  domains:
    - hosts: ["*"]
      routes:
        - match: { path_prefix: "/block-hdr" }
          policy: { mode: block, checks: { headers: { forbidden: ["X-Debug"] } } }
        - match: { path_prefix: "/ok" }
          policy: { mode: off }
YAML

# ---------------- echo + shield (ClickHouse exporter) + Envoy ----------------
ECHO_ADDR=127.0.0.1:18080 "$DIR/echo.bin" & PIDS+=($!)
DSN="clickhouse://default:${CH_PW}@localhost:${CH_NATIVE}/default"
# Short flush interval so rows land within ~1s without relying on shutdown.
"$DIR/elchi-shield.bin" --config-dir "$CFG" --extproc-network tcp --extproc-addr 127.0.0.1:9999 \
  --http-addr "$HTTP" --watch-debounce 200ms --log-level error \
  --audit-exporter clickhouse --audit-clickhouse-dsn "$DSN" \
  --audit-clickhouse-flush-interval 300ms & PIDS+=($!)
for _ in $(seq 1 40); do curl -sf "http://${HTTP}/readyz" >/dev/null 2>&1 && break; sleep 0.25; done
curl -sf "http://${HTTP}/readyz" >/dev/null 2>&1 || { echo "shield not ready"; exit 1; }

BASE_ID="${ENVOY_BASE_ID:-2719}"   # distinct from run.sh's 2718
if [ -n "${ENVOY:-}" ]; then "$ENVOY" -c "$DIR/envoy.yaml" --base-id "$BASE_ID" --log-level error & PIDS+=($!)
else func-e run -c "$DIR/envoy.yaml" --base-id "$BASE_ID" --log-level error & PIDS+=($!); fi
for _ in $(seq 1 60); do curl -sf -o /dev/null "http://127.0.0.1:${PORT}/ok" 2>/dev/null && break; sleep 0.5; done

# ---------------- drive traffic ----------------
# Several blocks (forbidden header) + one allowed request. The query string must
# be stripped from the audited path.
for _ in 1 2 3 4 5; do
  curl -s -o /dev/null -H 'X-Debug: 1' "http://127.0.0.1:${PORT}/block-hdr?secret=shh"
done
curl -s -o /dev/null "http://127.0.0.1:${PORT}/ok"

# Let the async queue + the 300ms flush land the rows.
sleep 2

# ---------------- assert in ClickHouse ----------------
echo "== ClickHouse audit verification =="
COLS="$(chq "SELECT name FROM system.columns WHERE database='default' AND table='elchi_shield_audit' FORMAT TSV" 2>/dev/null)"
for c in ts instance node_id project_id listener action severity reason rule_id engine host path method status_code config_version; do
  case "$COLS" in *"$c"*) P "schema has column '$c'";; *) F "schema missing column '$c'";; esac
done

NBLOCK="$(chq "SELECT count() FROM default.elchi_shield_audit WHERE action='block' AND project_id='proj-e2e'" 2>/dev/null | tr -d '[:space:]')"
case "${NBLOCK:-0}" in ''|0) F "no block rows scoped to project_id=proj-e2e";; *) P "block rows landed in ClickHouse ($NBLOCK)";; esac

ROW="$(chq "SELECT node_id, listener, status_code FROM default.elchi_shield_audit WHERE action='block' LIMIT 1 FORMAT TSV" 2>/dev/null)"
RN="$(printf '%s' "$ROW" | awk -F'\t' '{print $1}')"
RL="$(printf '%s' "$ROW" | awk -F'\t' '{print $2}')"
RS="$(printf '%s' "$ROW" | awk -F'\t' '{print $3}')"
[ "$RN" = "e2e-envoy-node::proj-e2e::10.0.0.1" ] && P "row carries the raw node_id" || F "row node_id wrong (got '$RN')"
[ "$RL" = "e2e-envoy-node" ] && P "row carries the parsed listener" || F "row listener wrong (got '$RL')"
[ "$RS" = "403" ] && P "row carries status_code 403" || F "row status_code wrong (got '$RS')"

NQ="$(chq "SELECT count() FROM default.elchi_shield_audit WHERE position(path, '?') > 0" 2>/dev/null | tr -d '[:space:]')"
case "${NQ:-0}" in ''|0) P "paths are query-stripped in ClickHouse (no secret leakage)";; *) F "a path leaked a query string ($NQ rows)";; esac

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ] && echo "CH-E2E: ALL PASS" || echo "CH-E2E: FAILURES"
exit "$fail"
