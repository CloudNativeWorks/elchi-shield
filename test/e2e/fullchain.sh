#!/usr/bin/env bash
# Full production-chain e2e (UI excluded): the data is verified by reading it back
# through the REAL backend read API, exactly as the UI would.
#
#   curl ─▶ Envoy ──ext_proc──▶ elchi-shield ──clickhouse exporter──▶ ClickHouse
#                                                                          ▲
#                                              elchi-backend controller ───┘
#                                              GET /api/v3/shield/events(/summary)
#                                                       ▲ (owner JWT)
#                                              this script asserts the API response
#
# Brings up MongoDB + ClickHouse (Docker) + the elchi-backend controller + the
# elchi-shield/Envoy/echo stack, drives blocking traffic, then asserts the
# backend's shield-events API returns those events from ClickHouse. AUTO-SKIPS
# (exit 0) when Docker / Envoy / the backend checkout are unavailable.
#
#   bash test/e2e/fullchain.sh
#   ELCHI_BACKEND_DIR=/path/to/elchi-backend make e2e-fullchain
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
BACKEND_DIR="${ELCHI_BACKEND_DIR:-$ROOT/../elchi-backend}"
PORT=10000                 # Envoy listener
SHIELD_HTTP=127.0.0.1:9001 # shield health/metrics
API_PORT="${API_PORT:-38099}"     # backend controller REST (off 8099 to dodge a dev controller)
API="127.0.0.1:${API_PORT}"
GRPC_PORT="${GRPC_PORT:-50161}"   # controller gRPC (off 50051 for the same reason)
CH_NAME="elchi-shield-fc-ch"
MG_NAME="elchi-shield-fc-mongo"
CH_NATIVE="${CH_NATIVE:-19000}"
MG_PORT="${MG_PORT:-27018}"
CH_IMAGE="${CH_IMAGE:-clickhouse/clickhouse-server:24.8-alpine}"
MG_IMAGE="${MG_IMAGE:-mongo:7}"
CH_PW="${CH_PW:-e2epass}"
JWT_SECRET="${JWT_SECRET:-e2e-fullchain-jwt-secret-at-least-32-bytes-long-xyz}"
PROJECT="proj-e2e"          # must match the project segment of the Envoy node id
pass=0; fail=0
P(){ echo "  PASS  $*"; pass=$((pass+1)); }
F(){ echo "  FAIL  $*"; fail=$((fail+1)); }

# ---------------- preflight ----------------
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker not available (full-chain e2e needs Mongo + ClickHouse containers)."; exit 0
fi
if [ -z "${ENVOY:-}" ] && ! command -v func-e >/dev/null 2>&1; then
  echo "SKIP: no Envoy (func-e/ENVOY)."; exit 0
fi
if [ ! -d "$BACKEND_DIR" ] || [ ! -f "$BACKEND_DIR/go.mod" ]; then
  echo "SKIP: elchi-backend checkout not found at '$BACKEND_DIR' (set ELCHI_BACKEND_DIR)."; exit 0
fi
for t in go curl jq openssl; do command -v "$t" >/dev/null 2>&1 || { echo "SKIP: missing $t"; exit 0; }; done
# The controller binds :API_PORT on all interfaces; if something is already there
# (a dev controller, a stray echo) our bind fails and readiness would falsely
# pass against the squatter. Fail fast with guidance instead.
port_busy(){ lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
if port_busy "$API_PORT"; then echo "SKIP: API port $API_PORT is in use — free it or set API_PORT=<free port>."; exit 0; fi
if port_busy "$GRPC_PORT"; then echo "SKIP: gRPC port $GRPC_PORT is in use — set GRPC_PORT=<free port>."; exit 0; fi

PIDS=(); CFG=""; BCFG=""
cleanup(){
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done
  # Safety net: also kill whatever WE bound to the API/gRPC ports (covers any
  # child that outlived its parent shell).
  for prt in "$API_PORT" "$GRPC_PORT"; do
    pids="$(lsof -nP -tiTCP:"$prt" -sTCP:LISTEN 2>/dev/null)"; [ -n "$pids" ] && kill $pids 2>/dev/null || true
  done
  docker rm -f "$CH_NAME" "$MG_NAME" >/dev/null 2>&1 || true
  rm -rf "${CFG:-}" "${BCFG:-}" "$DIR/elchi-shield.bin" "$DIR/echo.bin" "$DIR/elchi-backend.bin"
}
trap cleanup EXIT

# ---------------- mint an owner JWT (bash; SignedDetails has no json tags → PascalCase) ----------------
b64url(){ openssl base64 -A | tr '+/' '-_' | tr -d '='; }
EXP=$(( $(date +%s) + 3600 ))
JHDR="$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)"
JPL="$(printf '%s' "{\"UserID\":\"e2e-owner\",\"Username\":\"e2e\",\"Role\":\"owner\",\"exp\":${EXP}}" | b64url)"
JSIG="$(printf '%s' "${JHDR}.${JPL}" | openssl dgst -sha256 -hmac "$JWT_SECRET" -binary | b64url)"
TOKEN="${JHDR}.${JPL}.${JSIG}"   # owner → bypasses project membership; only Mongo needs to be up

# ---------------- build binaries ----------------
( cd "$ROOT" && go build -o "$DIR/elchi-shield.bin" ./cmd/elchi-shield ) || { echo "shield build failed"; exit 1; }
go build -o "$DIR/echo.bin" "$DIR/echo" || { echo "echo build failed"; exit 1; }
echo "building elchi-backend (this can take a minute)…"
( cd "$BACKEND_DIR" && go build -o "$DIR/elchi-backend.bin" . ) || { echo "backend build failed"; exit 1; }

# ---------------- MongoDB (no auth) ----------------
echo "starting MongoDB ($MG_IMAGE)…"
docker rm -f "$MG_NAME" >/dev/null 2>&1 || true
docker run -d --rm --name "$MG_NAME" -p "${MG_PORT}:27017" "$MG_IMAGE" >/dev/null || { echo "SKIP: mongo run failed"; exit 0; }
mgready=0
for _ in $(seq 1 60); do
  if docker exec "$MG_NAME" mongosh --quiet --eval "db.adminCommand('ping').ok" 2>/dev/null | grep -q 1; then mgready=1; break; fi
  sleep 1
done
[ "$mgready" = 1 ] || { echo "MongoDB not ready"; exit 1; }

# ---------------- ClickHouse ----------------
echo "starting ClickHouse ($CH_IMAGE)…"
docker rm -f "$CH_NAME" >/dev/null 2>&1 || true
docker run -d --rm --name "$CH_NAME" -e CLICKHOUSE_PASSWORD="$CH_PW" -p "${CH_NATIVE}:9000" "$CH_IMAGE" >/dev/null || { echo "SKIP: clickhouse run failed"; exit 0; }
chready=0
for _ in $(seq 1 60); do
  if docker exec "$CH_NAME" clickhouse-client --password "$CH_PW" -q "SELECT 1" >/dev/null 2>&1; then chready=1; break; fi
  sleep 1
done
[ "$chready" = 1 ] || { echo "ClickHouse not ready"; exit 1; }

CH_DSN="clickhouse://default:${CH_PW}@localhost:${CH_NATIVE}/default"

# ---------------- backend controller ----------------
# Both shield (writer) and backend (reader) use database `default` so the
# qualified table matches (CLICKHOUSE_DATABASE=default → default.elchi_shield_audit).
BCFG="$(mktemp -d)/controller.yaml"
cat > "$BCFG" <<YAML
ELCHI_JWT_SECRET: "${JWT_SECRET}"
MONGODB_HOSTS: "localhost"
MONGODB_PORT: "${MG_PORT}"
MONGODB_DATABASE: "elchi_e2e"
MONGODB_SCHEME: "mongodb"
CONTROLLER_PORT: "${API_PORT}"
CONTROLLER_GRPC_PORT: "${GRPC_PORT}"
CLICKHOUSE_URI: "${CH_DSN}"
CLICKHOUSE_DATABASE: "default"
# ACME cert-manager init requires a non-empty CA_PROVIDERS map (it's not used by
# the shield-events path; this is just enough to pass boot validation).
CA_PROVIDERS:
  letsencrypt:
    name: "Let's Encrypt"
    supported: true
LOGGING:
  level: error
  format: text
  output_path: stdout
YAML
# `exec` so $! is the controller itself (not the subshell) → cleanup actually kills it.
( cd "$BACKEND_DIR" && exec "$DIR/elchi-backend.bin" elchi-controller --config "$BCFG" ) & PIDS+=($!)
# Robust readiness: confirm it's REALLY our auth-protected backend, not a squatter.
# A no-token call must be rejected (401/422) AND a token call must return the
# backend's JSON envelope (`{"data":...}`). An echo/other server fails both.
probe="http://${API}/api/v3/shield/policies?project=${PROJECT}"
apiready=0
for _ in $(seq 1 90); do
  noauth="$(curl -s -o /dev/null -w '%{http_code}' "$probe" 2>/dev/null)"
  body="$(curl -s -H "Authorization: Bearer $TOKEN" "$probe" 2>/dev/null)"
  if { [ "$noauth" = 401 ] || [ "$noauth" = 422 ]; } && printf '%s' "$body" | jq -e 'has("data")' >/dev/null 2>&1; then
    apiready=1; break
  fi
  sleep 1
done
[ "$apiready" = 1 ] || { echo "backend API not ready on ${API} (no-token code: ${noauth:-none})"; exit 1; }
P "backend controller up, auth enforced + owner JWT accepted"

# ---------------- minimal blocking policy + shield + Envoy + echo ----------------
CFG="$(mktemp -d)"
cat > "$CFG/fc.yaml" <<'YAML'
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: fc-e2e }
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
ECHO_ADDR=127.0.0.1:18080 "$DIR/echo.bin" & PIDS+=($!)
"$DIR/elchi-shield.bin" --config-dir "$CFG" --extproc-network tcp --extproc-addr 127.0.0.1:9999 \
  --http-addr "$SHIELD_HTTP" --watch-debounce 200ms --log-level error \
  --audit-exporter clickhouse --audit-clickhouse-dsn "$CH_DSN" \
  --audit-clickhouse-flush-interval 300ms & PIDS+=($!)
for _ in $(seq 1 40); do curl -sf "http://${SHIELD_HTTP}/readyz" >/dev/null 2>&1 && break; sleep 0.25; done
curl -sf "http://${SHIELD_HTTP}/readyz" >/dev/null 2>&1 || { echo "shield not ready"; exit 1; }
BASE_ID="${ENVOY_BASE_ID:-2720}"
if [ -n "${ENVOY:-}" ]; then "$ENVOY" -c "$DIR/envoy.yaml" --base-id "$BASE_ID" --log-level error & PIDS+=($!)
else func-e run -c "$DIR/envoy.yaml" --base-id "$BASE_ID" --log-level error & PIDS+=($!); fi
for _ in $(seq 1 60); do curl -sf -o /dev/null "http://127.0.0.1:${PORT}/ok" 2>/dev/null && break; sleep 0.5; done

# ---------------- drive traffic ----------------
for _ in 1 2 3 4 5; do curl -s -o /dev/null -H 'X-Debug: 1' "http://127.0.0.1:${PORT}/block-hdr?secret=shh"; done
curl -s -o /dev/null "http://127.0.0.1:${PORT}/ok"
sleep 2   # async queue + 300ms flush

# ---------------- assert via the BACKEND read API (data comes from ClickHouse) ----------------
echo "== backend shield-events API (reads ClickHouse) =="
auth(){ curl -s -H "Authorization: Bearer $TOKEN" "$@"; }
EVURL="http://${API}/api/v3/shield/events?project=${PROJECT}&findings_only=true&include_total=true"
SUMURL="http://${API}/api/v3/shield/events/summary?project=${PROJECT}"

EV="$(auth "$EVURL")"
N="$(printf '%s' "$EV" | jq -r '.data | length' 2>/dev/null)"
case "${N:-0}" in ''|0) F "events API returned no rows (resp: $(printf '%s' "$EV" | head -c 200))";; *) P "events API returned $N rows from ClickHouse";; esac
B="$(printf '%s' "$EV" | jq -c '[.data[] | select(.action=="block")][0] // empty' 2>/dev/null)"
[ -n "$B" ] && P "events API: a block event present" || F "events API: no block event"
[ "$(printf '%s' "$B" | jq -r '.project_id // empty')" = "$PROJECT" ] && P "events API: project_id=$PROJECT" || F "events API: wrong project_id"
[ "$(printf '%s' "$B" | jq -r '.node_id // empty')" = "e2e-envoy-node::proj-e2e::10.0.0.1" ] && P "events API: raw node_id" || F "events API: wrong node_id"
[ "$(printf '%s' "$B" | jq -r '.status_code // empty')" = "403" ] && P "events API: status_code 403" || F "events API: wrong status_code ($(printf '%s' "$B" | jq -r '.status_code'))"
TOT="$(printf '%s' "$EV" | jq -r '.total_count // 0')"
case "$TOT" in ''|0) F "events API: total_count not set";; *) P "events API: total_count=$TOT";; esac

SUM="$(auth "$SUMURL")"
ST="$(printf '%s' "$SUM" | jq -r '.data.total // 0' 2>/dev/null)"
case "${ST:-0}" in ''|0) F "summary API: total is 0 (resp: $(printf '%s' "$SUM" | head -c 200))";; *) P "summary API: total=$ST";; esac
SG="$(printf '%s' "$SUM" | jq -r '.data.groups | length' 2>/dev/null)"
case "${SG:-0}" in ''|0) F "summary API: no groups";; *) P "summary API: $SG breakdown group(s)";; esac

# auth must be enforced: no token → 401
NOAUTH="$(curl -s -o /dev/null -w '%{http_code}' "$EVURL")"
case "$NOAUTH" in 401|403) P "events API rejects unauthenticated ($NOAUTH)";; *) F "events API did not require auth (got $NOAUTH)";; esac

echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ] && echo "FULLCHAIN-E2E: ALL PASS" || echo "FULLCHAIN-E2E: FAILURES"
exit "$fail"
