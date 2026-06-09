#!/usr/bin/env bash
# Real-traffic load test: a REAL Envoy proxies HTTP through elchi-shield to a
# local echo upstream, and a closed-loop Go driver drives sustained traffic,
# reporting throughput (req/s) and latency percentiles for three representative
# paths:
#   - passthrough (mode off)        → gRPC + prelude floor
#   - header-only enforced          → the common hot path (no body buffering)
#   - body-inspecting               → BUFFERED mode_override + body buffering
#
# Lean binary (no build tags) so numbers reflect the production default image.
# Needs: go, curl, and a real Envoy (auto-fetched via func-e, or ENVOY=...).
#
# Tunables: DURATION (per scenario, default 10s), CONNS (default 64), WARMUP (1s).
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
E2E="$ROOT/test/e2e"

PORT=10010                 # Envoy listener
HTTP=127.0.0.1:9012        # shield admin/metrics
DURATION="${DURATION:-10s}"
CONNS="${CONNS:-64}"
WARMUP="${WARMUP:-1s}"

echo "building (lean binary, no build tags) ..."
( cd "$ROOT" && go build -o "$DIR/elchi-shield.bin" ./cmd/elchi-shield ) || { echo "build failed"; exit 1; }
go build -o "$DIR/echo.bin" "$E2E/echo" || { echo "echo build failed"; exit 1; }
go build -o "$DIR/driver.bin" "$DIR/driver" || { echo "driver build failed"; exit 1; }

CFG="$(mktemp -d)"
cp "$DIR/policy.yaml" "$CFG/policy.yaml"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; rm -rf "$CFG" "$DIR/elchi-shield.bin" "$DIR/echo.bin" "$DIR/driver.bin" "$SOCK"; }
trap cleanup EXIT

SOCK="/tmp/elchi-shield-loadtest.sock"   # UDS, matching the production default (lower overhead than loopback TCP)
rm -f "$SOCK"
ECHO_ADDR=127.0.0.1:18090 "$DIR/echo.bin" & PIDS+=($!)
"$DIR/elchi-shield.bin" --config-dir "$CFG" --extproc-network unix --extproc-addr "$SOCK" \
  --http-addr "$HTTP" --log-level error & PIDS+=($!)
for _ in $(seq 1 40); do curl -sf "http://${HTTP}/readyz" >/dev/null 2>&1 && break; sleep 0.25; done
curl -sf "http://${HTTP}/readyz" >/dev/null 2>&1 || { echo "shield not ready"; exit 1; }

BASE_ID="${ENVOY_BASE_ID:-3141}"
if [ -n "${ENVOY:-}" ]; then "$ENVOY" -c "$DIR/envoy.yaml" --base-id "$BASE_ID" --log-level error & PIDS+=($!)
elif command -v func-e >/dev/null 2>&1; then func-e run -c "$DIR/envoy.yaml" --base-id "$BASE_ID" --log-level error & PIDS+=($!)
else echo "no Envoy (install func-e or set ENVOY=/path/to/envoy)"; exit 1; fi
for _ in $(seq 1 60); do curl -s -o /dev/null -H 'Host: api.example.com' "http://127.0.0.1:${PORT}/passthru" 2>/dev/null && break; sleep 0.25; done

# ---------------- sanity: the data plane decides correctly ----------------
echo
echo "== sanity =="
sane(){ local got; got=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: api.example.com' "$@"); echo "  $got  $*"; }
sane "http://127.0.0.1:${PORT}/passthru"                                       # 200
sane -H 'X-Bench-Token: 1' "http://127.0.0.1:${PORT}/bench"                    # 200 (required header present)
sane "http://127.0.0.1:${PORT}/bench"                                          # 403 (missing X-Bench-Token)
sane -X POST --data 'card 4111 1111 1111 1111' "http://127.0.0.1:${PORT}/body" # 403 (secret in body)

drive(){ "$DIR/driver.bin" -target "http://127.0.0.1:${PORT}$1" -host api.example.com \
  -duration "$DURATION" -conns "$CONNS" -warmup "$WARMUP" "${@:2}"; }

echo
echo "== load (conns=$CONNS, duration=$DURATION each) =="
drive /passthru                       -name "passthrough (mode off)"
drive /bench -H 'X-Bench-Token: load' -name "header-only enforced (allowed)"
drive /body  -method POST -body 'hello world clean body, no secrets here' -rand-bytes 256 \
                                       -name "body-inspecting (BUFFERED override)"

echo
echo "== shield metrics =="
msum(){ curl -s "http://${HTTP}/metrics" | awk -v re="$1" '$0 ~ re {s+=$2} END{print s+0}'; }
echo "  requests_total   : $(msum 'requests_total\{')"
echo "  allowed_total    : $(msum 'requests_allowed_total\{')"
echo "  blocked_total    : $(msum 'requests_blocked_total\{')"
echo "  body_inspected_B : $(msum 'body_inspected_bytes_total\{')"
echo "  go_goroutines    : $(curl -s "http://${HTTP}/metrics" | awk '/^go_goroutines[ {]/{print $2}')  (leak signal — should be small/stable)"
echo
echo "LOADTEST DONE"
