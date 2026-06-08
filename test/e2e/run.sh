#!/usr/bin/env bash
# Comprehensive end-to-end suite: a REAL Envoy proxies HTTP through elchi-shield
# to a configurable echo upstream, exercising EVERY capability phase by phase
# (routing, header checks, body checks, engines, modes, response inspection,
# observability, hot-reload). Built with -tags coraza so the WAF is testable.
#
# Needs: go, curl, gzip, and a real Envoy (auto-fetched via func-e, or ENVOY=...).
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
PORT=10000
HTTP=127.0.0.1:9001
pass=0; fail=0
P(){ echo "  PASS  $*"; pass=$((pass+1)); }
F(){ echo "  FAIL  $*"; fail=$((fail+1)); }
phase(){ echo; echo "== $* =="; }
expect(){ if [ "$2" = "$3" ]; then P "$1"; else F "$1 (got '$2' want '$3')"; fi; }

req(){ # req METHOD PATH [extra curl args...] ; sets $CODE, dumps headers to /tmp/eh
  local m="$1" p="$2"; shift 2
  CODE=$(curl -s -D /tmp/eh -o /tmp/eb -w '%{http_code}' -X "$m" "$@" "http://127.0.0.1:${PORT}${p}")
}
hashdr(){ grep -qi "^$1:" /tmp/eh; }
msum(){ curl -s "http://${HTTP}/metrics" | awk -v re="$1" '$0 ~ re {s+=$2} END{print s+0}'; }
H(){ printf -- '-HHost:%s' "$1"; }   # host header arg

# ---------------- bring up the stack ----------------
( cd "$ROOT" && go build -tags coraza -o "$DIR/elchi-shield.bin" ./cmd/elchi-shield ) || { echo "build failed"; exit 1; }
go build -o "$DIR/gentoken.bin" "$DIR/gentoken" || { echo "gentoken build failed"; exit 1; }

CFG="$(mktemp -d)"; cp "$DIR/policy/e2e.yaml" "$CFG/"
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; rm -rf "$CFG" "$DIR/elchi-shield.bin" "$DIR/gentoken.bin" /tmp/eh /tmp/eb /tmp/*.gz; }
trap cleanup EXIT

ECHO_ADDR=127.0.0.1:18080 go run "$DIR/echo/main.go" & PIDS+=($!)
"$DIR/elchi-shield.bin" --config-dir "$CFG" --extproc-network tcp --extproc-addr 127.0.0.1:9999 \
  --http-addr "$HTTP" --watch-debounce 200ms --log-level error & PIDS+=($!)
for _ in $(seq 1 40); do curl -sf "http://${HTTP}/readyz" >/dev/null 2>&1 && break; sleep 0.25; done
curl -sf "http://${HTTP}/readyz" >/dev/null 2>&1 || { echo "shield not ready"; exit 1; }

BASE_ID="${ENVOY_BASE_ID:-2718}"
if [ -n "${ENVOY:-}" ]; then "$ENVOY" -c "$DIR/envoy.yaml" --base-id "$BASE_ID" --log-level error & PIDS+=($!)
elif command -v func-e >/dev/null 2>&1; then func-e run -c "$DIR/envoy.yaml" --base-id "$BASE_ID" --log-level error & PIDS+=($!)
else echo "no Envoy (install func-e or set ENVOY=...)"; exit 1; fi
for _ in $(seq 1 60); do curl -s -o /dev/null "$(H api.example.com)" "http://127.0.0.1:${PORT}/off" 2>/dev/null && break; sleep 0.25; done

AH="$(H api.example.com)"
# JWT tokens
VALID=$("$DIR/gentoken.bin" -secret e2e-secret -aud api -sub u1 -exp 3600)
EXPIRED=$("$DIR/gentoken.bin" -secret e2e-secret -aud api -sub u1 -exp -10)
WRONGSIG=$("$DIR/gentoken.bin" -secret wrong -aud api -sub u1 -exp 3600)
NOAUD=$("$DIR/gentoken.bin" -secret e2e-secret -sub u1 -exp 3600)

# ==================== PHASE 1: Routing & precedence ====================
phase "Routing & precedence"
req GET /off "$AH" -H 'X-Debug: 1';                       expect "mode off → no inspection (200)" "$CODE" 200
req GET /unmatched "$AH" -H 'X-Debug: 1';                 expect "unmatched path → domain default off (200)" "$CODE" 200
req GET /p/health "$AH" -H 'X-Debug: 1';                  expect "exact path beats prefix (off → 200)" "$CODE" 200
req GET /p/other "$AH" -H 'X-Debug: 1';                   expect "prefix path applies (block → 403)" "$CODE" 403
req GET /method "$AH" -H 'X-Debug: 1';                    expect "method mismatch (GET≠POST) → default off (200)" "$CODE" 200
req POST /method "$AH" -H 'X-Debug: 1';                   expect "method match (POST) → block (403)" "$CODE" 403
req POST /ct "$AH" -H 'Content-Type: text/plain' --data x; expect "content-type mismatch → default off (200)" "$CODE" 200
req POST /ct "$AH" -H 'Content-Type: application/json' --data '{bad'; expect "content-type match → block invalid json (403)" "$CODE" 403
req GET /x "$(H foo.example.com)" -H 'X-Debug: 1';        expect "wildcard host matches (403)" "$CODE" 403
req GET /x "$(H other.example.com)" -H 'X-Debug: 1';      expect "exact host other.example.com (off → 200)" "$CODE" 200

# ==================== PHASE 2: Header checks (fast_pre_checks) ====================
phase "Header checks"
req GET /block-hdr "$AH" -H 'X-Debug: 1';   expect "forbidden header → 403" "$CODE" 403
hashdr 'x-elchi-shield' && P "block carries x-elchi-shield marker" || F "missing x-elchi-shield marker"
req GET /block-hdr "$AH";                    expect "no forbidden header → 200" "$CODE" 200
req GET /req-hdr "$AH";                        expect "required header missing → 403" "$CODE" 403
req GET /req-hdr "$AH" -H 'X-Custom-Req: yes'; expect "required header present → 200" "$CODE" 200
BIG=$(printf 'x%.0s' $(seq 1 300))   # 300 bytes > the 256 cap
req GET /big-hdr "$AH" -H "X-Big: $BIG"; expect "oversized header → 403" "$CODE" 403
req GET /big-hdr "$AH" -H 'X-Big: small'; expect "small header → 200" "$CODE" 200

# ==================== PHASE 3: Body checks (body phase) ====================
phase "Body checks"
req POST /json "$AH" -H 'Content-Type: application/json' --data '{"ok":true}'; expect "require_json valid → 200" "$CODE" 200
req POST /json "$AH" -H 'Content-Type: application/json' --data '{bad';        expect "require_json invalid → 403" "$CODE" 403
req POST /json "$AH" -H 'Content-Type: text/plain' --data '{"ok":true}';       expect "require_json non-JSON content-type → 403" "$CODE" 403
req POST /pii  "$AH" -H 'Content-Type: text/plain' --data 'card 4111 1111 1111 1111 here'; expect "sensitive data (credit card) → 403" "$CODE" 403
req POST /pii  "$AH" --data 'nothing sensitive here';                          expect "no sensitive data → 200" "$CODE" 200
req POST /small "$AH" --data 'this body is much larger than sixteen bytes';    expect "over-limit body (truncation) → 403" "$CODE" 403
req POST /small "$AH" --data 'tiny';                                           expect "within-limit body → 200" "$CODE" 200
printf '%s' '{bad json' | gzip > /tmp/bad.gz
req POST /gzip "$AH" -H 'Content-Type: application/json' -H 'Content-Encoding: gzip' --data-binary @/tmp/bad.gz; expect "gzip body decoded → invalid JSON → 403" "$CODE" 403
printf '%s' '{"ok":true}' | gzip > /tmp/good.gz
req POST /gzip "$AH" -H 'Content-Type: application/json' -H 'Content-Encoding: gzip' --data-binary @/tmp/good.gz; expect "gzip body decoded → valid JSON → 200" "$CODE" 200

# ==================== PHASE 4: Engines — JWT ====================
phase "Engine: JWT"
req GET /jwt "$AH" -H "Authorization: Bearer $VALID";    expect "valid JWT → 200" "$CODE" 200
req GET /jwt "$AH";                                       expect "missing JWT → 403" "$CODE" 403
req GET /jwt "$AH" -H "Authorization: Bearer $WRONGSIG"; expect "wrong-signature JWT → 403" "$CODE" 403
req GET /jwt "$AH" -H "Authorization: Bearer $EXPIRED";  expect "expired JWT → 403" "$CODE" 403
req GET /jwt "$AH" -H "Authorization: Bearer $NOAUD";    expect "wrong/missing audience → 403" "$CODE" 403

# ==================== PHASE 5: Engines — rate limit ====================
phase "Engine: rate limit"
got=0; ra=0
for _ in $(seq 1 6); do req GET /rl "$AH"; [ "$CODE" = 429 ] && { got=1; hashdr 'retry-after' && ra=1; }; done
expect "per-IP rate limit → 429 seen" "$got" 1
expect "429 carries Retry-After" "$ra" 1
gh=0; for _ in $(seq 1 3); do req GET /rl-hdr "$AH" -H 'X-Api-Key: k1'; [ "$CODE" = 429 ] && gh=1; done
expect "per-header rate limit (k1) → 429 seen" "$gh" 1
req GET /rl-hdr "$AH" -H 'X-Api-Key: brand-new-key';    expect "different key → independent bucket (200)" "$CODE" 200

# ==================== PHASE 6: Engines — Coraza WAF ====================
phase "Engine: Coraza WAF (-tags coraza)"
req POST /waf "$AH" -H 'Content-Type: text/plain' --data 'q=1 union select password from users'; expect "SQLi payload → 403" "$CODE" 403
req POST /waf "$AH" -H 'Content-Type: text/plain' --data 'q=hello world';                        expect "clean body → 200" "$CODE" 200

# ==================== PHASE 7: Decision modes (record but allow) ====================
phase "Decision modes (detect/shadow)"
det0=$(msum '^elchi_shield_detections_total'); req GET /detect "$AH" -H 'X-Debug: 1'; det1=$(msum '^elchi_shield_detections_total')
expect "detect: request allowed (200)" "$CODE" 200
if [ "$det1" -gt "$det0" ]; then P "detect: detections_total incremented ($det0 to $det1)"; else F "detect: detections_total not incremented ($det0 to $det1)"; fi
sh0=$(msum '^elchi_shield_shadow_detections_total'); req GET /shadow "$AH" -H 'X-Debug: 1'; sh1=$(msum '^elchi_shield_shadow_detections_total')
expect "shadow: request allowed (200)" "$CODE" 200
if [ "$sh1" -gt "$sh0" ]; then P "shadow: shadow_detections_total incremented ($sh0 to $sh1)"; else F "shadow: shadow_detections_total not incremented ($sh0 to $sh1)"; fi

# ==================== PHASE 8: Response inspection ====================
phase "Response inspection"
req GET '/resp?resp=badjson' "$AH";  expect "bad JSON response → blocked (403)" "$CODE" 403
req GET '/resp?resp=json' "$AH";     expect "valid JSON response → allowed (200)" "$CODE" 200
[ "$CODE" != 200 ] && { echo "    [debug] resp=json response headers:"; sed 's/^/      /' /tmp/eh; echo "      body: $(cat /tmp/eb)"; }

# ==================== PHASE 9: Observability ====================
phase "Observability endpoints"
expect "/healthz" "$(curl -s -o /dev/null -w '%{http_code}' http://${HTTP}/healthz)" 200
expect "/readyz"  "$(curl -s -o /dev/null -w '%{http_code}' http://${HTTP}/readyz)" 200
# Capture once and pattern-match (avoids `curl | grep -q` SIGPIPE under pipefail).
CZ=$(curl -s "http://${HTTP}/configz")
case "$CZ" in *'"version"'*) P "/configz has version";; *) F "/configz missing version";; esac
PZ=$(curl -s "http://${HTTP}/policyz?host=api.example.com&path=/block-hdr&method=GET")
case "$PZ" in *'"matched": true'*) P "/policyz resolves a policy";; *) F "/policyz no match";; esac
MX=$(curl -s "http://${HTTP}/metrics")
case "$MX" in *elchi_shield_build_info*) P "/metrics has build_info";; *) F "/metrics missing build_info";; esac
case "$MX" in *go_goroutines*) P "/metrics has go_goroutines";; *) F "/metrics missing go_goroutines";; esac
expect "/debug/pprof/" "$(curl -s -o /dev/null -w '%{http_code}' http://${HTTP}/debug/pprof/)" 200

# ==================== PHASE 10: Config hot-reload ====================
phase "Config hot-reload (keep-last-good + new policy applied live)"
req GET /x "$(H reload.local)";  expect "before reload: reload.local unconfigured → default-allow (200)" "$CODE" 200
v1=$(curl -s "http://${HTTP}/configz" | grep '"version"' | head -1)
cat > "$CFG/hot.yaml" <<'YAML'
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: hot }
spec:
  domains:
    - host: "reload.local"
      policy: { mode: block, checks: { headers: { forbidden: ["X-Debug"] } } }
YAML
for _ in $(seq 1 20); do v2=$(curl -s "http://${HTTP}/configz" | grep '"version"' | head -1); [ "$v2" != "$v1" ] && break; sleep 0.25; done
req GET /x "$(H reload.local)" -H 'X-Debug: 1';  expect "after reload: new domain blocks X-Debug (403)" "$CODE" 403
[ "$v2" != "$v1" ] && P "config version changed on reload" || F "config version did not change"

echo
echo "--- counters ---"
curl -s "http://${HTTP}/metrics" | grep -E '^elchi_shield_requests_(allowed|blocked)_total|^elchi_shield_detections_total|^elchi_shield_shadow_detections_total' | sed 's/^/    /'
echo
echo "RESULT: $pass passed, $fail failed"
[ "$fail" = 0 ] && echo "E2E: ALL PASS" || echo "E2E: FAILURES"
exit $fail
