#!/usr/bin/env bash
# ============================================================================
#  elchi-shield — continuous attack loop (demo)
# ============================================================================
# Fires a categorised stream of malicious/invalid requests at Envoy so that
# elchi-shield blocks them. Each line pairs with a route in demo-block-policy.yaml.
#
#   TARGET   base URL of the Envoy listener   (default http://localhost:10000)
#   SLEEP    seconds between rounds            (default 2)
#   HOSTHDR  Host header to send              (default demo.local)
#
# Usage:
#   ./demo-attack-loop.sh
#   TARGET=http://10.0.0.5:8080 SLEEP=1 ./demo-attack-loop.sh
#
# Expected: BLOCKED (403, or 429 for the rate limiter). A green line = shield
# blocked it. A red line = it got through (shield not in path, config not loaded,
# or that engine needs extra setup — see notes below).
# ============================================================================
set -u

TARGET="${TARGET:-https://api.otofiyatlist.com}"
SLEEP="${SLEEP:-2}"
HOSTHDR="${HOSTHDR:-demo.local}"

GREEN=$'\033[32m'; RED=$'\033[31m'; DIM=$'\033[2m'; YEL=$'\033[33m'; RST=$'\033[0m'

TOTAL=0; BLOCKED=0; LEAKED=0

# hit <name> <path> [extra curl args...] — expects the request to be BLOCKED.
hit() {
    local name="$1" path="$2"; shift 2
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 \
        -H "Host: $HOSTHDR" "$@" "$TARGET$path" 2>/dev/null)
    TOTAL=$((TOTAL+1))
    if [ "$code" = "403" ] || [ "$code" = "429" ]; then
        BLOCKED=$((BLOCKED+1))
        printf '  %sBLOCKED%s  %-16s %s(%s)%s\n' "$GREEN" "$RST" "$name" "$DIM" "$code" "$RST"
    else
        LEAKED=$((LEAKED+1))
        printf '  %sLEAKED %s  %-16s %s(got %s, expected 403/429)%s\n' "$RED" "$RST" "$name" "$DIM" "$code" "$RST"
    fi
}

# baseline <name> <path> — a clean request that should NOT be blocked.
baseline() {
    local name="$1" path="$2"
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -H "Host: $HOSTHDR" "$TARGET$path" 2>/dev/null)
    if [ "$code" = "403" ]; then
        printf '  %sFALSE-POS%s %-16s %s(clean request got 403)%s\n' "$YEL" "$RST" "$name" "$DIM" "$RST"
    else
        printf '  %sallowed%s  %-16s %s(%s)%s\n' "$DIM" "$RST" "$name" "$DIM" "$code" "$RST"
    fi
}

# rate_limit flood: many quick requests with the same key → some must be 429.
flood() {
    local n=8 code blocked=0
    for _ in $(seq 1 "$n"); do
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 \
            -H "Host: $HOSTHDR" -H "X-Demo-Client: attacker" "$TARGET/ratelimit/x" 2>/dev/null)
        [ "$code" = "429" ] && blocked=$((blocked+1))
    done
    TOTAL=$((TOTAL+1))
    if [ "$blocked" -gt 0 ]; then
        BLOCKED=$((BLOCKED+1))
        printf '  %sBLOCKED%s  %-16s %s(%d/%d got 429)%s\n' "$GREEN" "$RST" "RateLimit flood" "$DIM" "$blocked" "$n" "$RST"
    else
        LEAKED=$((LEAKED+1))
        printf '  %sLEAKED %s  %-16s %s(no 429 — needs use_remote_address or the header key)%s\n' "$RED" "$RST" "RateLimit flood" "$DIM" "$RST"
    fi
}

trap 'printf "\n%sstopped%s — %d blocked / %d leaked of %d\n" "$DIM" "$RST" "$BLOCKED" "$LEAKED" "$TOTAL"; exit 0' INT

printf '%sTarget:%s %s   %sHost:%s %s   %sCtrl-C to stop%s\n' "$DIM" "$RST" "$TARGET" "$DIM" "$RST" "$HOSTHDR" "$DIM" "$RST"

round=0
while true; do
    round=$((round+1))
    printf '\n%s── round %d ──%s\n' "$DIM" "$round" "$RST"

    # 1. WAF — OWASP CRS (SQLi / XSS in the query string)
    hit "WAF SQLi"     "/waf/items?id=1%27%20OR%20%271%27%3D%271%20--%20"
    hit "WAF XSS"      "/waf/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    hit "WAF traversal" "/waf/file?p=../../../../etc/passwd"

    # 2. Rate limit (flood keyed by X-Demo-Client)
    flood

    # 3. Bot / scanner (bad + empty User-Agent)
    hit "Bot bad-UA"   "/bot/probe" -A "sqlmap/1.5.2"
    hit "Bot empty-UA" "/bot/probe" -A ""

    # 4. GraphQL abuse (depth 6 > max_depth 4)
    hit "GraphQL depth" "/graphql" -X POST \
        -H "Content-Type: application/json" \
        --data '{"query":"{ a { b { c { d { e { f } } } } } }"}'

    # 5. DLP — a hard secret in the request body
    hit "DLP aws-key"  "/dlp/upload" -X POST \
        -H "Content-Type: application/json" \
        --data '{"note":"key is AKIAIOSFODNN7EXAMPLE"}'
    hit "DLP priv-key" "/dlp/upload" -X POST \
        -H "Content-Type: text/plain" \
        --data $'-----BEGIN PRIVATE KEY-----\nMIIBVQ...\n-----END PRIVATE KEY-----'

    # 6-9. Auth engines — missing credential
    hit "JWT missing"     "/jwt/orders"
    hit "JWT bad-token"   "/jwt/orders" -H "Authorization: Bearer not.a.jwt"
    hit "APIKey missing"  "/apikey/orders"
    hit "APIKey wrong"    "/apikey/orders" -H "X-Api-Key: nope"
    hit "HMAC missing"    "/hmac/webhook" -X POST --data '{}'
    hit "HTTPSig missing" "/httpsig/orders"

    # 10. IP reputation (source IP in a deny CIDR; needs XFF/remote-addr honoured)
    hit "IPRep deny"   "/iprep/orders" -H "X-Forwarded-For: 192.0.2.66"

    # Baseline — a clean request that must NOT be blocked
    baseline "Legit request" "/health"

    printf '  %s%d blocked / %d leaked so far%s\n' "$DIM" "$BLOCKED" "$LEAKED" "$RST"
    sleep "$SLEEP"
done
