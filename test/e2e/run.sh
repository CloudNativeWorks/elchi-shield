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
ROWS="$(mktemp)"; CURPHASE="-"; LASTREQ=""
REPORT="${REPORT:-$DIR/report.html}"
# rec STATUS NAME [GOT] [WANT] — one TSV row per assertion for the HTML report.
rec(){ printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$CURPHASE" "$1" "$2" "${3-}" "${4-}" "$LASTREQ" >> "$ROWS"; }
P(){ echo "  PASS  $*"; pass=$((pass+1)); rec PASS "$*"; }
F(){ echo "  FAIL  $*"; fail=$((fail+1)); rec FAIL "$*"; }
phase(){ echo; echo "== $* =="; CURPHASE="$*"; LASTREQ=""; }
expect(){
  if [ "$2" = "$3" ]; then echo "  PASS  $1"; pass=$((pass+1)); rec PASS "$1" "$2" "$3"
  else echo "  FAIL  $1 (got '$2' want '$3')"; fail=$((fail+1)); rec FAIL "$1" "$2" "$3"; fi
}

req(){ # req METHOD PATH [extra curl args...] ; sets $CODE, dumps headers to /tmp/eh
  local m="$1" p="$2"; shift 2
  LASTREQ="$m $p"
  CODE=$(curl -s -D /tmp/eh -o /tmp/eb -w '%{http_code}' -X "$m" "$@" "http://127.0.0.1:${PORT}${p}")
}
hashdr(){ grep -qi "^$1:" /tmp/eh; }
msum(){ curl -s "http://${HTTP}/metrics" | awk -v re="$1" '$0 ~ re {s+=$2} END{print s+0}'; }
H(){ printf -- '-HHost:%s' "$1"; }   # host header arg

# ---------------- bring up the stack ----------------
( cd "$ROOT" && go build -tags "coraza httpsig openapi" -o "$DIR/elchi-shield.bin" ./cmd/elchi-shield ) || { echo "build failed"; exit 1; }
go build -o "$DIR/gentoken.bin" "$DIR/gentoken" || { echo "gentoken build failed"; exit 1; }
go build -o "$DIR/gensig.bin" "$DIR/gensig" || { echo "gensig build failed"; exit 1; }
go build -o "$DIR/genjwks.bin" "$DIR/genjwks" || { echo "genjwks build failed"; exit 1; }
# Build the echo to a binary (not `go run`) so the PID we track IS the listener —
# `go run` leaves a child process holding the port that a kill of $! would miss.
go build -o "$DIR/echo.bin" "$DIR/echo" || { echo "echo build failed"; exit 1; }

CFG="$(mktemp -d)"
# Substitute __CFG__ with the live config dir so feed-file paths resolve.
sed "s#__CFG__#${CFG}#g" "$DIR/policy/e2e.yaml" > "$CFG/e2e.yaml"
# Threat feed consumed by the ip_reputation engine (test IPs set via XFF below).
printf '# e2e threat feed\n198.51.100.0/24\n2001:db8:bad::/48\n' > "$CFG/threat-feed.txt"
# MaxMind test Country DB for the GeoIP cases (81.2.69.142→GB, 89.160.20.128→SE).
cp "$ROOT/internal/geoip/testdata/GeoLite2-Country-Test.mmdb" "$CFG/geo-country.mmdb"
# Verified-bot IP feed for the bot engine (a Googlebot range).
printf '# googlebot ranges\n66.249.64.0/19\n' > "$CFG/googlebot.txt"
# OpenAPI spec for the openapi engine (.oas extension so the config watcher
# doesn't try to parse it as a SecurityPolicy).
cat > "$CFG/api-spec.oas" <<'OAS'
openapi: 3.0.0
info: {title: e2e, version: 1.0.0}
paths:
  /oas/users/{id}:
    get:
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
        - {name: q, in: query, required: true, schema: {type: string}}
      responses: {'200': {description: ok}}
  /oas/create:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema: {type: object, required: [name], properties: {name: {type: string}}}
      responses: {'200': {description: ok}}
OAS
# JWKS file + RS256 tokens for the jwks engine (valid token line 1, invalid line 2).
JWT_OUT=$("$DIR/genjwks.bin" -out "$CFG/jwks.keyset" -kid k1 -aud api)
JWKS_VALID=$(printf '%s\n' "$JWT_OUT" | sed -n 1p)
JWKS_BAD=$(printf '%s\n' "$JWT_OUT" | sed -n 2p)
PIDS=()
cleanup(){ for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null; done; rm -rf "$CFG" "$DIR/elchi-shield.bin" "$DIR/gentoken.bin" "$DIR/gensig.bin" "$DIR/genjwks.bin" "$DIR/echo.bin" "$ROWS" /tmp/eh /tmp/eb /tmp/*.gz /tmp/good.zz; }
trap cleanup EXIT

ECHO_ADDR=127.0.0.1:18080 "$DIR/echo.bin" & PIDS+=($!)
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
BROWSER='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
# JWT tokens
VALID=$("$DIR/gentoken.bin" -secret e2e-secret -aud api -sub u1 -exp 3600)
EXPIRED=$("$DIR/gentoken.bin" -secret e2e-secret -aud api -sub u1 -exp -10)
WRONGSIG=$("$DIR/gentoken.bin" -secret wrong -aud api -sub u1 -exp 3600)
NOAUD=$("$DIR/gentoken.bin" -secret e2e-secret -sub u1 -exp 3600)
ALGNONE=$("$DIR/gentoken.bin" -alg none -aud api -sub u1 -exp 3600)            # unsigned
ALGHS384=$("$DIR/gentoken.bin" -alg HS384 -secret e2e-secret -aud api -sub u1) # disallowed alg
NOSUB=$("$DIR/gentoken.bin" -secret e2e-secret -aud api -sub '' -exp 3600)     # missing required claim
NOTYET=$("$DIR/gentoken.bin" -secret e2e-secret -aud api -sub u1 -nbf 3600)    # nbf in the future
ISS_OK=$("$DIR/gentoken.bin" -secret e2e-secret -aud api -sub u1 -iss https://issuer.example.com)
ISS_BAD=$("$DIR/gentoken.bin" -secret e2e-secret -aud api -sub u1 -iss https://evil.example.com)

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
req POST /json "$AH" -H 'Content-Type: application/json';                       expect "empty body + require_json → allowed (200)" "$CODE" 200
req POST /json "$AH" -H 'Content-Type: application/vnd.api+json' --data '{"ok":true}'; expect "vendor +json content-type accepted → 200" "$CODE" 200
req POST /small "$AH" --data 'this body is much larger than sixteen bytes';    expect "over-limit body (truncation) → 403" "$CODE" 403
req POST /small "$AH" --data 'tiny';                                           expect "within-limit body → 200" "$CODE" 200

# ---- Sensitive-data detector: every pattern class ----
req POST /pii "$AH" --data 'card 4111 1111 1111 1111 here';                    expect "PII: credit card (Luhn) → 403" "$CODE" 403
req POST /pii "$AH" --data 'key=AKIAIOSFODNN7EXAMPLE rest';                    expect "PII: AWS access key → 403" "$CODE" 403
req POST /pii "$AH" --data 'token ghp_0123456789abcdef0123456789abcdef0123';  expect "PII: GitHub token → 403" "$CODE" 403
req POST /pii "$AH" --data "tok $VALID end";                                   expect "PII: JWT in body → 403" "$CODE" 403
req POST /pii "$AH" --data '-----BEGIN PRIVATE KEY----- MIIE...';             expect "PII: private key block → 403" "$CODE" 403
req POST /pii "$AH" --data '4111 1111 1111 1112 invalid';                     expect "PII: non-Luhn number → allowed (200)" "$CODE" 200
req POST /pii "$AH" --data 'nothing sensitive here';                          expect "PII: clean body → 200" "$CODE" 200

# ---- Content-Encoding decode (gzip/deflate/brotli/stacked) ----
printf '%s' '{bad json' | gzip > /tmp/bad.gz
req POST /gzip "$AH" -H 'Content-Type: application/json' -H 'Content-Encoding: gzip' --data-binary @/tmp/bad.gz; expect "gzip decoded → invalid JSON → 403" "$CODE" 403
printf '%s' '{"ok":true}' | gzip > /tmp/good.gz
req POST /gzip "$AH" -H 'Content-Type: application/json' -H 'Content-Encoding: gzip' --data-binary @/tmp/good.gz; expect "gzip decoded → valid JSON → 200" "$CODE" 200
req POST /gzip "$AH" -H 'Content-Type: application/json' -H 'Content-Encoding: br' --data-binary @/tmp/good.gz;   expect "brotli (undecodable) → blocked (403)" "$CODE" 403
req POST /gzip "$AH" -H 'Content-Type: application/json' -H 'Content-Encoding: gzip, gzip' --data-binary @/tmp/good.gz; expect "stacked encodings → blocked (403)" "$CODE" 403
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import zlib,sys; sys.stdout.buffer.write(zlib.compress(b"{\"ok\":true}"))' > /tmp/good.zz
  req POST /gzip "$AH" -H 'Content-Type: application/json' -H 'Content-Encoding: deflate' --data-binary @/tmp/good.zz; expect "deflate decoded → valid JSON → 200" "$CODE" 200
fi

# ==================== PHASE 4: Engines — JWT ====================
phase "Engine: JWT"
req GET /jwt "$AH" -H "Authorization: Bearer $VALID";    expect "valid JWT → 200" "$CODE" 200
req GET /jwt "$AH";                                       expect "missing JWT → 403" "$CODE" 403
req GET /jwt "$AH" -H "Authorization: Bearer $WRONGSIG"; expect "wrong-signature JWT → 403" "$CODE" 403
req GET /jwt "$AH" -H "Authorization: Bearer $EXPIRED";  expect "expired JWT → 403" "$CODE" 403
req GET /jwt "$AH" -H "Authorization: Bearer $NOAUD";    expect "wrong/missing audience → 403" "$CODE" 403
req GET /jwt "$AH" -H "Authorization: Bearer $ALGNONE";  expect "alg:none unsigned token → 403" "$CODE" 403
req GET /jwt "$AH" -H "Authorization: Bearer $ALGHS384"; expect "disallowed algorithm (HS384) → 403" "$CODE" 403
req GET /jwt "$AH" -H "Authorization: Bearer $NOSUB";    expect "missing required claim (sub) → 403" "$CODE" 403
req GET /jwt "$AH" -H "Authorization: Bearer $NOTYET";   expect "not-yet-valid (nbf future) → 403" "$CODE" 403
req GET /jwt "$AH" -H "Authorization: Bearer garbage.token.here"; expect "malformed token → 403" "$CODE" 403
req GET /jwt-iss "$AH" -H "Authorization: Bearer $ISS_OK";  expect "issuer match → 200" "$CODE" 200
req GET /jwt-iss "$AH" -H "Authorization: Bearer $ISS_BAD"; expect "issuer mismatch → 403" "$CODE" 403

# ==================== PHASE 5: Engines — rate limit ====================
phase "Engine: rate limit"
got=0; ra=0
for _ in $(seq 1 6); do req GET /rl "$AH"; [ "$CODE" = 429 ] && { got=1; hashdr 'retry-after' && ra=1; }; done
expect "per-IP rate limit → 429 seen" "$got" 1
expect "429 carries Retry-After" "$ra" 1
gh=0; for _ in $(seq 1 3); do req GET /rl-hdr "$AH" -H 'X-Api-Key: k1'; [ "$CODE" = 429 ] && gh=1; done
expect "per-header rate limit (k1) → 429 seen" "$gh" 1
req GET /rl-hdr "$AH" -H 'X-Api-Key: brand-new-key';    expect "different key → independent bucket (200)" "$CODE" 200
hh=0; for _ in $(seq 1 3); do req GET /rl-host "$AH"; [ "$CODE" = 429 ] && hh=1; done
expect "per-host rate limit → 429 seen" "$hh" 1
# Token-bucket refill: after the rps window the bucket recovers and allows again.
sleep 1.2; req GET /rl-host "$AH";                      expect "rate limit refills after window → 200" "$CODE" 200

# ==================== PHASE 5b: Engine — IP reputation ====================
# Source IP is taken from the first X-Forwarded-For token (Envoy appends the real
# downstream hop after it), so each case pins a deterministic test IP.
phase "Engine: IP reputation"
req GET /ip-deny  "$AH" -H 'X-Forwarded-For: 203.0.113.9';   expect "deny CIDR hit → 403" "$CODE" 403
req GET /ip-deny  "$AH" -H 'X-Forwarded-For: 8.8.8.8';       expect "deny CIDR miss → 200" "$CODE" 200
req GET /ip-allow "$AH" -H 'X-Forwarded-For: 10.1.2.3';      expect "allowlist hit → 200" "$CODE" 200
req GET /ip-allow "$AH" -H 'X-Forwarded-For: 8.8.8.8';       expect "allowlist default-deny miss → 403" "$CODE" 403
req GET /ip-feed  "$AH" -H 'X-Forwarded-For: 198.51.100.7';  expect "threat-feed hit → 403" "$CODE" 403
req GET /ip-feed  "$AH" -H 'X-Forwarded-For: 1.1.1.1';       expect "threat-feed miss → 200" "$CODE" 200
req GET /ip-geo   "$AH" -H 'X-Forwarded-For: 81.2.69.142';   expect "GeoIP blocked country (GB) → 403" "$CODE" 403
req GET /ip-geo   "$AH" -H 'X-Forwarded-For: 89.160.20.128'; expect "GeoIP other country (SE) → 200" "$CODE" 200

# ==================== PHASE 5c: Engine — Bot detection ====================
phase "Engine: Bot detection"
AL='Accept-Language: en-US'
req GET /bot "$AH" -A 'python-requests/2.28' -H "$AL";  expect "UA deny (python-requests) → 403" "$CODE" 403
req GET /bot "$AH" -A 'curl/8.1.2' -H "$AL";            expect "UA deny (curl) → 403" "$CODE" 403
req GET /bot "$AH" -A '' -H "$AL";                      expect "empty User-Agent → 403" "$CODE" 403
req GET /bot "$AH" -A "$BROWSER" -H "$AL";              expect "clean browser → 200" "$CODE" 200
req GET /bot "$AH" -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -H 'X-Forwarded-For: 66.249.64.10' -H "$AL"; expect "verified Googlebot → 200" "$CODE" 200
req GET /bot "$AH" -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -H 'X-Forwarded-For: 1.2.3.4' -H "$AL";       expect "Googlebot impersonation → 403" "$CODE" 403
req GET /bot "$AH" -A "$BROWSER" -H 'x-shield-ja4: t13d-known-bad-ja4' -H "$AL"; expect "denied JA4 fingerprint → 403" "$CODE" 403
req GET /bot "$AH" -A "$BROWSER" -H 'x-shield-ja4: t13d-curl-tool-ja4' -H "$AL"; expect "JA4 tool vs browser-UA mismatch → 403" "$CODE" 403
req GET /bot "$AH" -A "$BROWSER";                       expect "missing Accept-Language heuristic → 403" "$CODE" 403

# ==================== PHASE 5d: Engines — API-key & HMAC signing ====================
phase "Engine: API-key & HMAC signing"
req GET /apikey "$AH" -H 'X-Api-Key: e2e-api-key-1';   expect "valid API key → 200" "$CODE" 200
req GET /apikey "$AH" -H 'X-Api-Key: nope';            expect "unknown API key → 403" "$CODE" 403
req GET /apikey "$AH";                                  expect "missing API key → 403" "$CODE" 403
req GET /apikey/admin "$AH" -H 'X-Api-Key: e2e-api-key-1'; expect "key lacks admin scope → 403" "$CODE" 403
req GET /apikey/admin "$AH" -H 'X-Api-Key: e2e-admin-key'; expect "key with admin scope → 200" "$CODE" 200
# HMAC: sign the canonical "METHOD\npath\nts\nnonce\ndigest" with openssl.
HS=e2e-hmac-secret; TS=$(date +%s)
sig(){ printf 'GET\n/hmac\n%s\n%s\n%s' "$1" "$2" "$3" | openssl dgst -sha256 -hmac "$HS" | awk '{print $NF}'; }
SIG=$(sig "$TS" '' '')
req GET /hmac "$AH" -H "X-Signature: $SIG" -H "X-Timestamp: $TS";  expect "valid HMAC signature → 200" "$CODE" 200
req GET /hmac "$AH" -H "X-Signature: deadbeef00" -H "X-Timestamp: $TS"; expect "tampered signature → 403" "$CODE" 403
req GET /hmac "$AH";                                               expect "missing signature → 403" "$CODE" 403
OLD=$((TS-600)); SIGO=$(sig "$OLD" '' '')
req GET /hmac "$AH" -H "X-Signature: $SIGO" -H "X-Timestamp: $OLD"; expect "stale timestamp → 403" "$CODE" 403
NONCE="n-$TS"; SIGN=$(sig "$TS" "$NONCE" '')
req GET /hmac "$AH" -H "X-Signature: $SIGN" -H "X-Timestamp: $TS" -H "X-Nonce: $NONCE"; expect "first nonce use → 200" "$CODE" 200
req GET /hmac "$AH" -H "X-Signature: $SIGN" -H "X-Timestamp: $TS" -H "X-Nonce: $NONCE"; expect "replayed nonce → 403" "$CODE" 403
# RFC 9421 (httpsig build tag): sign @method/@authority/@path with gensig.
SIGSECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SO=$("$DIR/gensig.bin" -secret "$SIGSECRET" -method GET -host api.example.com -path /sig)
RSI=$(printf '%s\n' "$SO" | sed -n 1p); RSIG=$(printf '%s\n' "$SO" | sed -n 2p)
req GET /sig "$AH" -H "Signature-Input: $RSI" -H "Signature: $RSIG"; expect "valid RFC 9421 signature → 200" "$CODE" 200
req GET /sig "$AH";                                                   expect "missing RFC 9421 signature → 403" "$CODE" 403
SO2=$("$DIR/gensig.bin" -secret "$SIGSECRET" -method GET -host api.example.com -path /other)
RSI2=$(printf '%s\n' "$SO2" | sed -n 1p); RSIG2=$(printf '%s\n' "$SO2" | sed -n 2p)
req GET /sig "$AH" -H "Signature-Input: $RSI2" -H "Signature: $RSIG2"; expect "signature for a different path → 403" "$CODE" 403

# ==================== PHASE 5e: Engines — JWKS & mTLS (XFCC) ====================
phase "Engine: JWKS & mTLS (XFCC)"
req GET /jwks "$AH" -H "Authorization: Bearer $JWKS_VALID"; expect "valid RS256 (JWKS file) → 200" "$CODE" 200
req GET /jwks "$AH" -H "Authorization: Bearer $JWKS_BAD";   expect "token signed by non-JWKS key → 403" "$CODE" 403
req GET /jwks "$AH";                                        expect "missing JWT → 403" "$CODE" 403
req GET /xfcc "$AH" -H 'x-test-client-cert: URI=spiffe://cluster/ns/team/sa/web'; expect "XFCC SPIFFE URI allow-listed → 200" "$CODE" 200
req GET /xfcc "$AH" -H 'x-test-client-cert: DNS=client.example.com';              expect "XFCC DNS allow-listed → 200" "$CODE" 200
req GET /xfcc "$AH" -H 'x-test-client-cert: URI=spiffe://cluster/ns/evil/sa/x';   expect "XFCC identity not allow-listed → 403" "$CODE" 403
req GET /xfcc "$AH";                                        expect "XFCC required but absent → 403" "$CODE" 403

# ==================== PHASE 5f: Engine — GraphQL guard ====================
phase "Engine: GraphQL guard"
GQ='Content-Type: application/json'
req POST /graphql "$AH" -H "$GQ" --data '{"query":"{ a b }"}';                         expect "simple query → 200" "$CODE" 200
req POST /graphql "$AH" -H "$GQ" --data '{"query":"{ a { b { c { d { e } } } } }"}';   expect "depth > 4 → 403" "$CODE" 403
req POST /graphql "$AH" -H "$GQ" --data '{"query":"{ __schema { types { name } } }"}'; expect "introspection → 403" "$CODE" 403
req POST /graphql "$AH" -H "$GQ" --data '{"query":"{ a: f b: f c: f d: f }"}';         expect "aliases > 3 → 403" "$CODE" 403
req POST /graphql "$AH" -H "$GQ" --data '[{"query":"{a}"},{"query":"{b}"},{"query":"{c}"}]'; expect "batch > 2 → 403" "$CODE" 403
req POST /graphql "$AH" -H "$GQ" --data '{"query":"{ a {"}';                           expect "malformed query → 403" "$CODE" 403
req POST /graphql "$AH" -H 'Content-Type: text/plain' --data 'not graphql';           expect "non-GraphQL content-type → passthrough (200)" "$CODE" 200

# ==================== PHASE 5g: Engine — OpenAPI positive validation ====================
phase "Engine: OpenAPI validation (-tags openapi)"
req GET '/oas/users/5?q=hi' "$AH";                     expect "conforming request → 200" "$CODE" 200
req GET '/oas/users/abc?q=hi' "$AH";                   expect "path param wrong type → 403" "$CODE" 403
req GET '/oas/users/5' "$AH";                          expect "missing required query param → 403" "$CODE" 403
req GET '/oas/unknown' "$AH";                          expect "undeclared path → 403" "$CODE" 403
req POST /oas/create "$AH" -H 'Content-Type: application/json' --data '{"name":"alice"}'; expect "valid request body → 200" "$CODE" 200
req POST /oas/create "$AH" -H 'Content-Type: application/json' --data '{}';               expect "body missing required field → 403" "$CODE" 403

# ==================== PHASE 6: Engines — Coraza WAF ====================
phase "Engine: Coraza WAF (-tags coraza)"
req POST /waf "$AH" -H 'Content-Type: text/plain' --data 'q=1 union select password from users'; expect "SQLi (union select) → 403" "$CODE" 403
req POST /waf "$AH" -H 'Content-Type: text/plain' --data 'user=admin or 1=1';                     expect "SQLi (or 1=1) → 403" "$CODE" 403
req POST /waf "$AH" -H 'Content-Type: text/plain' --data 'c=<script>alert(1)</script>';           expect "XSS (<script>) → 403" "$CODE" 403
req POST /waf "$AH" -H 'Content-Type: text/plain' --data 'x=; cat /etc/passwd';                   expect "command injection → 403" "$CODE" 403
req POST /waf "$AH" -H 'Content-Type: text/plain' --data 'file=../../etc/passwd';                 expect "path traversal in body → 403" "$CODE" 403
req POST /waf "$AH" -A 'sqlmap/1.5' -H 'Content-Type: text/plain' --data 'q=hello';               expect "scanner User-Agent (phase:1) → 403" "$CODE" 403
req POST /waf "$AH" -H 'Content-Type: text/plain' --data 'q=hello world';                         expect "clean body → 200" "$CODE" 200
req POST /waf-detect "$AH" -H 'Content-Type: text/plain' --data 'q=1 union select x';             expect "WAF DetectionOnly: SQLi recorded but allowed (200)" "$CODE" 200
req GET '/waf-resp?resp=coraza' "$AH";   expect "WAF on response body (phase:4) → 403" "$CODE" 403
req GET '/waf-resp?resp=json' "$AH";     expect "WAF clean response → 200" "$CODE" 200

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
req GET '/resp?resp=pii' "$AH";      expect "non-JSON response + require_json → blocked (403)" "$CODE" 403
req GET '/resp-pii?resp=pii' "$AH";  expect "sensitive data in response → blocked (403)" "$CODE" 403
req GET '/resp-pii?resp=json' "$AH"; expect "clean response → allowed (200)" "$CODE" 200

# ==================== PHASE 9: Evasion, normalization & skip_checks ====================
phase "Evasion, normalization & skip_checks"
# An attacker must not dodge the /p/ block policy via traversal or extra slashes;
# the path is normalized (percent-decode + dot-segment collapse) before matching.
req GET '/p/../p/other' "$AH" -H 'X-Debug: 1';  expect "dot-segment traversal still hits /p/ block → 403" "$CODE" 403
req GET '//p//other' "$AH" -H 'X-Debug: 1';     expect "duplicate slashes still hit /p/ block → 403" "$CODE" 403
req GET '/p/./health' "$AH" -H 'X-Debug: 1';    expect "normalized exact /p/health stays off → 200" "$CODE" 200
req GET '/block-hdr?x=1#frag' "$AH" -H 'X-Debug: 1'; expect "query/fragment stripped before match → 403" "$CODE" 403
# skip_checks omits the configured forbidden-header check for this route.
req GET /skip "$AH" -H 'X-Debug: 1';            expect "skip_checks bypasses forbidden header → 200" "$CODE" 200

# ==================== PHASE 10: Observability ====================
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

# ==================== PHASE 11: Config hot-reload ====================
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
COUNTERS="$(curl -s "http://${HTTP}/metrics" | grep -E '^elchi_shield_requests_(allowed|blocked)_total|^elchi_shield_detections_total|^elchi_shield_shadow_detections_total')"
echo "$COUNTERS" | sed 's/^/    /'

# ---------------- HTML report ----------------
# Render every recorded assertion (phase / rule / expected / got / result) into a
# self-contained dark-themed page. Pure awk over the TSV; no external deps.
gen_report(){
  local ts envoy ctok conffile
  ts="$(date '+%Y-%m-%d %H:%M:%S %Z')"
  envoy="$( { [ -n "${ENVOY:-}" ] && "$ENVOY" --version; } 2>/dev/null | head -1 || true)"; [ -n "$envoy" ] || envoy="func-e · Envoy 1.36.3"
  # BSD awk can't take a multi-line -v value; join counter lines with a token and
  # expand it back to newlines inside awk (cnl).
  ctok="$(printf '%s' "$COUNTERS" | awk 'NR>1{printf "~|~"}{printf "%s",$0}')"
  # Build a JS map path -> route YAML block, parsed straight from the policy file,
  # so each row can reveal "how this rule is configured". The block is emitted as
  # JS-string-escaped lines (\n line separator) and read into awk via getline,
  # which sidesteps -v escape processing.
  conffile="$(mktemp)"
  awk '
    function js(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); return s }
    function flush(){ if(key!="") printf "\"%s\": \"%s\",\n", key, blk; key=""; blk="" }
    /^ *#/ { next }
    /^ *$/ { next }
    /^        - match:/ {
      flush(); blk=js($0); key=""
      if(match($0,/path_prefix: *"[^"]*"/)){ t=substr($0,RSTART,RLENGTH); sub(/path_prefix: *"/,"",t); sub(/"$/,"",t); key=t }
      else if(match($0,/path_exact: *"[^"]*"/)){ t=substr($0,RSTART,RLENGTH); sub(/path_exact: *"/,"",t); sub(/"$/,"",t); key=t }
      next
    }
    /^    - host:/ { flush(); next }
    /^  [a-zA-Z]/ { flush(); next }
    { if(key!=""){ if(blk!="") blk=blk "\\n" js($0); else blk=js($0) } }
    END { flush() }
  ' "$DIR/policy/e2e.yaml" > "$conffile"
  awk -F'\t' -v pass="$pass" -v fail="$fail" -v ts="$ts" -v envoy="$envoy" -v counters="$ctok" -v conffile="$conffile" '
    function esc(s){ gsub(/&/,"\\&amp;",s); gsub(/</,"\\&lt;",s); gsub(/>/,"\\&gt;",s); return s }
    function cnl(s){ s=esc(s); gsub(/~\|~/,"\n",s); return s }
    { ph[NR]=$1; st[NR]=$2; nm[NR]=$3; got[NR]=$4; want[NR]=$5; rq[NR]=$6; n=NR }
    END {
      total=pass+fail; pct=(total>0)?int(pass*100/total):0
      ok=(fail==0)
      print "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
      print "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      print "<title>elchi-shield · e2e report</title><style>"
      print ":root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--line:#30363d;--fg:#e6edf3;--muted:#8b949e;--ok:#3fb950;--bad:#f85149;--okbg:#12361f;--badbg:#3d1418;--accent:#58a6ff}"
      print "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}"
      print ".wrap{max-width:1040px;margin:0 auto;padding:28px 20px 60px}"
      print "h1{font-size:20px;margin:0 0 4px;display:flex;align-items:center;gap:10px}.sub{color:var(--muted);font-size:12px;margin-bottom:20px}"
      print ".cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}"
      print ".card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.card .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}.card .v{font-size:24px;font-weight:700;margin-top:4px}"
      print ".v.ok{color:var(--ok)}.v.bad{color:var(--bad)}"
      print ".bar{height:8px;border-radius:99px;background:var(--badbg);overflow:hidden;margin:6px 0 22px}.bar>i{display:block;height:100%;background:var(--ok)}"
      print ".pill{font-size:12px;padding:3px 10px;border-radius:99px;font-weight:700}.pill.ok{background:var(--okbg);color:var(--ok)}.pill.bad{background:var(--badbg);color:var(--bad)}"
      print ".toolbar{margin:0 0 14px}.toolbar button{background:var(--panel2);color:var(--fg);border:1px solid var(--line);border-radius:7px;padding:6px 12px;cursor:pointer;font:inherit}.toolbar button.on{border-color:var(--accent);color:var(--accent)}"
      print "section{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin:0 0 14px;overflow:hidden}"
      print "section>h2{font-size:14px;margin:0;padding:11px 16px;background:var(--panel2);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none}"
      print "section.fail>h2{box-shadow:inset 3px 0 0 var(--bad)}section.ok>h2{box-shadow:inset 3px 0 0 var(--ok)}"
      print "section>h2 .lhs{display:flex;align-items:center;gap:9px}.chev{display:inline-block;transition:transform .15s;color:var(--muted);font-size:11px}section.collapsed .chev{transform:rotate(-90deg)}section.collapsed table{display:none}"
      print ".pc{font-size:12px;color:var(--muted);font-weight:600}"
      print "table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 16px;border-bottom:1px solid var(--line);vertical-align:top}"
      print "th{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;font-weight:600}tr:last-child td{border-bottom:0}"
      print "td.rule{width:44%}td.rule .tw{display:inline-block;width:11px;color:var(--muted)}td.req code{color:var(--accent);font-size:12px}.exp{color:var(--muted)}td.code{font-weight:700}"
      print "tr.bad{background:rgba(248,81,73,.06)}tr.row{cursor:pointer}tr.row:hover{background:rgba(88,166,255,.07)}tr.row.open .tw{transform:rotate(90deg);display:inline-block}"
      print ".badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px}.badge.ok{background:var(--okbg);color:var(--ok)}.badge.bad{background:var(--badbg);color:var(--bad)}"
      print "tr.detail{display:none}tr.detail>td{padding:0 16px 14px;background:#0b0f15}tr.detail .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin:10px 0 4px}"
      print "tr.detail pre.conf{margin:0;padding:12px 14px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:#cdd9e5;font-size:12px;white-space:pre;overflow:auto}"
      print "pre{margin:0;padding:14px 16px;color:var(--muted);font-size:12px;overflow:auto;white-space:pre-wrap}"
      print "</style></head><body><div class=\"wrap\">"
      print "<h1>🛡️ elchi-shield <span class=\"pill " (ok?"ok\">PASS":"bad\">FAIL") "</span></h1>"
      print "<div class=\"sub\">End-to-end · real Envoy · " esc(envoy) " · " esc(ts) "</div>"
      print "<div class=\"cards\">"
      print "<div class=\"card\"><div class=\"k\">Total</div><div class=\"v\">" total "</div></div>"
      print "<div class=\"card\"><div class=\"k\">Passed</div><div class=\"v ok\">" pass "</div></div>"
      print "<div class=\"card\"><div class=\"k\">Failed</div><div class=\"v " (fail>0?"bad":"") "\">" fail "</div></div>"
      print "<div class=\"card\"><div class=\"k\">Pass rate</div><div class=\"v\">" pct "%</div></div></div>"
      print "<div class=\"bar\"><i style=\"width:" pct "%\"></i></div>"
      print "<div class=\"toolbar\"><button id=\"bAll\" class=\"on\" onclick=\"flt(0)\">All " total "</button> <button id=\"bBad\" onclick=\"flt(1)\">Failed " fail "</button></div>"
      prev=""
      for(i=1;i<=n;i++){
        if(ph[i]!=prev){
          if(prev!="") print "</tbody></table></section>"
          pp=0; pf=0
          for(j=i;j<=n && ph[j]==ph[i];j++){ if(st[j]=="PASS")pp++; else pf++ }
          prev=ph[i]
          print "<section class=\"" (pf>0?"fail":"ok") "\"><h2 onclick=\"toggleSec(this)\"><span class=\"lhs\"><span class=\"chev\">&#9660;</span><span>" esc(ph[i]) "</span></span><span class=\"pc\">" pp "/" (pp+pf) " passed</span></h2>"
          print "<table><thead><tr><th>Test / rule</th><th>Request</th><th>Expected</th><th>Got</th><th>Result</th></tr></thead><tbody>"
        }
        rc=(st[i]=="PASS")?"ok":"bad"
        w=(want[i]=="")?"&mdash;":esc(want[i]); g=(got[i]=="")?"&mdash;":esc(got[i])
        rqs=(rq[i]=="")?"&mdash;":("<code>"esc(rq[i])"</code>")
        # Strip "METHOD " and "?query" from the request to get the route path used
        # to look up its config on click.
        rp=rq[i]; sub(/^[A-Z]+ /,"",rp); sub(/\?.*$/,"",rp)
        if(rp!=""){
          print "<tr class=\"row " rc "\" data-path=\"" esc(rp) "\" onclick=\"toggleRow(this)\"><td class=\"rule\"><span class=\"tw\">&#9656;</span> " esc(nm[i]) "</td><td class=\"req\">" rqs "</td><td class=\"exp\">" w "</td><td class=\"code\">" g "</td><td><span class=\"badge " rc "\">" (rc=="ok"?"PASS":"FAIL") "</span></td></tr>"
          print "<tr class=\"detail " rc "\"><td colspan=\"5\"><div class=\"lbl\">Config — test/e2e/policy/e2e.yaml</div><pre class=\"conf\"></pre></td></tr>"
        } else {
          print "<tr class=\"" rc "\"><td class=\"rule\">" esc(nm[i]) "</td><td class=\"req\">" rqs "</td><td class=\"exp\">" w "</td><td class=\"code\">" g "</td><td><span class=\"badge " rc "\">" (rc=="ok"?"PASS":"FAIL") "</span></td></tr>"
        }
      }
      if(prev!="") print "</tbody></table></section>"
      print "<section class=\"ok\"><h2 onclick=\"toggleSec(this)\"><span class=\"lhs\"><span class=\"chev\">&#9660;</span><span>Metric counters</span></span></h2><pre>" cnl(counters) "</pre></section>"
      print "<script>var CONF={"
      while((getline cl < conffile) > 0) print cl
      print "};"
      print "function bestConf(p){var best=\"\",bl=-1;for(var k in CONF){if(p===k||p.indexOf(k)===0){if(k.length>bl){bl=k.length;best=k}}}return best?CONF[best]:\"\"}"
      print "function toggleRow(tr){var d=tr.nextElementSibling;if(!d||!d.classList.contains(\"detail\"))return;var open=d.style.display===\"table-row\";d.style.display=open?\"none\":\"table-row\";tr.classList.toggle(\"open\",!open);if(!open&&!d.dataset.filled){var c=bestConf(tr.dataset.path||\"\");d.querySelector(\"pre\").textContent=c?c:\"(route düzeyinde config yok — domain default / host-level policy geçerli)\";d.dataset.filled=\"1\"}}"
      print "function toggleSec(h){h.parentElement.classList.toggle(\"collapsed\")}"
      print "function flt(b){document.getElementById(\"bAll\").classList.toggle(\"on\",!b);document.getElementById(\"bBad\").classList.toggle(\"on\",b);document.querySelectorAll(\"tr.detail\").forEach(function(d){d.style.display=\"none\";var p=d.previousElementSibling;if(p)p.classList.remove(\"open\")});document.querySelectorAll(\"tr.row,tr.ok,tr.bad\").forEach(function(r){if(r.classList.contains(\"detail\"))return;r.style.display=(b&&r.classList.contains(\"ok\"))?\"none\":\"\"});document.querySelectorAll(\"section\").forEach(function(s){if(b){var v=s.querySelectorAll(\"tr.bad\").length;s.style.display=v?\"\":\"none\"}else s.style.display=\"\"})}"
      print "</script>"
      print "</div>"
      print "</body></html>"
    }' "$ROWS" > "$REPORT"
  rm -f "$conffile"
}
gen_report
echo
echo "RESULT: $pass passed, $fail failed"
echo "REPORT: $REPORT"
[ -z "${CI:-}" ] && command -v open >/dev/null 2>&1 && open "$REPORT" 2>/dev/null
[ "$fail" = 0 ] && echo "E2E: ALL PASS" || echo "E2E: FAILURES"
exit $fail
