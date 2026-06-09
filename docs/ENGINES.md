# elchi-shield — Engine Behavior Guide

How each security engine actually behaves at request time: what it reads, how it
decides block vs allow, what every field does, the fail posture, and the security
gotchas you must watch out for.

This is the **behavior** companion to [`docs/CONFIG-REFERENCE.md`](CONFIG-REFERENCE.md)
(the field/type/default schema). Read the reference for *what to type*; read this
for *what happens when you do*.

> All engines are compiled into the single binary — there are no build tags.

## Contents
- [The engine model (read this first)](#the-engine-model)
- [Authentication engines](#authentication-engines): [jwt](#jwt) · [jwks](#jwks) · [api_key](#api_key) · [hmac_sign](#hmac_sign) · [http_signature](#http_signature) · [xfcc](#xfcc)
- [Traffic & reputation engines](#traffic--reputation-engines): [rate_limit](#rate_limit) · [ip_reputation](#ip_reputation) · [bot](#bot)
- [Content-inspection engines](#content-inspection-engines): [coraza](#coraza-owasp-crs) · [graphql](#graphql) · [openapi](#openapi) · [DLP & sensitive data](#dlp--sensitive-data)
- [Anomaly scoring](#anomaly-scoring)
- [Always-on body protections](#always-on-structural-body-protections)
- [Gotchas at a glance](#gotchas-at-a-glance)

---

## The engine model

Every engine implements one narrow interface over a **read-only** request view
(`Direction, Host, Path, Method, ContentType, SourceIP, Body, Headers`). Headers
are case-insensitive. Understanding five cross-cutting rules explains most engine
behavior:

**1. Header phase vs body phase.** An engine declares `RequiresBody()`:
- **`false` → header phase.** Runs in the cheap pre-body stage; the body is
  **never buffered** for it. (jwt, jwks, api_key, ip_reputation, bot, xfcc, and
  hmac_sign/http_signature/openapi *when not body-bound*.)
- **`true` → body phase.** Runs after the body is buffered (coraza, graphql,
  openapi-with-body, hmac_sign with `require_body_digest`, http_signature when it
  covers `content-digest`).

A policy whose engines don't need the body **never buffers the body just to run
the WAF**. Header-phase and body-phase engines are partitioned so **no engine
runs twice**.

**2. Direction.** Auth/traffic/bot engines are **request-side only** — they pass
responses through untouched. Only Coraza inspects responses (CRS phase 3/4).

**3. Credential-absent and credential-invalid both BLOCK — deterministically.**
Auth engines report a failed/missing credential as a **finding (a Block verdict),
never as a Go error**. There is no anonymous pass-through. Consequence:
**`fail_open`/`fail_close` does NOT govern a missing or bad credential** — those
always block. The fail posture only governs the rare case of an internal engine
*error* (e.g. Coraza body-processing failure, a GeoIP DB read error).

**4. Fail posture governs internal errors only.** When an engine returns an error
(not a block), the WAF stage applies the policy `fail_mode`:
- `fail_open` → allow, count `fail_open_total`.
- `fail_close` → block with a **fixed reason** (`fail_close_error` /
  `fail_close_timeout`); the underlying error string is **never** put in the
  audit reason (no-leak). Default when no policy resolves is fail-open, so a bug
  never blackholes traffic.
A **confirmed Block always beats an error** — if one engine blocks while another
errors, the request blocks.

**5. How multiple engines combine.** Within a policy, `engine.Set` runs the
engines **in the policy's order**, checking the per-request **deadline before each
engine** (a single synchronous engine is never preempted mid-flight — it runs to
completion and back-pressures the stream by design; bodies are size-capped and
the bundled engines are linear-time RE2). It returns the **highest-severity
Block** and **sums positive `Score` values** (see [Anomaly scoring](#anomaly-scoring)).

**Block status codes.** Auth/WAF/positive-security blocks are **403** (a 0 status
falls back to 403). Rate-limit is **429**. A Coraza rule that forces a status
(e.g. `status:418`) is honored.

**Source IP is trusted-hop-derived — never the leftmost XFF.** Every source-IP
control (ip-reputation, rate-limit-by-ip, bot verified-crawler check, Coraza
`REMOTE_ADDR`) reads `tx.SourceIP`, derived once: `X-Forwarded-For` is read **from
the RIGHT** — `index = len(tokens) - 1 - xff_trusted_hops`, default
`xff-trusted-hops = 0` (the address Envoy appended via `use_remote_address`).
Falls back to `X-Real-IP`. The result is canonicalized: `ip:port` tolerated, IPv6
zone stripped, **IPv4-in-IPv6 unmapped** (`::ffff:1.2.3.4 → 1.2.3.4`). The
leftmost token is client-controlled and is **never** used — reading it would let
any client forge its source IP and defeat every source-IP control.
> **Operator gotcha:** set `--xff-trusted-hops` to the exact number of trusted
> proxies in front of Envoy (LB/CDN). Too low → you trust a hop the attacker
> controls; too high → it clamps toward the spoofable left. And Envoy must run
> with `use_remote_address` or there's no trustworthy source IP to key on.

---

## Authentication engines

All header-phase, request-only, stateless except where noted. A failed credential
always blocks (see rule 3 above). Block reasons are fixed strings with stable rule
IDs and never embed the token/claim/library-error text.

### jwt
Validates a bearer JWT with a **static** key (no rotation — use `jwks` for that).

**Logic:** read the header (default `Authorization`) → missing/blank ⇒ block
`jwt.missing` → strip a case-insensitive `Bearer ` prefix → parse & verify →
any failure (bad signature, expired, wrong `iss`/`aud`, disallowed `alg`) ⇒ block
`jwt.invalid` → enforce `required_claims` (present **and** non-empty) ⇒ block
`jwt.missing_claim` → else allow. **A token with no `exp` is always rejected**
(`WithExpirationRequired`).

**Fields:** `algorithms` (required allow-list; becomes the valid-methods set),
`hmac_secret` XOR `public_key_file` (exactly one; checked against the alg family
at load), `issuer`/`audience` (exact match when set), `required_claims`,
`header_name` (default `Authorization`), `leeway` (default **0** = strict).

**Gotchas:**
- **Algorithm-confusion is doubly defended:** the valid-methods allow-list *plus*
  a type-gated key function that hands the HMAC secret only to HMAC methods and
  the public key only to asymmetric ones. `alg:none` is refused outright. A
  load-time check fails the build if a configured alg doesn't match the key type
  (so you learn at reload, not by silently rejecting every token).
- **`leeway: 0` is the default** — under real clock skew, tokens near `exp`/`nbf`
  get rejected. Set a small leeway (e.g. `30s`) in production.
- An empty-string/empty-array/empty-object claim counts as "missing"; numeric `0`
  and boolean `false` do **not**.

### jwks
Like `jwt`, but resolves the verification key by `kid` from a **JWK Set** (local
file or remote URL), enabling key rotation.

**Logic:** identical block flow (`jwks.missing` / `jwks.invalid` /
`jwks.missing_claim`). Key resolution looks up the token's `kid` in an in-memory
map. **An unknown `kid` blocks — it never triggers a hot-path network fetch.** If
the token omits `kid` and exactly one key is configured, that key is used.

**Fields:** `file` XOR `url` (exactly one), `algorithms` (**asymmetric only** —
HS\* is rejected; a JWKS holds public keys), `issuer`/`audience`/`required_claims`/
`header_name` (default `Authorization`)/`leeway` (default 0), `refresh_interval`
(default **10m**, URL only), `http_timeout` (default **10s**, URL only).

**Gotchas:**
- **No request-path network I/O, ever** — verification only reads an atomic
  pointer to an immutable `kid→key` map. A remote URL is fetched once at load,
  then refreshed in the background; **a failed refresh keeps the last-good keys**
  (degrades closed-ish, not open).
- **JWKS parsing is hardened:** duplicate `kid` ⇒ the whole set is rejected; RSA
  keys must be ≥ 2048 bits; EC points are validated on-curve; the fetch body is
  capped at 1 MiB and gated on HTTP 200.
- **Rotation procedure:** publish the new key (new `kid`) in the JWKS *before*
  issuing tokens signed with it — a token whose `kid` the shield hasn't refreshed
  yet will block.
- A bad URL/file/parse at load **aborts the reload** (last-good config stays
  active); the background refresher is stopped cleanly on snapshot retire.

### api_key
SHA-256-hashed keys with optional scope→path bindings.

**Logic:** extract the key from a header (default `X-Api-Key`) or query parameter
→ empty ⇒ block `apikey.missing` → SHA-256 and look up ⇒ unknown ⇒ block
`apikey.unknown` → for each scope binding whose `path_prefix` prefixes the
**normalized** path, the key must carry `scope` ⇒ else block `apikey.scope` →
else allow.

**Fields:** `source` (`header` default | `query`), `name` (default `X-Api-Key`),
`keys[]` (each `sha256` hex **or** raw `key` hashed at load; `subject` is metadata;
`scopes` is the granted set; **duplicate keys ⇒ load error**),
`require_scope_for_path[]` (`{path_prefix, scope}`).

**Gotchas:**
- Config stores only **digests** — an exposed config doesn't leak usable keys.
  (The lookup is a hash-map lookup, not a constant-time compare; the secret is the
  SHA-256 preimage.)
- **Scope-binding paths are normalized** like the router (percent-decode,
  dot-segment/dup-slash collapse) so `//v1/admin`, `/v1/%61dmin`, `/v1/./admin`
  can't dodge a scope requirement.
- Bindings are **prefix** matches — `path_prefix: /admin` also matches
  `/administrator`. Use trailing slashes deliberately.
- Prefer `source: header` — query keys leak into URLs, logs, and referers.

### hmac_sign
Native HMAC request signing with a timestamp window + nonce replay protection and
optional body-digest binding. **Stateful** (shares the auth replay cache).

**Canonical string signed:** `method \n path \n timestamp \n nonce \n body-sha256`
— the **full path including query** (a tampered query breaks the signature);
`body-sha256` only when `require_body_digest`.

**Logic (in order):** missing signature ⇒ `sig.missing`; non-hex ⇒ `sig.invalid`;
parse timestamp (unix seconds) ⇒ `sig.invalid_timestamp`; **window check**
`|now-ts| ≤ window` (symmetric — also rejects far-future) ⇒ `sig.stale`; if
`require_nonce` and none ⇒ `sig.nonce_missing`; resolve secret (by `key_id` header
when `secrets` map is used; unknown ⇒ `sig.unknown_key`); **constant-time** MAC
compare ⇒ `sig.invalid`; **only after the MAC verifies**, replay check (key =
nonce, or the verified MAC hex when no nonce) ⇒ `sig.replayed`.

**Fields:** `secret` XOR `secrets{keyID:secret}`; header names default
`X-Signature`/`X-Timestamp`/`X-Nonce`/`X-Key-Id`; `algorithm` (`sha256` default |
`sha512`); `window` (default **5m**); `nonce_ttl` (default **= window**);
`require_nonce`; `require_body_digest` (flips the engine to the body phase).

**Gotchas:**
- **Replay is recorded only for *verified* requests** — an attacker can't pre-burn
  a victim's nonce with a bogus signature.
- **Replay works even without a nonce** (identical requests collide on the MAC
  within the window) — but two *legitimately identical* requests within the window
  also collide, so clients that legitimately repeat need a nonce.
- **Body-swap protection requires `require_body_digest`** — without it the body is
  not bound and can be swapped under a captured header-only signature. Turn it on
  for any body-bearing endpoint.
- Keep `nonce_ttl ≥ window`, or a nonce can expire before its signature goes
  stale, reopening a replay window (the default ties them together).

### http_signature
RFC 9421 (HTTP Message Signatures), pinned to **hmac-sha256**. **Stateful** (shares
the replay cache). Body phase only when it covers `content-digest`.

**Logic:** verify the RFC 9421 signature over the covered components ⇒ fail ⇒
block `httpsig.invalid`. **If `content-digest` is covered**, also require the
`Content-Digest` header (⇒ `httpsig.digest_missing`) and **recompute the digest
over the actual body** (⇒ `httpsig.digest_mismatch`) — because the signature alone
only proves it covered the *header value*, not that it matches the body.

**Fields:** `secret` (≥ 64 bytes), `signature_name` (default `sig1`),
`covered_components` (default `@method`, `@authority`, `@path`, **`@query`** — query
covered by default), `max_age` (default **0 = no freshness check**; when > 0,
rejects a signature whose `created` is older than this).

**Gotchas:**
- **Algorithm is pinned** — no negotiation, no asymmetric-confusion surface.
- **Replay protection only applies when the client sends a `nonce`** (the library
  invokes the nonce validator only then). A client that sends no nonce relies
  solely on `max_age`. If `max_age` is also 0, there is **no replay/freshness
  protection at all** — set `max_age` and/or require nonces.
- Include `content-digest` in `covered_components` for any body-bearing endpoint,
  or the body isn't bound.

### xfcc
Authenticates by Envoy's forwarded mTLS client-cert identity
(`x-forwarded-client-cert`). The most subtle trust model here — read the gotchas.

**Logic:** header missing/blank → if `require_present` ⇒ block `xfcc.missing`,
else allow (pass-through). If no allow-list configured ⇒ allow (presence-only).
Otherwise parse the header and **match ONLY the last (rightmost) element** ⇒ match
⇒ allow; no match ⇒ block `xfcc.no_match`. Matching ORs across `subjects` (DN),
`hashes` (cert fingerprint, case-insensitive), `uris` (SAN, e.g. SPIFFE IDs), and
`dns_names` (SAN, case-insensitive).

**Fields:** `header_name` (default `x-forwarded-client-cert`), `require_present`,
`uris`/`dns_names`/`subjects`/`hashes` (OR'd allow-list dimensions).

**Gotchas:**
- **Only the rightmost XFCC element is trusted.** Envoy appends the verified-peer
  identity last; earlier elements can be client-supplied under `APPEND_FORWARD`.
  Matching them would let a client prepend a forged allow-listed identity. **Use
  Envoy `forward_client_cert_details: SANITIZE_SET`.** The engine trusts that
  Envoy verified the peer cert — it cannot detect spoofing itself.
- Parsing is **quote/escape-aware** so a `\"` inside a Subject DN can't smuggle a
  comma/semicolon to forge element or field boundaries.
- **`require_present: false` with no allow-list is a no-op** (always allows) — easy
  to misconfigure into "auth that authenticates nothing." For enforcement you need
  an allow-list (and usually `require_present: true`).

#### Shared replay cache (hmac_sign, http_signature)
The auth engines share a sharded, TTL-bounded **two-generation** replay cache.
Each shard keeps a current and a previous nonce map; when the current fills
(16384 nonces/shard) it **rotates** (prev = cur) rather than wiping, and a hit in
`prev` is promoted back into `cur`. Security implication: to evict a victim's
nonce and replay a captured request, an attacker must flood **two full
generations** of distinct same-shard nonces within the TTL — far harder than
defeating a single-wipe cache. Memory is bounded to ~2× the shard cap.

---

## Traffic & reputation engines

All header-phase, request-only. They read the trusted `tx.SourceIP` (see
[the engine model](#the-engine-model)), never raw headers, for source-IP logic.

### rate_limit
Per-key token-bucket limiter. **The one sanctioned stateful engine** — 64 shards,
each with its own mutex, taken only when a policy opts in.

**Key selection:** `key: ip` (default) → `tx.SourceIP` (an empty source IP is
**not** limited — fails open on a *missing* IP rather than a spoofable one);
`key: host` → canonicalized host (port stripped, IPv6 brackets removed,
lowercased); `key: header` → the named header value (**absent header ⇒ empty key ⇒
not limited**).

**Bucket math:** `requests_per_second` (>0) is the refill rate; `burst` is
capacity (default ≈ `requests_per_second`, floored to 1). First sighting allows
with `burst-1` tokens; then `tokens += elapsed × rps` capped at `burst`; if `≥ 1`
allow & decrement, else **block 429** (`ratelimit.exceeded`, severity Low).

**Gotchas:**
- **Never keys on a raw XFF token** — a spoofable key would let an attacker mint
  unlimited fresh buckets.
- **Key-flood resilience is coarse:** each shard caps at 16384 keys and **resets
  the whole shard map when full**, which can let a burst through under a key-flood.
  Prefer `key: ip`/`key: host` over `key: header` on attacker-controlled headers.
- **Shared state follows inheritance:** a `rate_limit` defined at the **domain**
  level and inherited by N routes is **one combined limiter** across them; defined
  on a **route** it's independent; two separately-written identical blocks are
  independent. Define the limit at the scope it should apply to.

### ip_reputation
Static CIDR allow/deny + threat feeds + GeoIP/ASN. Stateless. Evaluation order is
cheapest-decisive-first and short-circuits:

0. **Unparseable source IP:** if an allow-list is configured ⇒ block
   `not_allowlisted` (an unidentifiable client can't be allow-listed); else
   continue. Then the IP is unmapped (4-in-6 → IPv4).
1. **Deny CIDRs** ⇒ block `deny_cidr`. **Deny always wins**, even over allow.
2. **Allow CIDRs ⇒ default-DENY mode.** If *any* `allow_cidrs` is set, an
   allow-listed (not denied) IP is treated as **trusted and short-circuits to
   ALLOW** (skipping feeds and geo); anything else ⇒ block `not_allowlisted`.
3. **Threat feeds** (only reached without an allow list) ⇒ block `feed:<name>`
   with the feed's severity (default medium).
4. **GeoIP:** total DB miss → `on_missing` (`continue` default | `block`);
   blocked country ⇒ block; country allow-list ⇒ block anything else (incl. an
   ASN-only hit with no confirmable country); blocked ASN ⇒ block. All geo blocks
   are 403.

**Gotchas:**
- **`allow_cidrs` is a hard switch to default-deny** *and* it suppresses
  feeds/geo for allow-listed IPs. Easy to lock out all unmatched legitimate
  traffic — roll out in `detect` first.
- **A GeoIP lookup error propagates** so the policy fail posture governs. A
  `fail_open` policy with a **country allow-list** (positive security) will fail
  *open* on a corrupt-DB read — **pair country allow-lists with `fail_close`.**
- Feed files are fully trusted (whoever writes them controls the blocklist). A
  malformed feed line **aborts the whole reload** (fail-loud) — last-good config
  stays active.

### bot
A layered scorer over User-Agent, verified-crawler IP checks, JA3/JA4 TLS
fingerprints (supplied by Envoy as headers), and header anomalies. **Any hard-block
layer short-circuits; scoring layers run only if nothing hard-blocked.** Order:

1. **Verified bots:** if the UA matches a configured crawler's `ua_match` regex
   and the source IP is in that crawler's published feed CIDRs ⇒ **immediate
   ALLOW** (real Googlebot is never collateral-damaged). If the UA *claims* a
   crawler but the IP matches **none** of its ranges ⇒ **hard-block**
   `bot.impersonation:<name>`.
2. **User-Agent:** empty UA with `block_empty` ⇒ `bot.ua_empty`; a `deny_substrings`
   match (case-insensitive) ⇒ `bot.ua_deny`.
3. **TLS fingerprint:** JA4 ∈ `deny_ja4` ⇒ block; JA4 ∈ `tool_ja4` **and** the UA
   claims a mainstream browser ⇒ **hard-block** `bot.ja4_ua_mismatch` (catches
   curl/python faking a browser UA); JA3 ∈ `deny_ja3` ⇒ block.
4. **Scoring (additive):** `score_known_bot` (known-bot UA), `score_ja4[fp]`,
   and `score_per_anomaly` per missing `accept`/`accept-language`/`accept-encoding`.

**Score resolution:** standalone (default) blocks `bot.score` when
`score ≥ score_threshold` (needs `score_threshold > 0`); **`emit_score: true`**
instead contributes the score to the policy [anomaly aggregator](#anomaly-scoring)
and never blocks on its own. **Hard-block layers always block regardless of
`emit_score`.**

**Fields/defaults:** JA4/JA3 headers default `x-shield-ja4`/`x-shield-ja3`;
`verified_bots[].format` ∈ `cidr_lines|firehol_netset|spamhaus_json`; scores `≥ 0`.

**Gotchas:**
- **JA3/JA4 protection depends entirely on Envoy** computing the fingerprint and
  forwarding it in the configured header. If Envoy doesn't set it, all JA-based
  layers **silently no-op**. Also ensure Envoy **strips any client-supplied**
  `x-shield-ja4`/`x-shield-ja3` so a client can't clear it to dodge a `score_ja4`
  penalty.
- Verified-bot feeds are trusted files — whoever writes them could whitelist their
  own IP for an impersonated crawler UA.

---

## Content-inspection engines

### coraza (OWASP CRS)
Full ModSecurity-style WAF. **Body phase, and the only engine that inspects
responses** (CRS phase 3/4). The WAF is compiled once into an atomic pointer so a
config reload can't race in-flight inspection.

**How `include_owasp` works:** the OWASP Core Rule Set is **embedded in the
binary** (`coraza-coreruleset/v4`, an in-memory filesystem — no rule files to
ship). The directive bundle is: `@coraza.conf-recommended` → **`SecRuleEngine On`**
→ `@crs-setup.conf.example` → your tuning → `@owasp_crs/*.conf` → your
`directives`/`directives_file` → `exclude_rule_ids` removals.

**`SecRuleEngine` is forced On** (overriding the CRS shipped `DetectionOnly`)
because shield expresses detect/shadow/off via the **policy mode** — the engine
must always enforce so the CRS blocking-evaluation rule actually raises an
interruption, which the executor then maps per mode. **Do not** put Coraza into
`DetectionOnly` via custom directives; use `mode: detect`/`shadow` on the policy.

**CRS anomaly scoring & tuning:** the CRS accumulates an anomaly score across
matching rules and blocks (rule 949110) when it crosses a threshold. The tuning
fields emit a phase-1 SecAction (before the rules load) — a **zero value leaves
the CRS default**:
- `paranoia_level` 1–4 (default 1): higher = more rules = stricter = more false
  positives.
- `detection_paranoia_level` (≥ blocking): run higher-PL rules in *detection* only.
- `inbound_anomaly_threshold` (default 5) / `outbound_anomaly_threshold` (default
  4): lower = stricter.

A CRS hit becomes a Block verdict (severity High, the rule-forced status or 403).

**Fail behavior:** body-processing errors **propagate** so `fail_open`/`fail_close`
governs — a body that Coraza can't process is not silently allowed.

**Gotchas:**
- Request and response are **separate transactions** — response rules don't see
  request-phase variables.
- `REMOTE_ADDR` is the trusted derived client IP (IP-keyed CRS rules work).
- Roll out with `mode: detect`, watch `detections_total` and tune
  `exclude_rule_ids` / thresholds, then switch to `block`.

### graphql
Guards GraphQL query shape against DoS. **Body phase**, request-only.

**Targeting:** only acts on requests that look like GraphQL — a POST with a
matching content-type within the path allow-list, **or a GET carrying `?query=`**
(guarding only POST would let an attacker move a deep query to GET). Everything
else passes through with no penalty — this is **not** a positive-security gate.

**Checks (a 0 value disables that specific one):** `max_operations` (batch + per
document), `max_root_fields` (counted through fragments so wrapping can't dodge
it), `max_depth`, `max_aliases`, `max_total_fields`, `block_introspection`
(`__schema`/`__type`). A parse failure blocks `graphql.parse_error`. All blocks
are severity Medium / 403.

**Always-on backstops (cannot be disabled — a 0 falls back to the default):**
`max_fragment_depth` (default **32**, fragment-spread recursion bound) and
`max_complexity` (default **100000** node-visit budget) — the hard guard against a
fragment "bomb" (a tiny query whose fragments fan out exponentially). Exceeding the
node budget blocks `graphql.complexity` immediately.

**Gotchas:** never drop the GET-over-`?query=` path if you customize targeting; an
unparseable-as-JSON body passes through (pair with OpenAPI/Coraza for positive
security); the two backstops are deliberately un-disable-able.

### openapi
Positive-security validation against an OpenAPI 3.x spec. **Request-only.**
**Header phase when `validate_request_body` is off, body phase when on.**

**Logic:** resolve the operation against the spec. **A path not in the contract is
blocked** (`openapi.undeclared_path`) — *regardless* of `reject_undeclared_path`
(that flag only selects the clearer rule id). A spec-resolution error also blocks
(`openapi.invalid`) — **fail-closed**. Then validate: with `validate_request_body`
on, params **and** body; off, params/headers/query/security only (validating the
body would falsely reject a required-body operation whose body wasn't buffered).
Any violation ⇒ block `openapi.invalid` (Medium / 403).

**Gotchas:**
- **Positive security blocks every undeclared path** — make sure the spec covers
  all legitimate routes or you'll block real traffic.
- With `validate_request_body: false`, **body schema violations are not caught** —
  only params/security.
- Block reasons use **only structural spec fields** (type/parameter name), never
  the submitted value — so PII/secrets don't leak into the audit log.

### DLP & sensitive data
Built-in body detector for PII/secrets, consumed two ways. Both run in the body
phase. Detector kinds: `aws_access_key`, `private_key`, `google_api_key`,
`slack_token`, `github_token`, `stripe_key`, `jwt`, `ssn`, `email`, `credit_card`
(Luhn-validated).

- **`detect_sensitive_data: true`** (`checks.body`): blocks on the first sensitive
  finding (`body.sensitive_data`, severity High).
- **`checks.body.dlp`**: finds **all** matches.
  - **Block precedence:** any match whose kind is in `dlp.block` ⇒ block
    `body.dlp_block:<kind>` **before any redaction** (fail closed on a hard
    secret).
  - **Redact:** kinds in `dlp.redact` are masked in place (credit cards keep the
    last 4 digits; others become `[REDACTED:<kind>]`) and the rewritten body is
    sent to Envoy via the body-mutation channel (strips Content-Encoding, lets
    Envoy recompute Content-Length; counted as `body_mutations_total`).
  - **Direction:** default **`response`** (`request`/`both` also valid).

**Gotchas:**
- **DLP defaults to the response direction** — to scrub/inspect request bodies set
  `direction: request` or `both`.
- The DLP policy kinds are the 9 above **minus `stripe_key`** — `stripe_key` is
  detectable by `detect_sensitive_data` but cannot be named in a DLP `block`/
  `redact` list.
- Redaction rewrites the forwarded body — mind the pipeline order relative to any
  body-digest/signature check.

---

## Anomaly scoring

Instead of each engine blocking on its own threshold, scoring engines can feed a
**collaborative per-request score** (the model OWASP CRS uses):

- A scoring engine (e.g. `bot` with `emit_score: true`) returns a non-blocking
  verdict carrying a positive `Score`.
- `engine.Set` **sums only positive scores** — a negative score is **clamped to
  zero** so a buggy/misconfigured engine can never subtract from the total and
  mask an attack below threshold.
- The WAF stage accumulates the score across the header and body phases; once
  `policy.anomaly_threshold > 0` and the running total `≥ threshold`, it emits a
  synthetic block `anomaly.threshold` (engine `anomaly`, severity Medium, 403).

So no single weak signal blocks alone, but several together cross the line.
`anomaly_threshold: 0` disables it.

---

## Always-on structural body protections

Three guards are **prepended to the body pipeline, are not reorderable, and honor
no skip list** — an enforcing policy cannot opt out. They turn an
un-fully-inspectable body into a **block**, never a silent allow:

1. **Truncation guard** — if the body was truncated (over `max_*_body_bytes` or the
   inflight budget), block `body.too_large` (engine `body_size`). Closes the bypass
   of padding a payload past the cap to hide it from the WAF.
2. **Content decode** — decompresses `gzip`/`deflate` (bomb-bounded to 8 MiB,
   charged against the shared budget) so inspectors see the real payload. An
   undecodable or stacked encoding (`br`, `compress`, multiple) **fails closed** →
   block `body.undecodable_encoding`. Closes the gzip-the-attack WAF bypass.
3. **Inflight body budget** — a single process-wide cap
   (`--max-inflight-body-bytes`) on bytes buffered across **all** streams, so a
   per-request cap can't become a `×concurrency` memory DoS. An over-budget body is
   marked truncated → blocked by guard #1 (reasons `per_request_cap` /
   `inflight_budget` on `body_budget_rejections_total`).

---

## Gotchas at a glance

| Topic | Watch out for |
|---|---|
| **Source IP** | Set `--xff-trusted-hops` to the exact proxy count in front of Envoy; run Envoy with `use_remote_address`. |
| **Missing credential** | Always **blocks** (no anonymous pass-through); `fail_open` does NOT let it through. |
| **jwt/jwks leeway** | Default 0 — set a small leeway or tokens near `exp` get rejected on clock skew. |
| **jwks rotation** | Publish the new `kid` in the JWKS before issuing tokens with it. |
| **hmac_sign body** | Set `require_body_digest` or the body can be swapped under a captured signature. |
| **http_signature replay** | Only protects when the client sends a `nonce`; otherwise set `max_age`. |
| **xfcc trust** | Only the rightmost element is trusted; use Envoy `SANITIZE_SET`; an allow-list-less config authenticates nothing. |
| **ip_reputation allow_cidrs** | Hard default-deny + suppresses feeds/geo — roll out in `detect`. |
| **ip_reputation geo** | Pair a country allow-list with `fail_close` (a GeoIP error otherwise fails open). |
| **rate_limit key** | Don't key on an attacker-controlled header; domain-level limits are shared across inherited routes. |
| **bot JA3/JA4** | Useless unless Envoy supplies the fingerprint header and strips client-supplied copies. |
| **coraza mode** | Use policy `mode` for monitor/shadow, never SecLang `DetectionOnly`. |
| **openapi** | Blocks every undeclared path; `validate_request_body: false` skips body schema checks. |
| **DLP** | Defaults to the response direction; `stripe_key` is detect-only, not DLP-policyable. |
| **graphql** | Not a positive-security gate; `max_complexity`/`max_fragment_depth` can't be disabled. |

---

*Keep this file in sync with the engine implementations under
`internal/engine/*`, the structural stages in `internal/pipeline/stages/`, and the
schema in [`docs/CONFIG-REFERENCE.md`](CONFIG-REFERENCE.md).*
