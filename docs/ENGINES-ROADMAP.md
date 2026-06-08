# elchi-shield — Phased Engine Roadmap (8 new security engines)

## Implementation status (2026-06-08)

**Delivered (Phases 1–6 + 7a):** IP reputation (CIDR/feeds/GeoIP) · bot detection
(UA/verified-bot/JA4/heuristics) · API-key auth · native HMAC signing · RFC 9421
(`-tags httpsig`) · OAuth2/OIDC JWKS · mTLS XFCC · OpenAPI positive validation
(`-tags openapi`) · GraphQL guard · DLP response redaction (new body-mutation
channel) · collaborative anomaly scoring. Shared infra `internal/{netmatch,feed,
geoip}` + `internal/engine/auth` built first. Every phase landed with unit tests,
a real-Envoy e2e phase (now 146 assertions), and `-race`/lint/0-alloc green.

**Deferred — Phase 7b adaptive concurrency limiting:** not built. It needs the
single most invasive change in the roadmap — an ext_proc per-stream
reservation-token (reserve on the request, release on the matching response AND on
stream teardown, or a leaked slot becomes a permanent shed → self-DoS), which sits
at the server level rather than the clean engine abstraction. The existing sharded
rate-limit engine already covers per-key abuse, so this is a nice-to-have parked
for a future, dedicated change with its own stress/leak proof.

## Executive summary

This plan adds eight engines to elchi-shield, sequenced so that **shared infrastructure lands first** and each engine reuses it rather than re-inventing it. The dominant theme: most of these engines are cheap, header-phase, lock-free lookups (IP/CIDR/Geo, bot, JWKS, XFCC, API-key); a smaller set are body-phase (OpenAPI body validation, GraphQL, DLP, HMAC-with-digest); and two are cross-cutting control mechanisms (anomaly scoring, adaptive concurrency).

Ordering rationale:

1. **Bot detection is the user's top priority and must block** — but it depends on two pieces of shared infra (a CIDR/prefix matcher for good-bot IP feeds, and a feed-file loader). So Phase 1 builds the shared infra **as** the IP-reputation engine (which needs the same trie + feed loader + GeoIP), and Phase 2 immediately delivers bot detection on top of it. This gets bot blocking out fast while avoiding throwaway work.
2. Auth engines (API-key, JWKS, XFCC, HMAC) cluster around a shared `internal/engine/auth` helper (constant-time compare, replay cache, JWKS background refresher, canonicalization) — Phases 3–4.
3. Contract/semantic engines (OpenAPI, GraphQL) are body-phase and share the `*http.Request` shim + body-gating discipline — Phase 5.
4. DLP introduces the **body-mutation channel** (a genuinely new pipeline capability) — Phase 6, isolated because it touches ext_proc response wiring.
5. Anomaly scoring + adaptive concurrency are cross-cutting and depend on every detection engine already emitting findings, plus a new per-stream response token — Phase 7, last.

Three things touch core hot-path/value types and need extra care (machine-checked by `TestHotPathZeroAlloc`/`TestResolveZeroAlloc`): adding `Score` to `decision.Verdict` (Phase 7), the per-stream reservation token in ext_proc (Phase 7), and the body-mutation action (Phase 6).

**Decisions needed from the user** are flagged inline and collected at the end.

---

## Shared infrastructure (build first — Phase 0/1 foundation)

These are built once and reused by multiple engines. Several are delivered **inside Phase 1** (the IP-reputation engine is their first consumer), but they are designed as standalone, engine-agnostic packages.

### SI-1 — CIDR / prefix matcher (`internal/netmatch`)
- **Library:** `github.com/gaissmai/bart` (MIT, netip-native BART trie, ~9–18 ns/op, **0 allocs**, lock-free reads). Beats `cidranger`/`patricia`.
- **API:** `bart.Lite` for allow/deny set membership; `bart.Table[meta]` for feed→{name,severity} payloads.
- **Consumers:** IP-reputation (CIDR ACLs + threat feeds), **bot** (good-bot IP-range verification feeds).
- **Constraint:** use only the **stable lock-free read path**; tables are immutable post-build, swapped via the snapshot pointer. Never use bart's experimental concurrent writers.
- Helper: `go4.org/netipx` (BSD-3) `IPSetBuilder` to dedupe/normalize messy feeds on the cold path before insert.

### SI-2 — Feed-file loader (`internal/feed`)
- File-driven, no network (honors "management plane distributes config only; sidecar never fetches"). elchi-client writes feed files into the watched dir → atomic reload recompiles.
- **Parsers:** `spamhaus_json`, `firehol_netset`, `cidr_lines` (for IP feeds); plain `base16-sha256-per-line` (for GraphQL persisted-query allowlist, DLP custom rules, API-key hash files).
- **Freshness guard:** every feed carries a file mtime/age; an engine can refuse to *enforce* (e.g. impersonation-block) on a feed older than N days, and emit a `feed_age_seconds`/`feed_stale` metric. Empty-file guard (don't silently stop blocking).
- **Consumers:** IP-reputation, bot, GraphQL persisted queries, DLP custom rules.

### SI-3 — GeoIP reader (`internal/geoip`)
- **Library:** `github.com/oschwald/maxminddb-golang/v2` (ISC, netip-native, thread-safe, v2 = 56% fewer allocs). Decode **only** needed fields (country ISO, ASN) into a flat struct — no `geoip2-golang` map records.
- **Load:** `FromBytes(copy)` + atomic swap (NOT mmap) so an in-place file replace by elchi-client can't invalidate an in-flight read.
- **Consumers:** IP-reputation (now), available to bot later.

### SI-4 — `internal/engine/auth` shared helpers
- `crypto/subtle.ConstantTimeCompare` / `hmac.Equal` wrappers (timing-safe).
- **Sharded replay/nonce cache** — clone the proven `internal/engine/ratelimit` sharded-map + per-shard-mutex + `maxKeysPerShard` reset model (the *second* sanctioned lock, contained to opt-in engines).
- **Canonicalization plan** compiler (method/path/headers/timestamp/nonce/body-digest) shared by native HMAC, RFC 9421, SigV4 presets.
- **Consumers:** API-key, HMAC-signing.

### SI-5 — JWKS background refresher (`internal/engine/auth/jwks`)
- **Pattern (critical):** NO synchronous network fetch on the verify path. A per-snapshot background goroutine fetches+parses JWKS into an immutable `map[kid]crypto.PublicKey` published via `atomic.Pointer`. The per-request keyFunc reads the pointer lock-free; **unknown kid ⇒ fail-posture block, never a fetch.**
- **Libraries:** `MicahParks/jwkset` (Apache-2.0) for JWK→`crypto.PublicKey` parsing; reuse existing `golang-jwt/jwt/v5` verifier. `coreos/go-oidc` used **only** at config-load for `.well-known` discovery.
- **Lifecycle:** goroutine tied to snapshot retirement (ctx cancel on reload); **deduped by `*EnginesSpec` pointer** via the existing `engineCache` so N inherited routes don't spawn N IdP-hammering goroutines.
- **Consumers:** JWKS (Phase 4).

### SI-6 — `action` abstraction: `block | detect | shadow | redact`
- Today the executor maps `mode → action`. DLP needs a **mutation** outcome the current `decision.Verdict`/`SecurityEngine.Inspect` cannot express. Introduce a narrow `ActionRedact` `StageResult` action + a `BodyRewriter` capability (or, preferred, model DLP as a first-class mutating **Stage**). Built in Phase 6 but called out here so engines converge on one action vocabulary.

### SI-7 — `engine.Request` / shim conventions (verify, don't build)
- Confirm `engine.Request.SourceIP` (trusted-hop-derived from XFF/X-Real-IP), `HeaderView`, `ContentType`, `Body`, `Direction` are all present and used as the single source of truth. The minimal `*http.Request` shim (used by OpenAPI) is documented as a shared helper so OpenAPI/GraphQL don't each invent one.

**Phase 0 deliverable:** `internal/netmatch`, `internal/feed`, `internal/geoip` packages exist with doc comments + unit tests + benchmarks, no engine wired yet. **Verification:** `go test -race ./internal/netmatch/... ./internal/feed/... ./internal/geoip/...`, a benchmark proving `bart.Contains` is 0-alloc, `golangci-lint` clean. (May be folded into Phase 1 to avoid a dead-code phase — see note.)

---

## Phase 1 — IP reputation, GeoIP & CIDR allow/deny

**Why first:** It is the consumer that *forces* SI-1/SI-2/SI-3 into existence, it's the cheapest possible block (header phase, pre-body), and it's pure-Go/built-in so it ships in the lean binary.

- **Package:** `internal/engine/ipreputation` — **built-in, NO build tag** (bart + maxminddb/v2 are pure-Go, zero-cgo).
- **Wiring:** add `IPReputation *IPReputationSpec` to `config.EnginesSpec`; `buildIPReputation()` in `policy/engines.go` (does ALL compilation cold-path: parse feeds → bart, open MMDB → FromBytes).
- **`engine.SecurityEngine`:** `Name()="ipreputation"`, `RequiresBody()==false` (header phase, never buffers body), `Close()` closes the MMDB reader.
- **Stateful?** No. No mutex, no `*EnginesSpec` sharing needed beyond `engine.Set` dedup.
- **Hot path:** read `req.SourceIP` (already derived once), `netip.ParseAddr` once → deny-feed `Contains()` → allow-list default-deny → GeoIP `Lookup`→decode country/ASN → compare. Block ⇒ `Verdict{Action:Block, RuleID:"ipreputation.<feed|geo>", Engine:"ipreputation", StatusCode:403}`.
- **Envoy config:** none beyond ensuring the trusted client IP reaches the shield (XFF trusted-hops / original_src). **Source-IP trust must use the trusted-hop-derived IP**, not the raw first XFF token.
- **YAML config:**
```yaml
policy:
  engines:
    ip_reputation:
      mode: block            # block | detect | shadow
      fail_open: false       # feed/db load failure at reload ⇒ abort reload (last-good stays)
      allow_cidrs: [10.0.0.0/8, 2001:db8::/32]   # non-empty ⇒ default-deny
      deny_cidrs: [192.0.2.0/24, 198.51.100.7/32]
      feeds:
        - { name: spamhaus_drop, file: /etc/elchi/elchi-shield/feeds/spamhaus_drop.json, format: spamhaus_json, action: block, severity: high }
        - { name: firehol_level1, file: /etc/elchi/elchi-shield/feeds/firehol_level1.netset, format: firehol_netset, action: block, severity: medium }
      geoip:
        database_file: /etc/elchi/elchi-shield/geo/GeoLite2-Country.mmdb
        asn_database_file: /etc/elchi/elchi-shield/geo/GeoLite2-ASN.mmdb
        block_countries: [KP, RU]   # OR allow_countries (default-deny)
        block_asns: [64512, 64513]
        on_missing: continue
```
- **Metrics:** reuse `detections_total`/`requests_blocked_total`; add labeled `ipreputation_matches_total{feed|country}`, `feed_age_seconds` (pull-based), `feed_entries` gauge — all via pre-resolved `metrics.RegisterStages`/`ForListener` (never per-request).
- **Fail posture:** malformed feed/DB ⇒ **reload aborts**, last-good snapshot stays active. Default-deny allow-lists are foot-guns → recommend detect/shadow first.
- **e2e cases:** deny-CIDR hit → 403; allow-list default-deny miss → 403; Spamhaus/FireHOL feed hit → 403; GeoIP country block → 403; IP not in DB + `on_missing:continue` → pass; stale feed (> N days) does not enforce + metric fires; spoofed XFF blocked from bypassing (uses trusted-hop IP); malformed feed file → reload aborts, traffic unaffected.

**Deliverable:** lean binary blocks by IP/CIDR/Geo/feed. **Verification:** `make build` (default), `go test -race ./internal/engine/ipreputation/... ./internal/netmatch/... ./internal/feed/... ./internal/geoip/...`, `golangci-lint run`, e2e cases above, `TestHotPathZeroAlloc` still passes.

---

## Phase 2 — Bot / scanner / automation detection  ⭐ TOP PRIORITY, BLOCK-CAPABLE

**Why second:** It's the user's #1 priority and must block; it reuses SI-1 (prefix matcher) + SI-2 (feed loader) from Phase 1 for good-bot IP verification, so it lands immediately after the infra exists.

- **Package:** `internal/engine/bot` — **built-in, NO build tag** (pure-Go, light deps).
- **Library:** `github.com/mileusna/useragent` (MIT, ~750★, ~945 ns/op, built-in Bot/known-crawler flags). Fallback `medama-io/go-useragent` (~287 ns/op) if UA parse shows in the alloc budget. **Do NOT** add `ja4plus`/`fingerproxy` — JA4/JA3 arrive as Envoy-supplied headers.
- **Wiring:** add `Bot *BotSpec` to `config.EnginesSpec`; `buildBot()` in `policy/engines.go`. Not an inspector/stage — it's an engine.
- **`engine.SecurityEngine`:** `RequiresBody()==false` (header phase, never buffers body). Stateless.
- **Layered scorer (cheapest first), all precompiled cold-path:**
  1. UA classification + deny-substring list (RE2).
  2. Good-bot verification: claimed Googlebot/Bingbot whose `SourceIP` ∉ feed prefix set ⇒ impersonation block (reuses SI-1 bart + SI-2 feed loader).
  3. JA3/JA4 deny/score sets + **JA4↔UA consistency** (TLS says curl/python, UA claims Chrome ⇒ block) — matched against Envoy-supplied `x-shield-ja4`/`x-shield-ja3` headers.
  4. Header-anomaly heuristics (missing Accept/Accept-Language/Accept-Encoding, suspicious casing if Envoy surfaces it).
  - Score ≥ threshold OR any hard `*_deny` ⇒ `Verdict{Action:Block, StatusCode:403, RuleID:"bot.<reason>", Engine:"bot"}`.
- **Envoy config REQUIRED:** (1) TLS-inspector `enable_ja4_fingerprinting: true` (+`enable_ja3` if wanted); (2) propagate the filter-state fingerprint into a request header (`%TLS_JA3_FINGERPRINT%` formatter / filter-state→header) so shield sees `x-shield-ja3`/`x-shield-ja4`; (3) real client IP reaches shield. **Graceful degrade:** if the header is absent, skip the TLS layer (don't block everything); optionally surface a config warning.
- **YAML config:** layered `user_agent` / `verified_bots` (with feed files + `ua_match` + `action:allow`) / `tls_fingerprint` (`ja4_header`, `deny_ja4`, `score_ja4`, `consistency_check`) / `heuristics` blocks with a `score_threshold` (see the detailed sketch in findings; ship verbatim).
- **Metrics:** reuse `detections_total`/`requests_blocked_total` with `reason: ua_deny|spoofed_bot|ja4_deny|heuristic` via pre-curried registration.
- **Fail posture:** must NOT fail-closed-block on engine error; ship in **detect/shadow first** (false-positive risk on monitoring/SDKs/partners). JA4 = score contributor, not sole hard block (except known-bad exact hashes). Don't impersonation-block on a stale good-bot feed (reuses SI-2 freshness guard — protects real Googlebot/SEO).
- **e2e cases:** `python-requests`/`curl` UA → block; empty UA → block; spoofed Googlebot (Google UA, non-Google IP) → block; verified Googlebot (UA + real Google IP) → allow-listed/pass; JA4 deny hash → block; JA4↔UA mismatch → block; missing-header heuristic accumulates to threshold → block; TLS header absent → TLS layer no-ops, no false block; stale feed → impersonation check disabled, real Googlebot passes.

**Decision needed:** confirm Envoy can be configured for JA4 header propagation in target deployments; if not, Phase 2 ships layers 1/2/4 and documents the JA4 layer as enabled-when-available. **Document the H2/Akamai fingerprint gap** (Envoy doesn't export raw H2 frames to ext_proc) as a future layer, not buildable inline today.

**Deliverable:** block-capable bot engine in lean binary. **Verification:** `make build`, `go test -race ./internal/engine/bot/...`, `golangci-lint`, e2e cases, `TestHotPathZeroAlloc` passes (UA parsed once).

---

## Phase 3 — API-key auth + native HMAC signing

**Why here:** Establishes SI-4 (`internal/engine/auth`: constant-time compare, sharded replay cache, canonicalization) that JWKS/HMAC-RFC9421 build on. Pure-stdlib core ships in the lean binary.

- **Two engines, shared `internal/engine/auth`:**
  - `internal/engine/apikey` — **built-in, no tag.** Header-phase, stateless. Extract key from header/query → lookup in precompiled `map[[32]byte]entry` of `SHA-256(key)→{subject,scopes}` (hashed-at-rest, never plaintext) → `subtle.ConstantTimeCompare` → optional scope/path binding. `RequiresBody()==false`.
  - `internal/engine/hmacsign` — **native scheme built-in (stdlib only)**; RFC 9421 (`yaronf/httpsign`, Apache-2.0) and SigV4 presets **build-tagged**. `RequiresBody()==false` normally; **`==true` only when `body_digest.enabled`** (RFC 9530 Content-Digest in the covered set) → body phase, charges `bodyBudget`. **Stateful** (replay nonce cache, the second sanctioned lock) — shared by `*EnginesSpec` pointer identity like ratelimit.
- **Libraries:** stdlib `crypto/hmac`,`crypto/sha256`,`crypto/subtle`. RFC 9421 → `yaronf/httpsign` (build tag). SigV4 → re-implement canonicalization over SI-4 (reference `aws-sdk-go-v2` signer, don't import on hot path).
- **Envoy data:** request line + headers (present); buffered body only when digest covered.
- **YAML config:** `apikey` (header/query, `hash: sha256`, `keys[]` inline-hash or `sha256_file`, `require_scope_for_path[]`, `fail: fail_close`) and `hmacsign` (`scheme: native|rfc9421|sigv4`, `signed_components[]`, `body_digest{enabled,algorithm,header}`, `secrets[]` via `secret_file`, `replay{timestamp_header,window,nonce_header,nonce_ttl}`, `algorithm`, `fail`). Ship the detailed sketch verbatim.
- **Metrics:** `engine="apikey"|"hmacsign"` + reasons `auth.key_unknown`/`sig.invalid`/`sig.replayed`/`sig.stale`. **Never log key/secret/MAC/nonce** — add `X-Signature`/`X-Nonce` to `internal/redaction` (X-Api-Key already redacted).
- **Fail posture:** missing/unknown key or bad sig ⇒ fail_close 403. **Canonicalization must match the signer exactly** — pin to normalized `matchPath` form; document precisely what is signed (path escaping/header casing/trailing dots are the classic footgun). **Body-digest gate must be `RequiresBody()==true` whenever a digest is covered**, or verification is bypassable.
- **e2e cases:** valid key → pass; unknown/missing key → 403; scope-mismatch on bound path → 403; valid native HMAC → pass; tampered MAC → 403; replayed nonce within TTL → 403 (`sig.replayed`); stale timestamp outside window → 403; body-digest enabled + body swapped → 403 (proves body-phase gate); RFC 9421 (tagged build) valid/invalid; nonce cache bounded under key-flood (no memory DoS).

**Deliverable:** lean binary does API-key + native HMAC; tagged binary adds RFC 9421/SigV4. **Verification:** `make build` (default) and `make build TAGS="..."`; `go test -race` over both tag sets; `golangci-lint`; `make vuln` (RFC 9421 lib); e2e cases.

---

## Phase 4 — OAuth2/OIDC JWKS + mTLS (XFCC) identity

**Why here:** Extends the existing `jwt` engine + reuses SI-5 (JWKS background refresher) and the `*EnginesSpec` dedup pattern from Phase 3. Both header-phase, pure-Go, built-in.

- **Two cooperating engines, both `RequiresBody()==false`, no build tag:**
  - **JWKS (extends `internal/engine/jwt`):** keep `golang-jwt/jwt/v5`; add a remote-JWKS key source via SI-5. **Stateful** (background refresher goroutine), deduped by `*EnginesSpec` pointer. One **blocking** initial JWKS fetch at config-load (cold path) so the snapshot is hot; **fail the reload** if it fails (keep last-good). Pin algorithms (`WithValidMethods`) to block alg-confusion/none-alg; reject HS* when only asymmetric keys exist.
  - **XFCC (`internal/engine/xfcc`):** parse Envoy's `x-forwarded-client-cert` (header-only, zero network). **Reimplement a ~120-line pure-Go parser** (don't vendor `alecholmes/xfccparser`/participle; use it as a **fuzz oracle**). Match SAN-URI/SPIFFE-ID/SAN-DNS/CN/issuer/SHA256-fingerprint against a config-load allowlist. Optional `bind_jwt_cnf`: require JWT `cnf.x5t#S256` == XFCC `Hash=` (RFC 9449/8705 proof-of-possession).
- **Envoy config REQUIRED:** `set_current_client_cert_details(uri,dns,subject,cert,chain)` + **`forward_client_cert_details: SANITIZE_SET`** (mandatory — strips client-supplied XFCC; APPEND on an external hop = forgeable identity). The engine cannot detect spoofing itself.
- **YAML config:** extend `jwt` with a `jwks{url | oidc_discovery_url, refresh_interval, http_timeout, min_refresh_interval, serve_stale_on_error}` block; add `xfcc{header_name, require_present, match_any[], bind_jwt_cnf}`. Ship the detailed sketch verbatim.
- **Metrics:** `jwks_refresh_success_total`, `jwks_refresh_failure_total`, `jwks_keys_active` (gauge), `jwks_last_refresh_timestamp_seconds`, `jwt_validation_failures_total{reason}`, `xfcc_validation_failures_total{reason}` via `Metrics.register` (instance label).
- **Fail posture:** unknown kid ⇒ fail-posture block (NEVER a synchronous fetch — this is the key invariant the default libs violate). Key-rotation race (new kid before refresh) mitigated by short `refresh_interval` + serve-stale + rate-limited background "refresh soon" signal.
- **e2e cases:** valid RS256/ES256 against published JWKS → pass; unknown kid → fail-posture block (and **assert no network call on the request path**); rotated key after background refresh → pass; alg-confusion HS256-with-pubkey → block; XFCC SPIFFE-ID match → pass; XFCC absent + `require_present` → block; XFCC forged value with SANITIZE_SET → stripped (no match) → block; `bind_jwt_cnf` mismatch → block; JWKS background goroutine stops on snapshot retirement (`-race`, no leak — `go_goroutines` stable); N inherited policies → 1 refresher (pointer dedup).

**Deliverable:** lean binary enforces OIDC bearer + mTLS identity. **Verification:** `make build`; `go test -race` (incl. goroutine-leak + `TestStressConcurrentListenersWithReloads`); `make fuzz` (XFCC parser vs oracle); `golangci-lint`; e2e cases.

---

## Phase 5 — OpenAPI positive validation + GraphQL guard

**Why grouped:** Both are body-phase semantic engines that share the `*http.Request` shim discipline and strict body-gating (`RequiresBody()` true only when body validation is on). OpenAPI is build-tagged (heavy deps); GraphQL is built-in (light).

### 5a — OpenAPI / JSON-Schema positive validation
- **Package:** `internal/engine/openapi` — **build-tagged (`-tags openapi`)** (libopenapi + validator + santhosh-tekuri pull a non-trivial tree). Factory-registry pattern mirroring Coraza.
- **Libraries:** `pb33f/libopenapi` (MIT) + `pb33f/libopenapi-validator` (MIT) → `santhosh-tekuri/jsonschema/v6` (Apache-2.0, transitive). **Reject `kin-openapi`** (double body copy, weak 3.1, heavy allocs).
- **Hot-path discipline:** at config-load build Document + Validator once and **pre-resolve `*v3.PathItem`** (`FindPath`). On the hot path call `ValidateHttpRequestSyncWithPathItem` — **NO goroutine spawn, NO route re-resolution** (the high-level `ValidateHttpRequest` does both — forbidden). Feed the **normalized** `tx.Path` (matchPath invariant) into FindPath.
- **`RequiresBody()`:** `true` only if `validate.request_body`/`response_body` on; else `false` (header-phase param/path validation, no buffering). Direction-aware.
- **YAML:** `openapi{spec_file, validate{path,params,request_body,response_body}, reject_unknown_query_params, allowed_content_types_from_spec, max_body_bytes, fail: fail_close, mode}`.
- **Fail posture:** malformed JSON ⇒ **fail closed** (propagate parse error). Undeclared path ⇒ block (shadow-endpoint detection) but make it a per-policy toggle (aggressive). `reject_unknown_query_params` opt-in.
- **e2e:** valid request → pass; undeclared path → block; missing required param → block; wrong type/enum/pattern → block; unknown query param (strict) → block; wrong content-type → block; malformed JSON body → fail-closed block; response-direction validation when enabled.

### 5b — GraphQL guard
- **Package:** `internal/engine/graphql` — **built-in, NO tag** (pure-Go). Optional schema-aware cost via **`-tags graphql_advanced`** (`wundergraph/graphql-go-tools/v2`).
- **Library:** `vektah/gqlparser/v2` (MIT) `parser.ParseQuery` (schema-free, ~2× faster / 3× fewer allocs than graph-gophers/graphql-go).
- **`RequiresBody()==true`**, stateless. Gate on POST + content-type/path first → non-GraphQL ⇒ Continue immediately (don't penalize other routes). **Persisted-query allowlist (SHA-256, reuses SI-2 hash-file loader) checked BEFORE parsing** → non-allowlisted strict ⇒ block without parsing attacker text. Single DFS computes depth/aliases/field-count/static-complexity/introspection; **fragment-cycle bound** (visited-set + `max_fragment_depth`) or the guard self-DoSes.
- **YAML:** `graphql{content_types, paths, max_depth, max_aliases, max_root_fields, max_total_fields, max_complexity, field_weights, max_operations_per_request, max_fragment_depth, block_introspection, persisted_queries{mode,allow_unpersisted,hashes_file}, fail}`. **Config validation must reject APQ+strict-allowlist combined** (APQ defeats the allowlist).
- **Fail posture:** parse error ⇒ fail-closed block; body size capped by truncation guard **before** parse.
- **e2e:** depth > cap → block; alias overload → block; batch > `max_operations` → block; `__schema` introspection → block; allowlisted op → pass without parse; non-allowlisted strict → block; fragment cycle → bounded, no hang; non-GraphQL POST → pass-through.

**Shared metrics:** `engine="openapi"|"graphql"` on `detections_total`/`requests_blocked_total` + per-violation/per-limit counters via `RegisterStages`. One `decision.Decision` per finding through `tx.findings`. **No body/query values in logs/audit** — type/limit/measured-vs-cap only.

**Deliverable:** lean binary gets GraphQL guard; `-tags openapi` adds positive validation. **Verification:** `make build` (default — GraphQL present, OpenAPI absent) and `make build TAGS="openapi"`; `go test -race` over both; `golangci-lint`; `make vuln`; e2e cases for both.

---

## Phase 6 — DLP / sensitive-data response redaction

**Why here, isolated:** It introduces the **body-mutation channel** (SI-6) — a genuinely new pipeline + ext_proc capability — so it's sequenced after the detect/block engines are stable and given its own phase.

- **Package:** evolve `internal/sensitive` into a **build-tagged (`-tags dlp`)** body-phase capability. Lean built-in detectors (cards/SSN/private-key/JWT/AWS) stay always-on; the **gitleaks corpus** (800+ RE2 rules) is the tagged extension.
- **Libraries:** `gitleaks/v8/config` **corpus as DATA** (MIT, `go:embed gitleaks.toml`) — **not** the gitleaks engine, **not** trufflehog (it makes live API calls — forbidden on a local data plane). `BurntSushi/toml` (cold-path parse). Stdlib `regexp` (RE2) for matching. Inline Shannon-entropy + existing `luhnValid` as post-regex filters.
- **CRITICAL interface gap (SI-6):** `SecurityEngine.Inspect` returns only a verdict — it cannot rewrite a body. **Preferred:** model DLP as a first-class **mutating pipeline Stage** (register in `stages.NewCatalog` + `config.knownInspectors`) that calls the already-present-but-unwired `tx.ReplaceBody([]byte)` and emits a new `ActionRedact` `StageResult`. (Alternative: a narrow `BodyRewriter` capability interface — but mutation-as-a-Stage is cleaner than overloading the engine contract.)
- **ext_proc wiring (new):** `processor.go onResponseBody` currently returns bare CONTINUE; when `tx` body was replaced, emit `ResponseBody{CommonResponse{Status:CONTINUE, BodyMutation{Body{newBody}}, HeaderMutation resetting Content-Length}}`. **BUFFERED response-body mode only** (STREAMED can't do offset-correct rewrite). Response-only.
- **Detection:** keyword-prefilter (gitleaks keywords) → broad RE2 → entropy/Luhn gate (base64≥4.5, hex≥3.0) to cut false positives. **Single-pass `FindAllIndex` offset rewrite → one output alloc, only when a match exists.** Format-preserving masks (BIN+last4 for cards, last4 for SSN, `[REDACTED:<type>]` tags) so JSON stays valid.
- **`RequiresBody()==true`**, gate on `Direction==Response` + content-type (skip binary). Charges `bodyBudget`; over-limit ⇒ truncation guard blocks (never pass unredacted).
- **YAML:** `dlp{direction: response, fail_close, max_body_bytes, content_types, entropy{base64_min,hex_min}, builtins{credit_card,ssn,email,private_key,jwt,aws_access_key → {action: block|redact|detect, mask}}, gitleaks_corpus{enabled, rule_groups, default_action, exclude_rule_ids}, custom_rules[]}`. Per-type `action: block|redact|detect|allow`.
- **Content-Length/encoding (high-risk):** recompute Content-Length after rewrite; **decode to scan, return identity-encoded** with correct length (don't re-compress / mishandle Content-Encoding → corrupt response). Relies on `bodyContentDecode` for gzip/deflate plaintext.
- **Metrics:** `dlp_detections_total{kind,action}`, `dlp_redactions_total{kind}` pre-curried. **Findings are the most sensitive data in the system — never log matched bytes, never put values in audit reasons** (type-only, like current `sensitive data detected: <kind>`).
- **e2e:** card in JSON response → masked, valid JSON, correct Content-Length; private-key → **block** (not redact); AWS key → block; email → `[REDACTED:email]`; gzip response → decoded, scanned, redacted, identity-encoded out; over-budget body → truncation guard blocks; detection error + `fail_close:false` → pass unredacted; high-entropy gate suppresses base64-image false positive; multiple matches → single-pass rewrite, one alloc.

**Decision needed:** confirm acceptance of forced BUFFERED response-body mode (latency/memory cost) for DLP-enabled routes, and the redact-vs-block default per detector kind.

**Deliverable:** `-tags dlp` binary redacts/blocks sensitive response data. **Verification:** `make build TAGS="dlp"`; `go test -race ./internal/sensitive/... ./internal/server/extproc/...`; ext_proc body-mutation integration test; `golangci-lint`; `make vuln`; e2e cases. Confirm `TestHotPathZeroAlloc` unaffected (DLP is body-phase, opt-in).

---

## Phase 7 — Anomaly scoring + adaptive concurrency limiting

**Why last:** Anomaly scoring aggregates signals from **every** detection engine above (so they must exist first) and requires adding `Score` to a hot-path value type; adaptive concurrency requires **new per-stream response-token plumbing** in ext_proc. Both native, pure-Go, no library imports.

### 7a — Anomaly scoring (cross-signal aggregator, pipeline-level — NOT an engine)
- Add `Score int` to `decision.Verdict` (and optionally `Decision`). Engines that today Block can instead Continue-with-Score; high-confidence engines emit Score ≥ threshold. **Must stay allocation-free** (verified by `TestHotPathZeroAlloc`/`TestResolveZeroAlloc`); Score 0 = unchanged "most severe wins" semantics for non-opting engines.
- Add `anomalyScore int` accumulator to the pooled `Transaction` (reset in `Reset` — keeps Transaction audit/metrics-free, one int, zero alloc).
- Add an `anomaly` **Stage** (register in `stages.NewCatalog` + `config.knownInspectors`), placed **after** scoring detection stages. Reads `tx.anomalyScore` vs compiled per-policy threshold → Block (`engine="anomaly"`, reason `anomaly score N>=T`, contributing rule_ids joined) or Continue. Weights compiled cold-path. Mirrors OWASP CRS collaborative scoring (default inbound 5 / outbound 4). Each contributing finding still recorded on `tx.findings` (full trail). `score_only` signals (CRS executing-vs-blocking-PL) contribute without ever blocking alone.
- **YAML:** `anomaly_scoring{enabled, threshold, response_threshold, status_code, weights{coraza,jwt,sensitive_data,header_anomaly,suspicious_user_agent}, score_only[]}` — **policy-level, not under `engines`.**

### 7b — Adaptive concurrency limiter (sibling of ratelimit)
- **Package:** `internal/engine/adaptivelimit` — **built-in, no tag.** Clone ratelimit's `numShards`/`maxKeysPerShard` sharded map, maphash keying, per-shard mutex (sanctioned lock), `KeySource`, `*EnginesSpec` pointer-identity sharing. `RequiresBody()==false` (header phase). **Stateful.**
- **Algorithm (no library — reimplement ~120 lines, reference `platinummonkey/go-concurrency-limits` Apache-2.0):** **AIMD as the lean default** (overload signal = 5xx/timeout/queue-reject, no RTT needed); Vegas/Gradient2 opt-in (need RTT, require response processing).
- **The hard part — per-stream reservation token (new ext_proc wiring, NOT a new lock):** reserve a slot on the request-headers message; **release + record RTT/overload on the matching RESPONSE message of the same stream**. Stash an opaque `{key, start, shard}` token on per-stream server state; release on the response handler **and on stream teardown via deferred cleanup** (reuse the panic-recover boundary) so an aborted/timed-out/half-open stream **always releases — no slot leak** (slot leak = permanent shed = DoS).
- **YAML:** `adaptive_limit{key, header, algorithm: aimd|vegas|gradient2, initial_limit, min_limit, max_limit, increase_by, backoff_ratio, overload_on[], rtt_tolerance, smoothing, status_code: 503}`.
- **Metrics:** `adaptive_limit_current`, `adaptive_limit_inflight`, `adaptive_limit_shed_total` (pull-based func collectors, instance label), `fail_open`/`fail_close` on limiter-internal error. **Keep shed (503, availability) distinct from anomaly block (403, security)** — shedding must NOT contribute to the anomaly score; audit/metric them separately.
- **Fail posture:** enforce `min_limit` floor (misconfigured `backoff_ratio` can collapse to 1); start in **detect/shadow** so operators see would-shed first; key-flood mitigated by `maxKeysPerShard` reset (fail-open on memory pressure — documented).

**Decision needed:** confirm Envoy ext_proc **response processing is enabled** in target deployments (required for Vegas/Gradient2 RTT release; AIMD works on request + stream-completion alone). Default to AIMD if not.

**e2e cases:** weak signals (header anomaly 2 + suspicious UA 2 + PL3 Coraza 5) sum ≥ threshold → block; single signal below threshold → pass; `score_only` UA never blocks alone; detect/shadow mode logs would-block without blocking. Adaptive: inflight reaches limit → 503 + Retry-After; backend 5xx → multiplicative decrease (limit drops); recovery → additive increase; **forced stream abort/timeout → slot released (no counter drift)** under `-race`; key-flood → shard reset, no unbounded memory; AIMD with response processing disabled still releases on stream end.

**Deliverable:** adaptive control plane. **Verification:** `make build`; `go test -race` incl. `TestStressConcurrentListenersWithReloads` + a **forced-abort slot-release** test + `TestHotPathZeroAlloc`/`TestResolveZeroAlloc` (Score must not regress 0-alloc); `golangci-lint`; e2e cases.

---

## Risks & cross-cutting flags

- **Hot-path value-type changes (Phase 7 `Score`)** and **per-stream token (Phase 7)** and **body-mutation action (Phase 6)** are the only three changes touching sacred hot-path/core types — gate each behind `TestHotPathZeroAlloc`/`TestResolveZeroAlloc` and the `-race` stress test.
- **Source-IP trust** underpins IP-rep and bot good-bot verification — both MUST use the trusted-hop-derived `tx.SourceIP`, never raw XFF (repo's normalized-attribute invariant).
- **Default-lib network-on-verify (JWKS)**, **canonicalization mismatch (HMAC/SigV4)**, **body-digest gate bypass (HMAC)**, **fragment-cycle self-DoS (GraphQL)**, **slot-leak (adaptive)**, **Content-Length corruption (DLP)** are the named footguns — each has a concrete mitigation above and a dedicated e2e case.
- **License/size → build tags:** OpenAPI (heavy tree → `openapi`), DLP gitleaks corpus (large → `dlp`), RFC 9421/SigV4 (young single-digit-star libs → tags), GraphQL advanced cost (large tree → `graphql_advanced`). Everything else (IP-rep/bart+maxminddb, bot/mileusna, apikey+native-HMAC/stdlib, JWKS/keyfunc+jwkset, XFCC/hand-rolled, GraphQL/gqlparser, anomaly+adaptive/native) is **pure-Go built-in** in the lean binary.
- **CI:** every phase must keep the `coraza clickhouse otel` + new-tag matrix green (vet/lint/test/-race/govulncheck/fuzz) per `.github/workflows/ci.yml`; **build go 1.26.4+**.

## Decisions needed from the user
1. **Bot (Phase 2):** can target Envoy deployments enable JA4 fingerprinting + header propagation? If not, ship layers 1/2/4 and document JA4 as enable-when-available.
2. **JWKS cold-start (Phase 4):** confirm preference to **fail the config reload** if the initial JWKS fetch fails (recommended — keep last-good) vs degraded serve.
3. **HMAC/RFC 9421/SigV4 (Phase 3):** which interop schemes are actually required? Native-only keeps the lean binary crypto-dependency-free.
4. **DLP (Phase 6):** accept forced BUFFERED response-body mode on DLP routes, and confirm redact-vs-block defaults per detector (recommend: private-key/AWS-key → block; card/SSN/email/JWT → redact).
5. **Adaptive concurrency (Phase 7):** is ext_proc **response processing** enabled? If not, ship AIMD-only (request + stream-completion signal); make Vegas/Gradient2 opt-in.
6. **Phase 0:** fold the shared-infra packages into Phase 1 (no dead-code phase) or land them standalone first? Recommend folding into Phase 1.

---

## Final ordered checklist

- [ ] **Phase 0/1 — Shared infra + IP reputation** (`internal/netmatch` bart, `internal/feed`, `internal/geoip` maxminddb/v2, `internal/engine/ipreputation`; header-phase, built-in). Verify: default build, `-race`, lint, 0-alloc bench, IP/CIDR/Geo/feed e2e.
- [ ] **Phase 2 — Bot detection ⭐** (`internal/engine/bot`, mileusna UA + bart good-bot feeds + JA4 header; header-phase, built-in, block-capable). Verify: default build, `-race`, lint, spoofed-Googlebot/JA4/UA-deny e2e, `TestHotPathZeroAlloc`. Envoy JA4 propagation documented.
- [ ] **Phase 3 — API-key + native HMAC** (`internal/engine/auth` shared, `apikey` built-in, `hmacsign` native built-in / RFC9421+SigV4 tagged; replay cache = 2nd sanctioned lock). Verify: default+tagged build, `-race`, lint, vuln, replay/stale/body-digest e2e, redaction of new headers.
- [ ] **Phase 4 — JWKS + XFCC** (extend `jwt` with SI-5 background refresher, `internal/engine/xfcc` hand-rolled; header-phase, built-in). Verify: default build, `-race` + goroutine-leak + stress, fuzz (XFCC oracle), unknown-kid-no-network e2e, SANITIZE_SET documented.
- [ ] **Phase 5 — OpenAPI (`-tags openapi`) + GraphQL (built-in)** (body-phase semantic; pre-resolved PathItem sync validate; gqlparser single-DFS + persisted-query allowlist). Verify: default+openapi build, `-race`, lint, vuln, positive-validation + GraphQL-DoS e2e.
- [ ] **Phase 6 — DLP (`-tags dlp`)** (mutating Stage + `tx.ReplaceBody` + ext_proc body_mutation, BUFFERED response mode, gitleaks corpus as data). Verify: dlp build, `-race`, ext_proc mutation integration test, lint, vuln, redact/block/Content-Length e2e.
- [ ] **Phase 7 — Anomaly scoring + adaptive concurrency** (`Score` on Verdict + `anomaly` Stage; `internal/engine/adaptivelimit` AIMD + per-stream release token). Verify: default build, `-race` + stress + forced-abort slot-release, `TestHotPathZeroAlloc`/`TestResolveZeroAlloc` (Score 0-alloc), lint, scoring + shed-vs-block e2e.

Each phase is independently shippable; the lean default binary grows by IP-rep → bot → apikey/native-HMAC → JWKS/XFCC → GraphQL → adaptive/anomaly, while OpenAPI, RFC9421/SigV4, and DLP stay behind build tags.
