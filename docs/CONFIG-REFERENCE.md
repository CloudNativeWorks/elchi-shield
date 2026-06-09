# elchi-shield — Configuration Reference

Complete reference for the on-disk policy configuration: every field, its type,
allowed values, default, and what it does. This is the source-of-truth model for
the YAML/JSON files the management plane (`elchi-client`) writes into the watched
config directory.

> **Scope.** This document covers the **policy config** (the watched files). It does
> NOT cover process/operational flags (sockets, loopback enforcement, body-memory
> budgets, pprof, GOGC) — those are CLI flags / env vars passed at startup, not
> policy files. See `cmd/elchi-shield` `--help` and `docs/CONCURRENCY.md`.

## Contents
- [File envelope](#file-envelope)
- [`spec`](#spec)
- [Multi-file behavior & merge](#multi-file-behavior--merge)
- [`spec.exclude`](#specexclude)
- [`Domain`](#domain)
- [`Route` & `Match`](#route--match)
- [`HeaderMatch`](#headermatch)
- [`PolicySpec` (defaults / domain.policy / route.policy)](#policyspec)
- [Policy resolution order](#policy-resolution-order)
- [`pipeline`](#pipeline)
- [`checks`](#checks)
- [`checks.body.dlp`](#checksbodydlp)
- [`engines`](#engines)
  - [jwt](#engine-jwt) · [jwks](#engine-jwks) · [coraza](#engine-coraza) ·
    [rate_limit](#engine-rate_limit) · [ip_reputation](#engine-ip_reputation) ·
    [bot](#engine-bot) · [api_key](#engine-api_key) · [hmac_sign](#engine-hmac_sign) ·
    [http_signature](#engine-http_signature) · [xfcc](#engine-xfcc) ·
    [graphql](#engine-graphql) · [openapi](#engine-openapi)
- [Engines and audit sinks](#engines-and-audit-sinks)
- [Conventions: types](#conventions-types)

---

## File envelope

Every file uses a Kubernetes-style envelope so it is versionable and familiar.

| Field | Type | Required | Allowed / default | Purpose |
|---|---|---|---|---|
| `apiVersion` | string | yes | must be `sentinel.elchi.io/v1` | Schema version. Any other value rejects the file. |
| `kind` | string | yes | must be `SecurityPolicy` | Document type. |
| `metadata.name` | string | no | free text | Human label for the document (diagnostics only). |
| `metadata.labels` | map[string]string | no | free text | Operator labels (informational; not used for selection). |
| `spec` | object | yes | — | The policy body (see below). |

```yaml
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata:
  name: public-api
spec:
  ...
```

---

## `spec`

| Field | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `defaults` | [`PolicySpec`](#policyspec) | no | built-in `DefaultPolicy` | File-level policy defaults applied beneath every domain/route in this file. |
| `domains` | [`Domain`](#domain)[] | no | empty | Host-scoped route sets. |
| `exclude` | string[] | no | empty | Request paths that bypass ALL inspection (see below). |

A file with no `domains` is valid (e.g. a file that only contributes `exclude`
paths, merged with other files). Hosts not matched by any domain fall through to
the request being allowed (no policy ⇒ pass-through; the inspection posture only
applies to matched hosts).

---

## Multi-file behavior & merge

- The service **watches a directory**; multiple YAML/JSON files are read and merged
  into one runtime snapshot on every (debounced) change.
- **One file may contain multiple domains**; one domain may contain multiple routes.
- **Hosts are globally unique** across all files. The same host (case-insensitive,
  whitespace-trimmed) declared in two domains — in the same or different files — is
  a validation error (ambiguous resolution). The error is attributed to the file.
- **`exclude` is a union** across all files, deduplicated.
- **Reload is atomic and fail-safe.** If the merged result fails validation, the
  current snapshot stays active and a failure metric/log is emitted with the
  attributed file+field. The last valid config is reloaded from disk on restart.

---

## `spec.exclude`

A list of request **paths** that bypass *all* inspection — checked **before**
policy resolution as a cheap, shared pass-through. Use it for health checks,
metrics scrapes, or static assets that never need a WAF decision.

| Property | Behavior |
|---|---|
| Match type | **Exact** path match (not prefix). |
| Query string | **Ignored** (stripped before matching). |
| Normalization | Path is percent-decoded once, dot-segments (`/./`, `/../`) and duplicate slashes collapsed, then compared — the same `NormalizePath` used for route matching, so an attacker can't dodge it with `%2e` or `//`. |
| Validation | Each entry must be a **non-empty absolute path** (start with `/`). |
| Case | Case-sensitive (HTTP path convention). |
| Posture | Applies regardless of the default mode (block/detect/etc.) — an excluded path is always a `continue`. |

```yaml
spec:
  exclude:
    - /healthz
    - /metrics
    - /favicon.ico
```

---

## `Domain`

Scopes a set of routes to one or more hosts.

| Field | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `hosts` | string[] | **yes** (≥1) | — | The request authorities this domain matches. |
| `policy` | [`PolicySpec`](#policyspec) | no | inherits file defaults | Domain-level override applied above file defaults, below each route. |
| `routes` | [`Route`](#route--match)[] | no | empty | Routes evaluated by match precedence. |

### `hosts` entries

Each entry is one of:

| Form | Example | Matches | Specificity |
|---|---|---|---|
| Exact host | `api.example.com` | only that host | highest |
| Leading wildcard | `*.example.com` | any single-or-multi-label subdomain | by suffix length |
| Catch-all | `*` | any host | lowest |

- The domain matches if **ANY** entry matches.
- When multiple domains could match a host, the **most-specific matching entry
  wins**: exact > `*.x` (longer suffix beats shorter) > `*`.
- Host matching is on the **canonical** authority: userinfo and port stripped,
  trailing dot removed, lower-cased. A `Host` header disagreeing with `:authority`
  is rejected.
- Validation: an entry must be `*` or match `^(\*\.)?label(\.label)*$`
  (alphanumerics, `_`, `-`). No port, `@`, or scheme allowed.

```yaml
domains:
  - hosts: ["api.example.com", "*.api.example.com"]
    policy: { mode: block }
    routes: [ ... ]
  - hosts: ["*"]            # catch-all fallback for any other host
    policy: { mode: detect }
```

---

## `Route` & `Match`

A route binds a **match predicate** to a **policy override**.

| Field | Type | Required | Purpose |
|---|---|---|---|
| `match` | `Match` | no | Predicate selecting requests. An **empty match matches every request** to the domain (the domain default route). |
| `policy` | [`PolicySpec`](#policyspec) | no | Policy override for matched requests. |

Within a domain, routes are selected by **path-match precedence**:
`path_exact` > `path_regex` > `path_prefix`. Two routes with identical predicates
in one domain is a validation error (duplicate route).

### `Match` fields

| Field | Type | Allowed values | Purpose |
|---|---|---|---|
| `path_exact` | string | a path | Match the exact normalized path. |
| `path_prefix` | string | a path prefix | Match paths under this prefix. |
| `path_regex` | string | RE2 regex | Match paths by regex (must compile). |
| `methods` | string[] | `GET HEAD POST PUT PATCH DELETE CONNECT OPTIONS TRACE` (case-insensitive) | Restrict to these HTTP methods. Empty = any. |
| `content_type` | string[] | media types | Restrict to these `Content-Type`s. Empty = any. |
| `headers` | [`HeaderMatch`](#headermatch)[] | — | Additional header predicates (all must match). |

**Constraint:** set **at most one** of `path_exact` / `path_prefix` / `path_regex`.
Paths are matched on the normalized form (percent-decoded, dot-segments collapsed).

```yaml
routes:
  - match: { path_prefix: /admin, methods: [POST, PUT] }
    policy: { mode: block, engines: { ... } }
  - match: {}                         # domain default route
    policy: { mode: detect }
```

---

## `HeaderMatch`

Matches a single request header. **Set at most one** of `exact`/`contains`/`regex`/`present`.

| Field | Type | Purpose |
|---|---|---|
| `name` | string (**required**) | Header name (case-insensitive). |
| `exact` | string | Exact value match. |
| `contains` | string | Substring match. |
| `regex` | string (RE2) | Regex match (must compile). |
| `present` | bool (pointer) | `true` = header must be present; `false` = must be absent. |

---

## `PolicySpec`

The sparse policy block used at three scopes (`spec.defaults`, `domain.policy`,
`route.policy`). Only **set** fields override the inherited value — pointers
distinguish "unset" from a meaningful zero (e.g. `max_request_body_bytes: 0`
means "do not inspect", not "no limit").

| Field | Type | Default (built-in) | Allowed / range | Purpose |
|---|---|---|---|---|
| `mode` | enum | `block` | `block` \| `detect` \| `shadow` \| `off` | Enforcement posture. See [modes](#modes). |
| `fail_mode` | enum | `fail_open` | `fail_open` \| `fail_close` | Behavior when an engine errors or times out. |
| `inspect_request_body` | bool | `false` | — | Buffer & inspect the request body. |
| `inspect_response_body` | bool | `false` | — | Buffer & inspect the response body. |
| `max_request_body_bytes` | int64 | `1048576` (1 MiB) | `0`–`1073741824` (1 GiB); `0` = do not inspect | Per-request body buffer cap. Over-limit ⇒ block (non-skippable). |
| `max_response_body_bytes` | int64 | `0` (no inspect) | `0`–`1 GiB`; `0` = do not inspect | Per-response body buffer cap. |
| `max_header_bytes` | int64 | `8192` (8 KiB) | `≥ 0` | Default per-header-value size cap when a route's `checks` doesn't set a tighter one. |
| `timeout` | duration | `50ms` | must be `> 0` if set | Per-request inspection deadline (context deadline). |
| `log_level` | string | `info` | `debug` \| `info` \| `warn` \| `warning` \| `error` | Per-policy log verbosity. |
| `sampling_rate` | float | `1.0` | `[0, 1]` | Fraction of *allow* decisions audited (blocks/detections always audited). |
| `anomaly_threshold` | int | `0` (disabled) | `≥ 0` | Block when summed engine anomaly scores reach this. `0` disables. |
| `skip_checks` | string[] | empty | see [skip_checks](#skip_checks-values) | Exempt named built-in checks. Accumulates (union) across scopes. |
| `pipeline` | [`PipelineSpec`](#pipeline) | default order | — | Reorder/disable inspector stages. |
| `checks` | [`Checks`](#checks) | none | — | Built-in header/body checks. |
| `engines` | [`EnginesSpec`](#engines) | none | — | Pluggable security engines. |

### Cross-field validation
- `mode: off` with `inspect_request_body: true` or `inspect_response_body: true`
  is rejected (inspecting a body while off can never do anything).
- `inspect_request_body: true` with `max_request_body_bytes: 0` is rejected
  (enabled but no budget). Same for the response pair.

### Modes
| Mode | Effect |
|---|---|
| `block` | Enforce. A blocked request gets an immediate **403**. |
| `detect` | Evaluate + log/metric (`detections_total`) but **allow** (monitor mode). |
| `shadow` | Evaluate as if blocking, log what *would* block (`shadow_detections_total`), **allow**. |
| `off` | Skip inspection entirely (continue). |

### `skip_checks` values
Names of built-in checks that can be exempted:

| Value | Skips |
|---|---|
| `host` | `enforce_valid_host` check |
| `forbidden_headers` | forbidden-header-names block |
| `required_headers` | required-header-names block |
| `oversized_headers` | per-header size cap |
| `json` | `require_json` body check |
| `sensitive_data` | `detect_sensitive_data` body hook |

> Note: structural protections (body **truncation** guard, content **decode**,
> body-memory **budget**) are **not** skippable — they always run.

---

## Policy resolution order

For a matched request, the effective policy is folded **least-specific first**:

```
built-in DefaultPolicy  →  spec.defaults  →  domain.policy  →  route.policy
```

Rules:
- Scalar fields: the **most-specific set value wins**.
- `skip_checks`: **union** across all scopes (a broad scope can exempt, a narrow
  scope can add more).
- `pipeline.request` / `pipeline.response`: **replace wholesale** per direction when set.
- `checks.headers` and `checks.body`: each sub-block **replaces** when set.
- `engines`: **replaces wholesale** when set (a narrower scope's `engines` block
  fully supersedes the inherited one — it is not deep-merged).

---

## `pipeline`

Reorders (and, by omission, disables) the **reorderable inspector stages**. The
structural stages (context init, policy resolve, early decision, body-truncation
guard, content-decode, body gate) are always present at fixed positions and are
not listed here.

| Field | Type | Purpose |
|---|---|---|
| `request` | string[] | Inspector order for the request pipeline. |
| `response` | string[] | Inspector order for the response pipeline. |

**Valid stage names** (no duplicates):

| Stage | Phase | Contains |
|---|---|---|
| `fast_pre_checks` | header | host/forbidden/required/oversized-header checks |
| `body_checks` | body | `require_json`, `detect_sensitive_data`, DLP |
| `waf_engine` | header **and** body | expands to header-phase engines (e.g. JWT, api_key, ip_reputation, bot, xfcc, hmac_sign, jwks) at header time + body engines (e.g. Coraza, GraphQL, OpenAPI) at body time |

Behavior:
- **Omitting** a stage disables it for that direction.
- Default order when unset: `fast_pre_checks` → `body_checks` → `waf_engine`.
- Cross-phase position is normalized (header-phase inspectors always run at header
  time, body-phase at body time); **ordering WITHIN a phase is honored exactly** —
  e.g. listing `waf_engine` before `body_checks` runs the WAF engines first.

```yaml
policy:
  pipeline:
    request:  [fast_pre_checks, waf_engine, body_checks]
    response: [body_checks]      # only DLP on the response
```

---

## `checks`

Built-in (non-engine) inspections.

| Field | Type | Purpose |
|---|---|---|
| `headers` | `HeaderChecks` | Header inspection. |
| `body` | `BodyChecks` | Body inspection. |

### `checks.headers`

| Field | Type | Default | Purpose |
|---|---|---|---|
| `forbidden` | string[] | empty | Header names that cause a **block** when present. |
| `required` | string[] | empty | Header names that cause a **block** when absent. |
| `max_header_value_bytes` | int64 | `0` (off) | Cap on a single header value's size; `0` disables. |
| `enforce_valid_host` | bool | `false` | Block requests with a missing/invalid Host/authority. |

### `checks.body`

| Field | Type | Default | Purpose |
|---|---|---|---|
| `require_json` | bool | `false` | Block bodies that are not valid JSON for JSON content types. |
| `detect_sensitive_data` | bool | `false` | Enable the built-in PII/secret detection hook. |
| `dlp` | [`DLPSpec`](#checksbodydlp) | none | Data-loss prevention (block/redact). |

> Any `checks.body.*` option that needs the body implies body inspection at the
> body phase; ensure `inspect_request_body`/`inspect_response_body` and the
> matching size cap are set for the relevant direction.

---

## `checks.body.dlp`

Data-loss prevention: **block** hard secrets and/or **redact** PII in the body via
the body-mutation channel (strips `Content-Encoding`, lets Envoy recompute
`Content-Length`).

| Field | Type | Default | Allowed | Purpose |
|---|---|---|---|---|
| `direction` | string | `response` | `response` \| `request` \| `both` | Where DLP runs. |
| `block` | string[] | empty | DLP kinds | Kinds that cause a **block**. |
| `redact` | string[] | empty | DLP kinds | Kinds **masked in place**. |

At least one of `block`/`redact` is required. **DLP kinds:**
`credit_card`, `ssn`, `email`, `jwt`, `aws_access_key`, `private_key`,
`google_api_key`, `slack_token`, `github_token`.

```yaml
checks:
  body:
    dlp:
      direction: response
      block:  [private_key, aws_access_key]
      redact: [credit_card, ssn, email]
```

---

## `engines`

The pluggable security engines. Each is a sub-block under `engines:`; omit a block
to disable that engine. Every engine is always compiled into the binary.

```yaml
engines:
  jwt: { ... }
  rate_limit: { ... }
  ip_reputation: { ... }
```

---

### Engine: `jwt`
Built-in. Header-phase. Validates a bearer JWT with a static key.

| Field | Type | Required | Default | Allowed / notes |
|---|---|---|---|---|
| `issuer` | string | no | — | Expected `iss`. |
| `audience` | string | no | — | Expected `aud`. |
| `algorithms` | string[] | **yes** | — | Allowlist. `HS256/384/512`, `RS256/384/512`, `ES256/384/512`, `PS256/384/512`, `EdDSA`. **`none` is rejected.** |
| `hmac_secret` | string | one-of | — | Symmetric key (for `HS*`). |
| `public_key_file` | string | one-of | — | PEM file (for `RS*`/`ES*`/`PS*`/`EdDSA`). |
| `required_claims` | string[] | no | — | Claims that must be present. |
| `header_name` | string | no | `Authorization` | Header carrying the token. |
| `leeway` | duration | no | `0` (strict) | Clock-skew tolerance for `exp`/`nbf`/`iat`. `≥ 0`, `≤ 5m`. |

**Rules:** exactly one of `hmac_secret` / `public_key_file` (mixing symmetric and
asymmetric keys enables algorithm-confusion attacks). The key family must match
the listed algorithms (an HS secret can't verify an RS token, and vice-versa).

---

### Engine: `jwks`
Built-in. Header-phase. Validates a bearer JWT against a **JWK Set**.

| Field | Type | Required | Default | Allowed / notes |
|---|---|---|---|---|
| `file` | string | one-of | — | Local JWKS file (hot-reloaded, no network). |
| `url` | string | one-of | — | Remote JWKS URL (fetched at load, then background-refreshed). Must be **https** (or a loopback host). |
| `issuer` | string | no | — | Expected `iss`. |
| `audience` | string | no | — | Expected `aud`. |
| `algorithms` | string[] | **yes** | — | **Asymmetric only**: `RS*`/`ES*`/`PS*`/`EdDSA`. `HS*` is rejected (a JWKS holds asymmetric keys; allowing HS invites RS256→HS256 confusion). |
| `required_claims` | string[] | no | — | Claims that must be present. |
| `header_name` | string | no | `Authorization` | Header carrying the token. |
| `leeway` | duration | no | `0` | `≥ 0`, `≤ 5m`. |
| `refresh_interval` | duration | no | `10m` | Background URL refresh cadence. `≥ 0`. |
| `http_timeout` | duration | no | `10s` | URL fetch timeout. `≥ 0`. |

**Rules:** exactly one of `file` / `url`. An unknown `kid` ⇒ fail-posture block
(never a hot-path fetch).

---

### Engine: `coraza`
Body-phase WAF. The **OWASP Core Rule Set is embedded in the binary** — set
`include_owasp: true` to load it from memory (no rule files to ship).

| Field | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `directives` | string | one-of | — | Inline SecLang directives (run **after** the CRS so they can add/override rules). |
| `directives_file` | string | one-of | — | Path to a SecLang file (concatenated into `directives`). |
| `include_owasp` | bool | one-of | `false` | Load the embedded OWASP Core Rule Set. |
| `exclude_rule_ids` | string[] | no | — | CRS/custom rule IDs to disable (`SecRuleRemoveById`, applied last). |
| `paranoia_level` | int | no | `0` → CRS default (1) | CRS **blocking** paranoia level `1`–`4` (higher = stricter, more false positives). |
| `detection_paranoia_level` | int | no | `0` → = `paranoia_level` | Run rules up to this PL in **detection** but only block at `paranoia_level`. Must be `≥ paranoia_level`. |
| `inbound_anomaly_threshold` | int | no | `0` → CRS default (5) | Request-side collaborative score that triggers a block (lower = stricter). |
| `outbound_anomaly_threshold` | int | no | `0` → CRS default (4) | Response-side score that triggers a block. |

**Rules:**
- At least one of `directives` / `directives_file` / `include_owasp`.
- The CRS tuning fields (`paranoia_level`, `detection_paranoia_level`,
  `inbound_anomaly_threshold`, `outbound_anomaly_threshold`) **require
  `include_owasp: true`** — they tune the CRS and are a no-op otherwise (rejected
  at load). PL values are `1`–`4` (`0` = use CRS default); thresholds are `≥ 0`.
- This engine inspects **both** request and response.

**Enforcement note:** Coraza always runs in enforcing mode internally (shield
forces `SecRuleEngine On`, overriding the CRS recommended `DetectionOnly`); a CRS
hit returns a block verdict and the shield policy `mode` (`block`/`detect`/
`shadow`/`off`) decides whether it actually blocks. Roll out with `mode: detect`,
watch `detections_total`, then switch to `block`.

---

### Engine: `rate_limit`
Built-in. Header-phase. Sharded token-bucket limiter.

| Field | Type | Required | Default | Allowed / notes |
|---|---|---|---|---|
| `requests_per_second` | float | **yes** | — | Sustained rate per key. Must be `> 0`. |
| `burst` | int | no | `ceil(requests_per_second)` | Bucket capacity (max instantaneous burst). `≥ 0` (`0` = derive from rate). |
| `key` | string | no | `ip` | `ip` \| `host` \| `header` — the limit dimension. |
| `header` | string | conditional | `X-Forwarded-For` (for `key=ip`) | For `key=ip`: header to read the source from. For `key=header`: the key header (**required**). |

> Source IP is derived from the **trusted hop** (right-side XFF), never the
> spoofable leftmost token.

---

### Engine: `ip_reputation`
Built-in. Header-phase. CIDR allow/deny + threat feeds + GeoIP/ASN.

| Field | Type | Required | Purpose |
|---|---|---|---|
| `allow_cidrs` | string[] (CIDR) | — | When **non-empty**, the policy is **default-DENY**: a source IP not in any allow prefix is blocked. |
| `deny_cidrs` | string[] (CIDR) | — | Explicitly blocked prefixes. |
| `feeds` | [`FeedSpec`](#feedspec)[] | — | Disk threat-intel feeds (block lists). |
| `geoip` | [`GeoIPSpec`](#geoipspec) | — | Country/ASN blocking. |

**Rule:** at least one of `allow_cidrs` / `deny_cidrs` / `feeds` / `geoip`.
Precedence: explicit `deny` wins, then `allow` (default-deny), then feeds, then geo.

#### `FeedSpec`
| Field | Type | Required | Default | Allowed |
|---|---|---|---|---|
| `name` | string | yes | — | Identifies the feed in reasons/metrics. |
| `file` | string | yes | — | Feed file path (written by the management plane; never network-fetched). |
| `format` | string | yes | — | `cidr_lines` \| `firehol_netset` \| `spamhaus_json`. |
| `severity` | string | no | `medium` | `low` \| `medium` \| `high` \| `critical`. |

#### `GeoIPSpec`
| Field | Type | Required | Default | Allowed / notes |
|---|---|---|---|---|
| `database_file` | string | one-of | — | MaxMind GeoLite2/GeoIP2 **Country** `.mmdb`. |
| `asn_database_file` | string | one-of | — | MaxMind **ASN** `.mmdb`. |
| `block_countries` | string[] | — | — | ISO 3166-1 alpha-2 codes to block (e.g. `["KP","RU"]`). |
| `allow_countries` | string[] | — | — | When **non-empty**, geo is **default-DENY**: any other country is blocked. |
| `block_asns` | uint[] | — | — | Autonomous system numbers to block. |
| `on_missing` | string | no | `continue` | `continue` \| `block` — behavior for an IP absent from the DB. |

**Rules:** one of `database_file` / `asn_database_file` required; at least one of
`block_countries` / `allow_countries` / `block_asns` / `on_missing=block`. A
country in **both** block and allow is rejected. A GeoIP **lookup error**
propagates so the policy `fail_mode` governs (it is not silently allowed).

---

### Engine: `bot`
Built-in. Header-phase. Layered scorer: verified-bot IP check, UA rules, JA3/JA4
TLS fingerprints (supplied by Envoy as headers), header-anomaly heuristics.

| Field | Type | Default | Purpose |
|---|---|---|---|
| `score_threshold` | int | `0` (disabled) | Block when the accumulated score reaches it. `0` disables score-based blocking (hard-block layers still apply). |
| `emit_score` | bool | `false` | Contribute the bot score to the policy **anomaly** aggregator instead of blocking at `score_threshold`. |
| `user_agent` | `BotUASpec` | — | User-Agent layer. |
| `verified_bots` | `BotVerifiedSpec`[] | — | Verified-crawler IP checks. |
| `tls_fingerprint` | `BotTLSSpec` | — | JA3/JA4 layer. |
| `heuristics` | `BotHeuristicsSpec` | — | Header-anomaly layer. |

**`user_agent` (`BotUASpec`)**
| Field | Type | Default | Purpose |
|---|---|---|---|
| `deny_substrings` | string[] | — | UA substrings that hard-block (an empty substring is rejected — it would match all traffic). |
| `block_empty` | bool | `false` | Block a missing/empty User-Agent. |
| `score_known_bot` | int | `0` | Score added for a known-bot UA. `≥ 0`. |

**`verified_bots` (`BotVerifiedSpec`)** — each entry:
| Field | Type | Required | Allowed |
|---|---|---|---|
| `name` | string | yes | identifier |
| `file` | string | yes | IP feed path |
| `format` | string | yes | `cidr_lines` \| `firehol_netset` \| `spamhaus_json` |
| `ua_match` | string (regex) | yes | UA pattern claiming this bot (must compile) |

**`tls_fingerprint` (`BotTLSSpec`)**
| Field | Type | Default | Purpose |
|---|---|---|---|
| `ja4_header` | string | `x-shield-ja4` | Header carrying the JA4 hash. |
| `ja3_header` | string | `x-shield-ja3` | Header carrying the JA3 hash. |
| `deny_ja4` | string[] | — | JA4 hashes that hard-block. |
| `deny_ja3` | string[] | — | JA3 hashes that hard-block. |
| `score_ja4` | map[string]int | — | Per-JA4 score contributions (each `≥ 0`). |
| `tool_ja4` | string[] | — | JA4s flagged as tools (used for JA4↔UA consistency). |

**`heuristics` (`BotHeuristicsSpec`)**
| Field | Type | Default | Purpose |
|---|---|---|---|
| `require_accept` | bool | `false` | Anomaly if `Accept` absent. |
| `require_accept_language` | bool | `false` | Anomaly if `Accept-Language` absent. |
| `require_accept_encoding` | bool | `false` | Anomaly if `Accept-Encoding` absent. |
| `score_per_anomaly` | int | `0` | Score added per header anomaly. `≥ 0`. |

**Rules:** at least one detection layer required. If any **score** layer is set,
either `score_threshold > 0` or `emit_score: true` is required (otherwise the
score can never block — a silent no-op). `emit_score` without a score layer is
also rejected.

---

### Engine: `api_key`
Built-in. Header-phase. SHA-256-hashed keys with scope→path bindings.

| Field | Type | Required | Default | Allowed |
|---|---|---|---|---|
| `source` | string | no | `header` | `header` \| `query`. |
| `name` | string | no | `X-Api-Key` | Header / query parameter carrying the key. |
| `keys` | `APIKeyEntrySpec`[] | **yes** (≥1) | — | Configured credentials. |
| `require_scope_for_path` | `ScopeBindingSpec`[] | no | — | Path-prefix → required-scope bindings. |

**`keys` (`APIKeyEntrySpec`)** — each entry needs `sha256` **or** `key`:
| Field | Type | Notes |
|---|---|---|
| `sha256` | string | 64-char hex SHA-256 digest of the key (preferred, hashed at rest). |
| `key` | string | Raw key (hashed at load). |
| `subject` | string | Identity attributed on success. |
| `scopes` | string[] | Scopes this key carries. |

**`require_scope_for_path` (`ScopeBindingSpec`)**:
| Field | Type | Required | Purpose |
|---|---|---|---|
| `path_prefix` | string | yes | Path prefix to guard. |
| `scope` | string | yes | Scope a key must carry to reach it. |

---

### Engine: `hmac_sign`
Built-in. Native HMAC request signing with a timestamp window + nonce replay
protection and optional body-digest gating.

| Field | Type | Required | Default | Allowed / notes |
|---|---|---|---|---|
| `secret` | string | one-of | — | Shared secret. **≥ 16 bytes.** |
| `secrets` | map[string]string | one-of | — | Per-key-id secrets for rotation (each **≥ 16 bytes**). |
| `signature_header` | string | no | `X-Signature` | Header carrying the signature. |
| `timestamp_header` | string | no | `X-Timestamp` | Header carrying the epoch-seconds timestamp. |
| `nonce_header` | string | no | `X-Nonce` | Header carrying the nonce. |
| `key_id_header` | string | no | `X-Key-Id` | Header selecting the key id (with `secrets`). |
| `algorithm` | string | no | `sha256` | `sha256` \| `sha512`. |
| `window` | duration | no | `5m` | Timestamp acceptance window. `0` (use default) or `≥ 1s`; `≤ 1h`. |
| `nonce_ttl` | duration | no | `= window` | Replay-cache TTL. `≤ 1h`. |
| `require_nonce` | bool | no | `false` | Require a nonce (else identical replays within the window are caught by the timestamp). |
| `require_body_digest` | bool | no | `false` | Require the signature to bind a body digest. |

**Rule:** exactly one of `secret` / `secrets`.

---

### Engine: `http_signature`
RFC 9421 (HTTP Message Signatures). Initial support: `hmac-sha256`.

| Field | Type | Required | Default | Allowed / notes |
|---|---|---|---|---|
| `secret` | string | **yes** | — | Shared HMAC key. **≥ 64 bytes** (RFC 9421 hmac-sha256 requirement). |
| `signature_name` | string | no | `sig1` | Label expected in `Signature-Input`. |
| `covered_components` | string[] | no | `@method`, `@authority`, `@path` (+`@query` covered by default) | Components the signature must cover. |
| `max_age` | duration | no | `10s` | Reject a signature whose `created` is older than this. `≥ 0`, `≤ 1h`. |

---

### Engine: `xfcc`
Built-in. Authenticates by Envoy's forwarded mTLS client-cert identity (XFCC).

| Field | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `header_name` | string | no | `x-forwarded-client-cert` | XFCC header. |
| `require_present` | bool | no | `false` | Require the XFCC header (presence-only auth). |
| `uris` | string[] | — | — | Allowed SPIFFE/URI SANs. |
| `dns_names` | string[] | — | — | Allowed DNS SANs (case-insensitive). |
| `subjects` | string[] | — | — | Allowed certificate subjects. |
| `hashes` | string[] | — | — | Allowed cert fingerprints. |

**Rule:** `require_present` or at least one allow-list dimension
(`uris`/`dns_names`/`subjects`/`hashes`) is required. Allow-list dimensions are
**OR'd**. Only the Envoy-appended (trusted) XFCC element is honored.

---

### Engine: `graphql`
Built-in. Body-phase. Guards GraphQL query shape (DoS protections).

| Field | Type | Default | Notes |
|---|---|---|---|
| `content_types` | string[] | `application/json`, `application/graphql` | Bodies treated as GraphQL. Also inspects GraphQL-over-GET. |
| `paths` | string[] | — | Restrict to these paths (empty = any). |
| `max_depth` | int | `0` (off) | Max query nesting depth. |
| `max_aliases` | int | `0` (off) | Max aliases. |
| `max_root_fields` | int | `0` (off) | Max root fields (counted through fragments). |
| `max_total_fields` | int | `0` (off) | Max total fields. |
| `max_operations` | int | `0` (off) | Max operations per document (batching). |
| `block_introspection` | bool | `false` | Block introspection queries. |
| `max_fragment_depth` | int | `32` | Fragment-spread recursion bound (DoS). |
| `max_complexity` | int | `100000` | Per-operation node-visit budget. **Always enforced** as a backstop (`0` falls back to the default, it does NOT disable it). |

**Rule:** at least one of `max_depth` / `max_aliases` / `max_root_fields` /
`max_total_fields` / `max_operations` or `block_introspection` is required (a
zero individual limit disables only *that* check).

---

### Engine: `openapi`
Positive-security validation against an OpenAPI 3.x spec.

| Field | Type | Required | Default | Purpose |
|---|---|---|---|---|
| `spec_file` | string | **yes** | — | Path to the OpenAPI 3.x document. |
| `validate_request_body` | bool | no | `false` | Validate the request body against the schema (implies body inspection). |
| `reject_undeclared_path` | bool | no | `false` | Block paths/operations not in the spec. |

---

## Engines and audit sinks

There are no build tags. The single binary always compiles in every engine
(including `coraza`, `http_signature`, and `openapi`) and every audit sink
(ClickHouse, OTEL). Build with `make build` and configure whatever you need.

---

## Conventions: types

- **Durations** are Go duration strings: `"50ms"`, `"2s"`, `"5m"`, `"1h"` (both
  YAML and JSON).
- **Pointers / "unset"**: in `PolicySpec`, an omitted field inherits; a present
  field (even a zero like `0` or `false`) overrides. This is why `0` body bytes
  means "do not inspect", not "no limit".
- **CIDR** fields are standard prefixes (`"10.0.0.0/8"`, `"2001:db8::/32"`).
- **Regex** fields are RE2 (linear-time, no backtracking) and must compile at load.
- **Country codes** are ISO 3166-1 alpha-2 (two letters).
- **Hosts** are exact, single leading-wildcard (`*.example.com`), or `*`.
- All config errors are attributed to **file + field + reason**; an invalid file
  never affects active traffic (the last valid snapshot stays live).

---

*Keep this file in sync with `internal/config/types.go` (schema),
`internal/config/validate.go` (constraints), `internal/config/policy.go`
(`DefaultPolicy`), and the engine builders under `internal/engine/*` and
`internal/policy/engines.go` (build-time defaults).*
