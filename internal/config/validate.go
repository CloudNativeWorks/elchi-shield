package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// knownMethods is the set of HTTP methods accepted in a route match.
var knownMethods = map[string]struct{}{
	"GET": {}, "HEAD": {}, "POST": {}, "PUT": {}, "PATCH": {},
	"DELETE": {}, "CONNECT": {}, "OPTIONS": {}, "TRACE": {},
}

// knownLogLevels mirrors logging.parseLevel's accepted names.
var knownLogLevels = map[string]struct{}{
	"debug": {}, "info": {}, "warn": {}, "warning": {}, "error": {},
}

// knownJWTAlgs is the allowlist of accepted JWT signing algorithms. "none" is
// deliberately excluded — accepting it would allow signature-stripping forgery.
var knownJWTAlgs = map[string]struct{}{
	"HS256": {}, "HS384": {}, "HS512": {},
	"RS256": {}, "RS384": {}, "RS512": {},
	"ES256": {}, "ES384": {}, "ES512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
	"EdDSA": {},
}

// maxSaneBodyBytes is the hard ceiling a policy may request Envoy to buffer per
// body (1 GiB). It guards against a typo asking for terabytes of buffering.
const maxSaneBodyBytes = 1 << 30

// hostRe permits exact hosts and a single leading-wildcard label.
var hostRe = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9_-]+)(\.[a-zA-Z0-9_-]+)*$`)

// validateFile checks a single parsed file in isolation and returns every
// problem found, each attributed to file + field.
func validateFile(file string, f *File) []error {
	var errs []error
	add := func(field string, err error) {
		errs = append(errs, newFileError(file, field, err))
	}

	if f.APIVersion != APIVersionV1 {
		add("apiVersion", fmt.Errorf("unsupported apiVersion %q, want %q", f.APIVersion, APIVersionV1))
	}
	if f.Kind != KindSecurityPolicy {
		add("kind", fmt.Errorf("unsupported kind %q, want %q", f.Kind, KindSecurityPolicy))
	}

	errs = append(errs, validateSpec(file, "spec.defaults", f.Spec.Defaults)...)

	for _, ex := range f.Spec.Exclude {
		if strings.TrimSpace(ex) == "" || !strings.HasPrefix(ex, "/") {
			add("spec.exclude", fmt.Errorf("exclude path %q must be a non-empty absolute path (start with '/')", ex))
		}
	}

	for di, d := range f.Spec.Domains {
		dp := fmt.Sprintf("spec.domains[%d]", di)
		// A domain matches one or more hosts; at least one is required. Each entry
		// is exact, a leading-wildcard ("*.example.com"), or "*" (catch-all).
		if len(d.Hosts) == 0 {
			add(dp+".hosts", errors.New("at least one host is required"))
		}
		for hi, h := range d.Hosts {
			if h != "*" && !hostRe.MatchString(h) {
				add(fmt.Sprintf("%s.hosts[%d]", dp, hi), fmt.Errorf("invalid host %q", h))
			}
		}
		errs = append(errs, validateSpec(file, dp+".policy", d.Policy)...)

		routeSigs := make(map[string]int, len(d.Routes))
		for ri, r := range d.Routes {
			rp := fmt.Sprintf("%s.routes[%d]", dp, ri)
			errs = append(errs, validateMatch(file, rp+".match", r.Match)...)
			errs = append(errs, validateSpec(file, rp+".policy", r.Policy)...)

			sig := routeSignature(r.Match)
			if prev, ok := routeSigs[sig]; ok {
				add(rp+".match", fmt.Errorf("duplicate route match (identical to routes[%d])", prev))
			} else {
				routeSigs[sig] = ri
			}
		}
	}
	return errs
}

// routeSignature builds a canonical string for a Match so identical predicates
// can be detected as duplicate routes within a domain.
func routeSignature(m Match) string {
	methods := append([]string(nil), m.Methods...)
	cts := append([]string(nil), m.ContentType...)
	for i := range methods {
		methods[i] = strings.ToUpper(methods[i])
	}
	sort.Strings(methods)
	sort.Strings(cts)

	hdrs := make([]string, 0, len(m.Headers))
	for _, h := range m.Headers {
		present := ""
		if h.Present != nil {
			present = strconv.FormatBool(*h.Present)
		}
		hdrs = append(hdrs, strings.ToLower(h.Name)+"|"+h.Exact+"|"+h.Regex+"|"+h.Contains+"|"+present)
	}
	sort.Strings(hdrs)

	return strings.Join([]string{
		"e:" + m.PathExact,
		"p:" + m.PathPrefix,
		"r:" + m.PathRegex,
		"m:" + strings.Join(methods, ","),
		"c:" + strings.Join(cts, ","),
		"h:" + strings.Join(hdrs, ";"),
	}, "\x1f")
}

// validateSpec checks a sparse PolicySpec's set fields.
func validateSpec(file, prefix string, s PolicySpec) []error {
	var errs []error
	add := func(field string, err error) {
		errs = append(errs, newFileError(file, prefix+"."+field, err))
	}

	if s.Mode != nil && !s.Mode.Valid() {
		add("mode", fmt.Errorf("invalid mode %q", *s.Mode))
	}
	if s.FailMode != nil && !s.FailMode.Valid() {
		add("fail_mode", fmt.Errorf("invalid fail_mode %q", *s.FailMode))
	}
	if s.SamplingRate != nil && (*s.SamplingRate < 0 || *s.SamplingRate > 1) {
		add("sampling_rate", fmt.Errorf("must be within [0,1], got %v", *s.SamplingRate))
	}
	checkNonNeg := func(field string, v *int64) {
		if v != nil && *v < 0 {
			add(field, fmt.Errorf("must be >= 0, got %d", *v))
		}
	}
	checkNonNeg("max_request_body_bytes", s.MaxRequestBodyBytes)
	checkNonNeg("max_response_body_bytes", s.MaxResponseBodyBytes)
	checkNonNeg("max_header_bytes", s.MaxHeaderBytes)
	// A sane ceiling on body caps so one policy can't ask Envoy to buffer absurd
	// amounts of memory (the per-stream cost is multiplied by concurrency).
	checkCeiling := func(field string, v *int64) {
		if v != nil && *v > maxSaneBodyBytes {
			add(field, fmt.Errorf("must be <= %d (sane ceiling), got %d", maxSaneBodyBytes, *v))
		}
	}
	checkCeiling("max_request_body_bytes", s.MaxRequestBodyBytes)
	checkCeiling("max_response_body_bytes", s.MaxResponseBodyBytes)
	// An explicit timeout must be strictly positive: 0 would silently disable the
	// per-request deadline, letting a pathological engine hang the stream.
	if s.Timeout != nil && s.Timeout.AsDuration() <= 0 {
		add("timeout", fmt.Errorf("must be > 0, got %s", s.Timeout.AsDuration()))
	}
	// The anomaly threshold is checked as `score >= threshold` only when > 0; a
	// negative value would silently disable anomaly blocking the operator asked
	// for, so reject it (0 = explicitly disabled).
	if s.AnomalyThreshold != nil && *s.AnomalyThreshold < 0 {
		add("anomaly_threshold", fmt.Errorf("must be >= 0 (0 disables), got %d", *s.AnomalyThreshold))
	}
	if s.LogLevel != nil {
		if _, ok := knownLogLevels[strings.ToLower(*s.LogLevel)]; !ok {
			add("log_level", fmt.Errorf("invalid log level %q", *s.LogLevel))
		}
	}

	// Invalid action combinations: inspecting a body while mode is off, or while
	// the corresponding size budget is explicitly zero, can never do anything
	// useful and almost always signals a misconfiguration.
	if s.Mode != nil && *s.Mode == ModeOff {
		if s.InspectRequestBody != nil && *s.InspectRequestBody {
			add("inspect_request_body", errors.New("cannot inspect request body when mode is off"))
		}
		if s.InspectResponseBody != nil && *s.InspectResponseBody {
			add("inspect_response_body", errors.New("cannot inspect response body when mode is off"))
		}
	}
	if s.InspectRequestBody != nil && *s.InspectRequestBody &&
		s.MaxRequestBodyBytes != nil && *s.MaxRequestBodyBytes == 0 {
		add("inspect_request_body", errors.New("request body inspection enabled but max_request_body_bytes is 0"))
	}
	if s.InspectResponseBody != nil && *s.InspectResponseBody &&
		s.MaxResponseBodyBytes != nil && *s.MaxResponseBodyBytes == 0 {
		add("inspect_response_body", errors.New("response body inspection enabled but max_response_body_bytes is 0"))
	}

	if s.Pipeline != nil {
		validateOrder := func(field string, names []string) {
			seen := map[string]struct{}{}
			for i, n := range names {
				if _, ok := knownInspectors[n]; !ok {
					add(fmt.Sprintf("%s[%d]", field, i), fmt.Errorf("unknown stage %q (valid: fast_pre_checks, body_checks, waf_engine)", n))
				}
				if _, dup := seen[n]; dup {
					add(fmt.Sprintf("%s[%d]", field, i), fmt.Errorf("duplicate stage %q", n))
				}
				seen[n] = struct{}{}
			}
		}
		validateOrder("pipeline.request", s.Pipeline.Request)
		validateOrder("pipeline.response", s.Pipeline.Response)
	}

	if s.Checks.Body != nil && s.Checks.Body.DLP != nil {
		validateDLP(s.Checks.Body.DLP, add)
	}

	if s.Engines != nil {
		if j := s.Engines.JWT; j != nil {
			if len(j.Algorithms) == 0 {
				add("engines.jwt.algorithms", errors.New("at least one algorithm is required"))
			}
			if j.HMACSecret == "" && j.PublicKeyFile == "" {
				add("engines.jwt", errors.New("hmac_secret or public_key_file is required"))
			}
			if j.HMACSecret != "" && j.PublicKeyFile != "" {
				add("engines.jwt", errors.New("set either hmac_secret (HS*) or public_key_file (RS*/ES*), not both — mixing symmetric and asymmetric keys enables algorithm-confusion attacks"))
			}
			for i, alg := range j.Algorithms {
				if _, ok := knownJWTAlgs[alg]; !ok {
					add(fmt.Sprintf("engines.jwt.algorithms[%d]", i), fmt.Errorf("unsupported or unsafe algorithm %q (alg=none is rejected)", alg))
					continue
				}
				// The key source must match the algorithm family, or every valid
				// token is silently rejected (a symmetric secret can't verify an
				// RS*/ES* token and vice-versa).
				isHS := strings.HasPrefix(alg, "HS")
				if isHS && j.PublicKeyFile != "" && j.HMACSecret == "" {
					add(fmt.Sprintf("engines.jwt.algorithms[%d]", i), fmt.Errorf("algorithm %q needs hmac_secret, but only public_key_file is set", alg))
				}
				if !isHS && j.HMACSecret != "" && j.PublicKeyFile == "" {
					add(fmt.Sprintf("engines.jwt.algorithms[%d]", i), fmt.Errorf("algorithm %q needs public_key_file, but only hmac_secret is set", alg))
				}
			}
			if l := j.Leeway.AsDuration(); l < 0 {
				add("engines.jwt.leeway", fmt.Errorf("must be >= 0, got %s", l))
			} else if l > 5*time.Minute {
				add("engines.jwt.leeway", fmt.Errorf("must be <= 5m (sane clock-skew tolerance — a large leeway accepts long-expired tokens), got %s", l))
			}
		}
		if c := s.Engines.Coraza; c != nil {
			if c.Directives == "" && c.DirectivesFile == "" && !c.IncludeOWASP {
				add("engines.coraza", errors.New("directives, directives_file, or include_owasp is required"))
			}
		}
		if rl := s.Engines.RateLimit; rl != nil {
			if rl.RequestsPerSecond <= 0 {
				add("engines.rate_limit.requests_per_second", errors.New("must be > 0"))
			}
			if rl.Burst < 0 {
				add("engines.rate_limit.burst", errors.New("must be >= 0 (0 = derive from rate)"))
			}
			switch rl.Key {
			case "", "ip", "host", "header":
			default:
				add("engines.rate_limit.key", fmt.Errorf("invalid key %q (want ip|host|header)", rl.Key))
			}
			if rl.Key == "header" && rl.Header == "" {
				add("engines.rate_limit.header", errors.New("header is required when key is \"header\""))
			}
		}
		if ir := s.Engines.IPReputation; ir != nil {
			validateIPReputation(ir, add)
		}
		if b := s.Engines.Bot; b != nil {
			validateBot(b, add)
		}
		if ak := s.Engines.APIKey; ak != nil {
			validateAPIKey(ak, add)
		}
		if h := s.Engines.HMACSign; h != nil {
			validateHMACSign(h, add)
		}
		if hs := s.Engines.HTTPSignature; hs != nil {
			validateHTTPSignature(hs, add)
		}
		if j := s.Engines.JWKS; j != nil {
			validateJWKS(j, add)
		}
		if x := s.Engines.XFCC; x != nil {
			if !x.RequirePresent && len(x.URIs)+len(x.DNSNames)+len(x.Subjects)+len(x.Hashes) == 0 {
				add("engines.xfcc", errors.New("require_present or at least one allow-list dimension is required"))
			}
		}
		if g := s.Engines.GraphQL; g != nil {
			if g.MaxDepth == 0 && g.MaxAliases == 0 && g.MaxRootFields == 0 && g.MaxTotalFields == 0 &&
				g.MaxOperations == 0 && !g.BlockIntrospection {
				add("engines.graphql", errors.New("at least one limit (max_depth/max_aliases/max_root_fields/max_total_fields/max_operations) or block_introspection is required"))
			}
		}
		if o := s.Engines.OpenAPI; o != nil {
			if o.SpecFile == "" {
				add("engines.openapi.spec_file", errors.New("required"))
			}
		}
	}
	return errs
}

// knownDLPKinds is the set of sensitive-data kinds the detector can produce.
var knownDLPKinds = map[string]struct{}{
	"credit_card": {}, "ssn": {}, "email": {}, "jwt": {}, "aws_access_key": {},
	"private_key": {}, "google_api_key": {}, "slack_token": {}, "github_token": {},
}

// validateDLP checks the DLP config: a known direction and known kinds.
func validateDLP(d *DLPSpec, add func(field string, err error)) {
	switch d.Direction {
	case "", "response", "request", "both":
	default:
		add("checks.body.dlp.direction", fmt.Errorf("invalid direction %q (want response|request|both)", d.Direction))
	}
	if len(d.Block) == 0 && len(d.Redact) == 0 {
		add("checks.body.dlp", errors.New("at least one block or redact kind is required"))
	}
	for _, k := range append(append([]string{}, d.Block...), d.Redact...) {
		if _, ok := knownDLPKinds[k]; !ok {
			add("checks.body.dlp", fmt.Errorf("unknown DLP kind %q", k))
		}
	}
}

// validateJWKS checks the JWKS engine config: exactly one source, asymmetric
// algorithms only (a JWKS holds asymmetric keys — an HS* alg would invite an
// RS256→HS256 confusion attack), an HTTPS (or loopback) URL, and sane durations.
func validateJWKS(j *JWKSSpec, add func(field string, err error)) {
	if (j.File == "") == (j.URL == "") {
		add("engines.jwks", errors.New("exactly one of file or url is required"))
	}
	if len(j.Algorithms) == 0 {
		add("engines.jwks.algorithms", errors.New("at least one algorithm is required"))
	}
	for i, alg := range j.Algorithms {
		if _, ok := knownJWTAlgs[alg]; !ok {
			add(fmt.Sprintf("engines.jwks.algorithms[%d]", i), fmt.Errorf("unsupported or unsafe algorithm %q", alg))
		} else if strings.HasPrefix(alg, "HS") {
			add(fmt.Sprintf("engines.jwks.algorithms[%d]", i), fmt.Errorf("symmetric algorithm %q is not allowed with a JWKS (asymmetric keys only — RS*/ES*/PS*/EdDSA)", alg))
		}
	}
	if j.URL != "" {
		if u, err := url.Parse(j.URL); err != nil {
			add("engines.jwks.url", fmt.Errorf("invalid URL: %w", err))
		} else if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
			add("engines.jwks.url", fmt.Errorf("must use https (an http JWKS URL is MITM-able → an attacker can swap the keys); got scheme %q", u.Scheme))
		}
	}
	if l := j.Leeway.AsDuration(); l < 0 {
		add("engines.jwks.leeway", errors.New("must be >= 0"))
	} else if l > 5*time.Minute {
		add("engines.jwks.leeway", fmt.Errorf("must be <= 5m (a large leeway accepts long-expired tokens), got %s", l))
	}
	if j.RefreshInterval.AsDuration() < 0 {
		add("engines.jwks.refresh_interval", errors.New("must be >= 0"))
	}
	if j.HTTPTimeout.AsDuration() < 0 {
		add("engines.jwks.http_timeout", errors.New("must be >= 0"))
	}
}

// isLoopbackHost reports whether host is localhost or a loopback IP (so a local
// IdP over plain http is allowed; remote http is not).
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.IsLoopback()
	}
	return false
}

// validateAPIKey checks the API-key engine config.
func validateAPIKey(ak *APIKeySpec, add func(field string, err error)) {
	switch ak.Source {
	case "", "header", "query":
	default:
		add("engines.api_key.source", fmt.Errorf("invalid source %q (want header|query)", ak.Source))
	}
	if len(ak.Keys) == 0 {
		add("engines.api_key.keys", errors.New("at least one key is required"))
	}
	for i, k := range ak.Keys {
		p := fmt.Sprintf("engines.api_key.keys[%d]", i)
		if k.SHA256 == "" && k.Key == "" {
			add(p, errors.New("each key needs sha256 or key"))
		}
		if k.SHA256 != "" {
			if _, err := hex.DecodeString(k.SHA256); err != nil || len(k.SHA256) != 64 {
				add(p+".sha256", errors.New("must be a 64-char hex sha256 digest"))
			}
		}
	}
	for i, b := range ak.Bindings {
		if b.PathPrefix == "" || b.Scope == "" {
			add(fmt.Sprintf("engines.api_key.require_scope_for_path[%d]", i), errors.New("path_prefix and scope are required"))
		}
	}
}

// hmacMinSecretLen is the minimum shared-secret length (bytes). HMAC security
// rests on secret entropy; a short/guessable secret lets an attacker forge
// signatures, so a too-short secret is rejected at config load.
const hmacMinSecretLen = 16

// hmacMaxWindow caps the timestamp-acceptance window. The window also defaults
// the nonce-replay TTL, so an unbounded window would retain nonces indefinitely
// (unbounded memory) and widen the replay window; cap it at a sane maximum.
const hmacMaxWindow = time.Hour

// validateHMACSign checks the HMAC-signing engine config.
func validateHMACSign(h *HMACSignSpec, add func(field string, err error)) {
	if h.Secret == "" && len(h.Secrets) == 0 {
		add("engines.hmac_sign", errors.New("secret or secrets is required"))
	}
	if h.Secret != "" && len(h.Secrets) > 0 {
		add("engines.hmac_sign", errors.New("set either secret or secrets, not both"))
	}
	if h.Secret != "" && len(h.Secret) < hmacMinSecretLen {
		add("engines.hmac_sign.secret", fmt.Errorf("must be at least %d bytes (weak secret)", hmacMinSecretLen))
	}
	for id, s := range h.Secrets {
		if len(s) < hmacMinSecretLen {
			add("engines.hmac_sign.secrets", fmt.Errorf("secret for key id %q must be at least %d bytes (weak secret)", id, hmacMinSecretLen))
		}
	}
	switch h.Algorithm {
	case "", "sha256", "sha512":
	default:
		add("engines.hmac_sign.algorithm", fmt.Errorf("invalid algorithm %q (want sha256|sha512)", h.Algorithm))
	}
	if w := h.Window.AsDuration(); w < 0 {
		add("engines.hmac_sign.window", errors.New("must be >= 0"))
	} else if w > 0 && w < time.Second {
		// The signed timestamp is epoch SECONDS, so a sub-second window truncates
		// to an exact-second match and rejects nearly all traffic — a footgun.
		add("engines.hmac_sign.window", errors.New("must be >= 1s (the timestamp is second-granular) or 0 to use the default"))
	} else if w > hmacMaxWindow {
		add("engines.hmac_sign.window", fmt.Errorf("must be <= %s", hmacMaxWindow))
	}
	if ttl := h.NonceTTL.AsDuration(); ttl < 0 {
		add("engines.hmac_sign.nonce_ttl", errors.New("must be >= 0"))
	} else if ttl > hmacMaxWindow {
		add("engines.hmac_sign.nonce_ttl", fmt.Errorf("must be <= %s", hmacMaxWindow))
	}
}

// httpsigMinSecretLen is the minimum shared-secret length (bytes) for the RFC
// 9421 hmac-sha256 engine — the yaronf/httpsign library requires >= 64 bytes;
// rejecting it here attributes the error to the config field instead of failing
// opaquely at engine build.
const httpsigMinSecretLen = 64

// httpsigMaxAge caps the signature acceptance window. A large window widens the
// replay window for any client that doesn't send a nonce, so bound it.
const httpsigMaxAge = time.Hour

// validateHTTPSignature checks the RFC 9421 HTTP Message Signatures engine config.
func validateHTTPSignature(hs *HTTPSignatureSpec, add func(field string, err error)) {
	switch {
	case hs.Secret == "":
		add("engines.http_signature.secret", errors.New("required (hmac-sha256 shared secret)"))
	case len(hs.Secret) < httpsigMinSecretLen:
		add("engines.http_signature.secret", fmt.Errorf("must be at least %d bytes (RFC 9421 hmac-sha256 requirement)", httpsigMinSecretLen))
	}
	if age := hs.MaxAge.AsDuration(); age < 0 {
		add("engines.http_signature.max_age", errors.New("must be >= 0"))
	} else if age > httpsigMaxAge {
		add("engines.http_signature.max_age", fmt.Errorf("must be <= %s", httpsigMaxAge))
	}
}

// validateBot checks the bot-detection engine config: verified-bot feeds need a
// name/file/format/ua_match (a valid regex), and at least one detection layer
// must be configured.
func validateBot(b *BotSpec, add func(field string, err error)) {
	hasLayer := (b.UserAgent != nil && (len(b.UserAgent.DenySubstrings) > 0 || b.UserAgent.BlockEmpty || b.UserAgent.ScoreKnownBot > 0)) ||
		len(b.VerifiedBots) > 0 ||
		(b.TLSFingerprint != nil && (len(b.TLSFingerprint.DenyJA4) > 0 || len(b.TLSFingerprint.DenyJA3) > 0 || len(b.TLSFingerprint.ToolJA4) > 0 || len(b.TLSFingerprint.ScoreJA4) > 0)) ||
		(b.Heuristics != nil && b.Heuristics.ScorePerAnomaly > 0)
	if !hasLayer {
		add("engines.bot", errors.New("at least one detection layer (user_agent, verified_bots, tls_fingerprint, or heuristics) is required"))
	}
	if ua := b.UserAgent; ua != nil {
		for i, s := range ua.DenySubstrings {
			if strings.TrimSpace(s) == "" {
				add(fmt.Sprintf("engines.bot.user_agent.deny_substrings[%d]", i),
					errors.New("must not be empty (an empty substring matches every User-Agent and blocks all traffic)"))
			}
		}
		if ua.ScoreKnownBot < 0 {
			add("engines.bot.user_agent.score_known_bot", errors.New("must be >= 0"))
		}
	}
	if t := b.TLSFingerprint; t != nil {
		for field, list := range map[string][]string{"deny_ja4": t.DenyJA4, "deny_ja3": t.DenyJA3, "tool_ja4": t.ToolJA4} {
			for i, h := range list {
				if strings.TrimSpace(h) == "" {
					add(fmt.Sprintf("engines.bot.tls_fingerprint.%s[%d]", field, i), errors.New("must not be empty"))
				}
			}
		}
		for h, s := range t.ScoreJA4 {
			if s < 0 {
				add("engines.bot.tls_fingerprint.score_ja4", fmt.Errorf("score for %q must be >= 0", h))
			}
		}
	}
	if h := b.Heuristics; h != nil && h.ScorePerAnomaly < 0 {
		add("engines.bot.heuristics.score_per_anomaly", errors.New("must be >= 0"))
	}
	// A score layer with no threshold (and not emitting to the anomaly scorer) is
	// a silent no-op — the accumulated score can never block.
	hasScoreLayer := (b.UserAgent != nil && b.UserAgent.ScoreKnownBot > 0) ||
		(b.TLSFingerprint != nil && len(b.TLSFingerprint.ScoreJA4) > 0) ||
		(b.Heuristics != nil && b.Heuristics.ScorePerAnomaly > 0)
	if hasScoreLayer && b.ScoreThreshold <= 0 && !b.EmitScore {
		add("engines.bot.score_threshold", errors.New("must be > 0 when score layers are configured (or set emit_score to feed the policy anomaly scorer)"))
	}
	// The reverse: emit_score with nothing that produces a score is a silent no-op
	// (the engine feeds 0 to the anomaly scorer and never contributes).
	if b.EmitScore && !hasScoreLayer {
		add("engines.bot.emit_score", errors.New("requires at least one score layer (user_agent.score_known_bot, tls_fingerprint.score_ja4, or heuristics.score_per_anomaly)"))
	}
	for i, vb := range b.VerifiedBots {
		p := fmt.Sprintf("engines.bot.verified_bots[%d]", i)
		if vb.Name == "" {
			add(p+".name", errors.New("required"))
		}
		if vb.File == "" {
			add(p+".file", errors.New("required"))
		}
		switch vb.Format {
		case "cidr_lines", "firehol_netset", "spamhaus_json":
		default:
			add(p+".format", fmt.Errorf("invalid format %q (want cidr_lines|firehol_netset|spamhaus_json)", vb.Format))
		}
		if vb.UAMatch == "" {
			add(p+".ua_match", errors.New("required"))
		} else if _, err := regexp.Compile(vb.UAMatch); err != nil {
			add(p+".ua_match", fmt.Errorf("invalid regex: %w", err))
		}
	}
}

// validateIPReputation checks the IP-reputation engine config: CIDRs must parse,
// and each feed needs a name, file, and a known format/severity.
func validateIPReputation(ir *IPReputationSpec, add func(field string, err error)) {
	for i, c := range ir.AllowCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			add(fmt.Sprintf("engines.ip_reputation.allow_cidrs[%d]", i), fmt.Errorf("invalid CIDR %q", c))
		}
	}
	for i, c := range ir.DenyCIDRs {
		if _, err := netip.ParsePrefix(c); err != nil {
			add(fmt.Sprintf("engines.ip_reputation.deny_cidrs[%d]", i), fmt.Errorf("invalid CIDR %q", c))
		}
	}
	if len(ir.AllowCIDRs) == 0 && len(ir.DenyCIDRs) == 0 && len(ir.Feeds) == 0 && ir.GeoIP == nil {
		add("engines.ip_reputation", errors.New("at least one of allow_cidrs, deny_cidrs, feeds, or geoip is required"))
	}
	for i, f := range ir.Feeds {
		p := fmt.Sprintf("engines.ip_reputation.feeds[%d]", i)
		if f.Name == "" {
			add(p+".name", errors.New("required"))
		}
		if f.File == "" {
			add(p+".file", errors.New("required"))
		}
		switch f.Format {
		case "cidr_lines", "firehol_netset", "spamhaus_json":
		default:
			add(p+".format", fmt.Errorf("invalid format %q (want cidr_lines|firehol_netset|spamhaus_json)", f.Format))
		}
		switch f.Severity {
		case "", "low", "medium", "high", "critical":
		default:
			add(p+".severity", fmt.Errorf("invalid severity %q (want low|medium|high|critical)", f.Severity))
		}
	}
	if g := ir.GeoIP; g != nil {
		if g.DatabaseFile == "" && g.ASNDatabaseFile == "" {
			add("engines.ip_reputation.geoip", errors.New("database_file or asn_database_file is required"))
		}
		if len(g.BlockCountries) == 0 && len(g.AllowCountries) == 0 && len(g.BlockASNs) == 0 && g.OnMissing != "block" {
			add("engines.ip_reputation.geoip", errors.New("at least one of block_countries, allow_countries, block_asns, or on_missing=block is required"))
		}
		for j, cc := range append(append([]string{}, g.BlockCountries...), g.AllowCountries...) {
			if len(cc) != 2 {
				add(fmt.Sprintf("engines.ip_reputation.geoip.countries[%d]", j), fmt.Errorf("invalid ISO country code %q (want 2 letters)", cc))
			}
		}
		// A country in both block and allow is contradictory (block wins, so the
		// allow entry is a silent no-op the operator likely didn't intend).
		blocked := make(map[string]struct{}, len(g.BlockCountries))
		for _, cc := range g.BlockCountries {
			blocked[strings.ToUpper(cc)] = struct{}{}
		}
		for _, cc := range g.AllowCountries {
			if _, dup := blocked[strings.ToUpper(cc)]; dup {
				add("engines.ip_reputation.geoip", fmt.Errorf("country %q is in both block_countries and allow_countries", cc))
			}
		}
		switch g.OnMissing {
		case "", "continue", "block":
		default:
			add("engines.ip_reputation.geoip.on_missing", fmt.Errorf("invalid on_missing %q (want continue|block)", g.OnMissing))
		}
	}
}

// validateMatch checks a route match predicate.
func validateMatch(file, prefix string, m Match) []error {
	var errs []error
	add := func(field string, err error) {
		errs = append(errs, newFileError(file, prefix+"."+field, err))
	}

	pathKinds := 0
	for _, set := range []bool{m.PathExact != "", m.PathPrefix != "", m.PathRegex != ""} {
		if set {
			pathKinds++
		}
	}
	if pathKinds > 1 {
		add("", errors.New("set at most one of path_exact, path_prefix, path_regex"))
	}
	if m.PathRegex != "" {
		if _, err := regexp.Compile(m.PathRegex); err != nil {
			add("path_regex", fmt.Errorf("invalid regex: %w", err))
		}
	}
	for i, meth := range m.Methods {
		if _, ok := knownMethods[strings.ToUpper(meth)]; !ok {
			add(fmt.Sprintf("methods[%d]", i), fmt.Errorf("unknown HTTP method %q", meth))
		}
	}
	for i, h := range m.Headers {
		hp := fmt.Sprintf("headers[%d]", i)
		if strings.TrimSpace(h.Name) == "" {
			add(hp+".name", errors.New("header name is required"))
		}
		set := 0
		if h.Exact != "" {
			set++
		}
		if h.Contains != "" {
			set++
		}
		if h.Regex != "" {
			set++
		}
		if h.Present != nil {
			set++
		}
		if set > 1 {
			add(hp, errors.New("set at most one of exact, contains, regex, present"))
		}
		if h.Regex != "" {
			if _, err := regexp.Compile(h.Regex); err != nil {
				add(hp+".regex", fmt.Errorf("invalid regex: %w", err))
			}
		}
	}
	return errs
}

// validateMerged checks cross-file invariants on the merged config, chiefly that
// no host is claimed by two domains (which would make resolution ambiguous).
func validateMerged(m *MergedConfig) []error {
	var errs []error
	seen := make(map[string]string, len(m.Domains)) // normalized host -> source
	for i, d := range m.Domains {
		for _, h := range d.Hosts {
			k := strings.ToLower(strings.TrimSpace(h)) // case-insensitive dedup key
			if prev, ok := seen[k]; ok {
				errs = append(errs, newFileError(d.Source,
					fmt.Sprintf("domains[%d]", i),
					fmt.Errorf("duplicate host %q (already defined in %s)", h, prev)))
				continue
			}
			seen[k] = d.Source
		}
	}
	return errs
}
