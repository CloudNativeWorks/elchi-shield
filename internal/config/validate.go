package config

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
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

	for di, d := range f.Spec.Domains {
		dp := fmt.Sprintf("spec.domains[%d]", di)
		if strings.TrimSpace(d.Host) == "" {
			add(dp+".host", errors.New("host is required"))
		} else if !hostRe.MatchString(d.Host) {
			add(dp+".host", fmt.Errorf("invalid host %q", d.Host))
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
				}
			}
			if j.Leeway.AsDuration() < 0 {
				add("engines.jwt.leeway", fmt.Errorf("must be >= 0, got %s", j.Leeway.AsDuration()))
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
	}
	return errs
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

// validateMerged checks cross-file invariants on the merged config, chiefly
// that no two domains collide on (host, listener_id).
func validateMerged(m *MergedConfig) []error {
	var errs []error
	type key struct{ host, listener string }
	seen := make(map[key]string, len(m.Domains))
	for i, d := range m.Domains {
		k := key{host: d.Host, listener: d.ListenerID}
		if prev, ok := seen[k]; ok {
			errs = append(errs, newFileError(d.Source,
				fmt.Sprintf("domains[%d]", i),
				fmt.Errorf("duplicate domain host=%q listener_id=%q (already defined in %s)", d.Host, d.ListenerID, prev)))
			continue
		}
		seen[k] = d.Source
	}
	return errs
}
