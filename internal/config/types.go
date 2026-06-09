package config

import (
	"encoding/json"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Supported config envelope identifiers. The on-disk format is Kubernetes-style
// (apiVersion/kind/metadata/spec) so it is familiar to operators and versionable
// independently of the engine.
const (
	APIVersionV1       = "sentinel.elchi.io/v1"
	KindSecurityPolicy = "SecurityPolicy"
)

// Mode is the enforcement posture applied to a matched request.
type Mode string

const (
	// ModeBlock enforces decisions: a blocked request gets an immediate 403.
	ModeBlock Mode = "block"
	// ModeDetect evaluates and logs/metrics but always allows (monitor mode).
	ModeDetect Mode = "detect"
	// ModeShadow evaluates as if blocking and logs what would be blocked,
	// but allows the request through.
	ModeShadow Mode = "shadow"
	// ModeOff skips inspection entirely (continue).
	ModeOff Mode = "off"
)

// Valid reports whether m is a recognized mode.
func (m Mode) Valid() bool {
	switch m {
	case ModeBlock, ModeDetect, ModeShadow, ModeOff:
		return true
	default:
		return false
	}
}

// FailMode selects behavior when the engine errors or times out.
type FailMode string

const (
	// FailOpen allows the request through on engine error/timeout.
	FailOpen FailMode = "fail_open"
	// FailClose blocks the request on engine error/timeout.
	FailClose FailMode = "fail_close"
)

// Valid reports whether f is a recognized fail mode.
func (f FailMode) Valid() bool {
	return f == FailOpen || f == FailClose
}

// Duration is a time.Duration that (un)marshals from Go duration strings such
// as "50ms" or "2s" in both YAML and JSON.
type Duration time.Duration

// AsDuration returns the underlying time.Duration.
func (d Duration) AsDuration() time.Duration { return time.Duration(d) }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"50ms\": %w", err)
	}
	return d.parse(s)
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"50ms\": %w", err)
	}
	return d.parse(s)
}

func (d *Duration) parse(s string) error {
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON implements json.Marshaler so round-tripping stays human-readable.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// File is the on-disk representation of a single config file using a
// Kubernetes-style envelope.
type File struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`
}

// Metadata identifies a config document.
type Metadata struct {
	Name   string            `yaml:"name" json:"name"`
	Labels map[string]string `yaml:"labels" json:"labels"`
}

// Spec is the body of a config document: file-level defaults plus domains.
type Spec struct {
	Defaults PolicySpec `yaml:"defaults" json:"defaults"`
	Domains  []Domain   `yaml:"domains" json:"domains"`
	// Exclude lists request paths that bypass ALL inspection (a cheap exact-match,
	// query-stripped, checked before policy resolution). Use it for health checks,
	// metrics scrapes, or static assets that never need a WAF decision.
	Exclude []string `yaml:"exclude" json:"exclude"`
}

// Domain scopes a set of routes to one or more hosts.
type Domain struct {
	// Hosts are the request authorities/Hosts this domain matches (at least one
	// required). Each entry is an exact host, a single leading-wildcard
	// ("*.example.com"), or "*" (catch-all, matches any host). The domain matches
	// if ANY entry matches; precedence uses the most-specific matching entry.
	Hosts []string `yaml:"hosts" json:"hosts"`
	// Policy is an optional domain-level override applied beneath file Defaults
	// and above each route's policy.
	Policy PolicySpec `yaml:"policy" json:"policy"`
	// Routes are evaluated by matching precedence (exact > regex > prefix).
	Routes []Route `yaml:"routes" json:"routes"`
}

// Route binds a match predicate to a policy override.
type Route struct {
	Match  Match      `yaml:"match" json:"match"`
	Policy PolicySpec `yaml:"policy" json:"policy"`
}

// Match is the predicate selecting requests for a route. An empty Match matches
// every request to the domain (acts as the domain default route).
type Match struct {
	PathExact   string        `yaml:"path_exact" json:"path_exact"`
	PathPrefix  string        `yaml:"path_prefix" json:"path_prefix"`
	PathRegex   string        `yaml:"path_regex" json:"path_regex"`
	Methods     []string      `yaml:"methods" json:"methods"`
	ContentType []string      `yaml:"content_type" json:"content_type"`
	Headers     []HeaderMatch `yaml:"headers" json:"headers"`
}

// HeaderMatch matches a single request header by exact value, substring,
// regex, or mere presence/absence. At most one of Exact/Contains/Regex/Present
// may be set.
type HeaderMatch struct {
	Name     string `yaml:"name" json:"name"`
	Exact    string `yaml:"exact" json:"exact"`
	Contains string `yaml:"contains" json:"contains"`
	Regex    string `yaml:"regex" json:"regex"`
	Present  *bool  `yaml:"present" json:"present"`
}

// PolicySpec is a sparse policy: only set fields override the inherited value.
// Pointers distinguish "unset" from a meaningful zero (e.g. 0 body bytes means
// "do not inspect", not "no limit"). Resolution order, most to least specific:
// route → domain → file defaults → built-in defaults (see DefaultPolicy).
type PolicySpec struct {
	Mode                 *Mode         `yaml:"mode" json:"mode"`
	FailMode             *FailMode     `yaml:"fail_mode" json:"fail_mode"`
	InspectRequestBody   *bool         `yaml:"inspect_request_body" json:"inspect_request_body"`
	InspectResponseBody  *bool         `yaml:"inspect_response_body" json:"inspect_response_body"`
	MaxRequestBodyBytes  *int64        `yaml:"max_request_body_bytes" json:"max_request_body_bytes"`
	MaxResponseBodyBytes *int64        `yaml:"max_response_body_bytes" json:"max_response_body_bytes"`
	MaxHeaderBytes       *int64        `yaml:"max_header_bytes" json:"max_header_bytes"`
	Timeout              *Duration     `yaml:"timeout" json:"timeout"`
	LogLevel             *string       `yaml:"log_level" json:"log_level"`
	SamplingRate         *float64      `yaml:"sampling_rate" json:"sampling_rate"`
	AnomalyThreshold     *int          `yaml:"anomaly_threshold" json:"anomaly_threshold"`
	SkipChecks           []string      `yaml:"skip_checks" json:"skip_checks"`
	Pipeline             *PipelineSpec `yaml:"pipeline" json:"pipeline"`
	Checks               Checks        `yaml:"checks" json:"checks"`
	Engines              *EnginesSpec  `yaml:"engines" json:"engines"`
}

// Reorderable inspector stage names — the per-policy pipeline vocabulary. The
// config package owns these names so the cold path can validate orderings
// without importing the stages package. The structural stages (context init,
// policy resolution, early decision, body gate) are always present at fixed
// positions and are not listed here.
const (
	StageFastPreChecks = "fast_pre_checks"
	StageBodyChecks    = "body_checks"
	StageWAFEngine     = "waf_engine"
)

// knownInspectors is the set of names valid in a PipelineSpec.
var knownInspectors = map[string]struct{}{
	StageFastPreChecks: {},
	StageBodyChecks:    {},
	StageWAFEngine:     {},
}

// DefaultPipelineOrder is the canonical inspector order used when a policy does
// not specify one (cheap header checks → body checks → WAF engines).
var DefaultPipelineOrder = []string{StageFastPreChecks, StageBodyChecks, StageWAFEngine}

// PipelineSpec lets a policy reorder (and, by omission, disable) the inspector
// stages for requests and/or responses. Cross-phase list position is normalized
// by the runtime (header-phase inspectors always run at header time, body-phase
// at body time); ordering WITHIN a phase is honored exactly, so e.g. listing
// waf_engine before body_checks runs the WAF first.
type PipelineSpec struct {
	Request  []string `yaml:"request" json:"request"`
	Response []string `yaml:"response" json:"response"`
}

// EnginesSpec configures the pluggable security engines that run for a policy.
type EnginesSpec struct {
	JWT           *JWTSpec           `yaml:"jwt" json:"jwt"`
	Coraza        *CorazaSpec        `yaml:"coraza" json:"coraza"`
	RateLimit     *RateLimitSpec     `yaml:"rate_limit" json:"rate_limit"`
	IPReputation  *IPReputationSpec  `yaml:"ip_reputation" json:"ip_reputation"`
	Bot           *BotSpec           `yaml:"bot" json:"bot"`
	APIKey        *APIKeySpec        `yaml:"api_key" json:"api_key"`
	HMACSign      *HMACSignSpec      `yaml:"hmac_sign" json:"hmac_sign"`
	HTTPSignature *HTTPSignatureSpec `yaml:"http_signature" json:"http_signature"`
	JWKS          *JWKSSpec          `yaml:"jwks" json:"jwks"`
	XFCC          *XFCCSpec          `yaml:"xfcc" json:"xfcc"`
	GraphQL       *GraphQLSpec       `yaml:"graphql" json:"graphql"`
	OpenAPI       *OpenAPISpec       `yaml:"openapi" json:"openapi"`
}

// OpenAPISpec configures the OpenAPI positive-validation engine (only usable in a
// binary built with the `openapi` build tag).
type OpenAPISpec struct {
	SpecFile             string `yaml:"spec_file" json:"spec_file"`
	ValidateRequestBody  bool   `yaml:"validate_request_body" json:"validate_request_body"`
	RejectUndeclaredPath bool   `yaml:"reject_undeclared_path" json:"reject_undeclared_path"`
}

// GraphQLSpec configures the body-phase GraphQL guard. A zero limit disables that
// check.
type GraphQLSpec struct {
	ContentTypes       []string `yaml:"content_types" json:"content_types"`
	Paths              []string `yaml:"paths" json:"paths"`
	MaxDepth           int      `yaml:"max_depth" json:"max_depth"`
	MaxAliases         int      `yaml:"max_aliases" json:"max_aliases"`
	MaxRootFields      int      `yaml:"max_root_fields" json:"max_root_fields"`
	MaxTotalFields     int      `yaml:"max_total_fields" json:"max_total_fields"`
	MaxOperations      int      `yaml:"max_operations" json:"max_operations"`
	BlockIntrospection bool     `yaml:"block_introspection" json:"block_introspection"`
	MaxFragmentDepth   int      `yaml:"max_fragment_depth" json:"max_fragment_depth"`
	MaxComplexity      int      `yaml:"max_complexity" json:"max_complexity"`
}

// JWKSSpec configures the header-phase JWKS JWT engine. Keys come from a local
// `file` (hot-reloaded, no network) or a remote `url` (fetched once at load,
// then refreshed in the background — never on the request path).
type JWKSSpec struct {
	File            string   `yaml:"file" json:"file"`
	URL             string   `yaml:"url" json:"url"`
	Issuer          string   `yaml:"issuer" json:"issuer"`
	Audience        string   `yaml:"audience" json:"audience"`
	Algorithms      []string `yaml:"algorithms" json:"algorithms"`
	RequiredClaims  []string `yaml:"required_claims" json:"required_claims"`
	HeaderName      string   `yaml:"header_name" json:"header_name"`
	Leeway          Duration `yaml:"leeway" json:"leeway"`
	RefreshInterval Duration `yaml:"refresh_interval" json:"refresh_interval"`
	HTTPTimeout     Duration `yaml:"http_timeout" json:"http_timeout"`
}

// XFCCSpec configures the mTLS client-certificate (XFCC) engine. The allow-list
// dimensions are OR'd; an empty allow-list with require_present is presence-only.
type XFCCSpec struct {
	HeaderName     string   `yaml:"header_name" json:"header_name"`
	RequirePresent bool     `yaml:"require_present" json:"require_present"`
	URIs           []string `yaml:"uris" json:"uris"`
	DNSNames       []string `yaml:"dns_names" json:"dns_names"`
	Subjects       []string `yaml:"subjects" json:"subjects"`
	Hashes         []string `yaml:"hashes" json:"hashes"`
}

// HTTPSignatureSpec configures the RFC 9421 (HTTP Message Signatures) engine
// (only usable in a binary built with the `httpsig` build tag). Initial support
// is hmac-sha256.
type HTTPSignatureSpec struct {
	// Secret is the shared HMAC key.
	Secret string `yaml:"secret" json:"secret"`
	// SignatureName is the label expected in Signature-Input (default "sig1").
	SignatureName string `yaml:"signature_name" json:"signature_name"`
	// CoveredComponents are the components the signature must cover (default
	// @method, @authority, @path).
	CoveredComponents []string `yaml:"covered_components" json:"covered_components"`
	// MaxAge rejects a signature whose `created` is older than this.
	MaxAge Duration `yaml:"max_age" json:"max_age"`
}

// APIKeySpec configures the header-phase API-key authentication engine. Keys are
// stored hashed (sha256 hex) at rest; provide `sha256` or a raw `key`.
type APIKeySpec struct {
	// Source is "header" (default) or "query".
	Source string `yaml:"source" json:"source"`
	// Name is the header/query parameter carrying the key (default "X-Api-Key").
	Name     string             `yaml:"name" json:"name"`
	Keys     []APIKeyEntrySpec  `yaml:"keys" json:"keys"`
	Bindings []ScopeBindingSpec `yaml:"require_scope_for_path" json:"require_scope_for_path"`
}

// APIKeyEntrySpec is one configured credential.
type APIKeyEntrySpec struct {
	SHA256  string   `yaml:"sha256" json:"sha256"`
	Key     string   `yaml:"key" json:"key"`
	Subject string   `yaml:"subject" json:"subject"`
	Scopes  []string `yaml:"scopes" json:"scopes"`
}

// ScopeBindingSpec restricts a path prefix to keys carrying a scope.
type ScopeBindingSpec struct {
	PathPrefix string `yaml:"path_prefix" json:"path_prefix"`
	Scope      string `yaml:"scope" json:"scope"`
}

// HMACSignSpec configures the HMAC request-signing engine (native scheme).
type HMACSignSpec struct {
	// Secret is the shared secret; or use Secrets for per-key-id rotation.
	Secret  string            `yaml:"secret" json:"secret"`
	Secrets map[string]string `yaml:"secrets" json:"secrets"`

	SignatureHeader string `yaml:"signature_header" json:"signature_header"`
	TimestampHeader string `yaml:"timestamp_header" json:"timestamp_header"`
	NonceHeader     string `yaml:"nonce_header" json:"nonce_header"`
	KeyIDHeader     string `yaml:"key_id_header" json:"key_id_header"`

	// Algorithm is "sha256" (default) or "sha512".
	Algorithm string   `yaml:"algorithm" json:"algorithm"`
	Window    Duration `yaml:"window" json:"window"`
	NonceTTL  Duration `yaml:"nonce_ttl" json:"nonce_ttl"`

	RequireNonce      bool `yaml:"require_nonce" json:"require_nonce"`
	RequireBodyDigest bool `yaml:"require_body_digest" json:"require_body_digest"`
}

// BotSpec configures the header-phase bot/scanner detection engine: a layered
// scorer over User-Agent, verified-crawler IP checks, JA3/JA4 TLS fingerprints
// (supplied by Envoy as headers), and header-anomaly heuristics.
type BotSpec struct {
	// ScoreThreshold blocks when the accumulated score reaches it (0 disables
	// score-based blocking; hard-block layers still apply).
	ScoreThreshold int `yaml:"score_threshold" json:"score_threshold"`
	// EmitScore contributes the bot score to the policy anomaly aggregator instead
	// of blocking at score_threshold (hard-block layers still block).
	EmitScore      bool               `yaml:"emit_score" json:"emit_score"`
	UserAgent      *BotUASpec         `yaml:"user_agent" json:"user_agent"`
	VerifiedBots   []BotVerifiedSpec  `yaml:"verified_bots" json:"verified_bots"`
	TLSFingerprint *BotTLSSpec        `yaml:"tls_fingerprint" json:"tls_fingerprint"`
	Heuristics     *BotHeuristicsSpec `yaml:"heuristics" json:"heuristics"`
}

// BotUASpec configures the User-Agent layer.
type BotUASpec struct {
	DenySubstrings []string `yaml:"deny_substrings" json:"deny_substrings"`
	BlockEmpty     bool     `yaml:"block_empty" json:"block_empty"`
	ScoreKnownBot  int      `yaml:"score_known_bot" json:"score_known_bot"`
}

// BotVerifiedSpec declares a crawler whose claim is verified against an IP feed.
type BotVerifiedSpec struct {
	Name    string `yaml:"name" json:"name"`
	File    string `yaml:"file" json:"file"`
	Format  string `yaml:"format" json:"format"`
	UAMatch string `yaml:"ua_match" json:"ua_match"`
}

// BotTLSSpec configures the JA3/JA4 fingerprint layer.
type BotTLSSpec struct {
	JA4Header string         `yaml:"ja4_header" json:"ja4_header"`
	JA3Header string         `yaml:"ja3_header" json:"ja3_header"`
	DenyJA4   []string       `yaml:"deny_ja4" json:"deny_ja4"`
	DenyJA3   []string       `yaml:"deny_ja3" json:"deny_ja3"`
	ScoreJA4  map[string]int `yaml:"score_ja4" json:"score_ja4"`
	ToolJA4   []string       `yaml:"tool_ja4" json:"tool_ja4"`
}

// BotHeuristicsSpec configures the header-anomaly layer.
type BotHeuristicsSpec struct {
	RequireAccept         bool `yaml:"require_accept" json:"require_accept"`
	RequireAcceptLanguage bool `yaml:"require_accept_language" json:"require_accept_language"`
	RequireAcceptEncoding bool `yaml:"require_accept_encoding" json:"require_accept_encoding"`
	ScorePerAnomaly       int  `yaml:"score_per_anomaly" json:"score_per_anomaly"`
}

// IPReputationSpec configures the header-phase IP-reputation engine: static CIDR
// allow/deny lists plus disk-loaded threat-intelligence feeds.
type IPReputationSpec struct {
	// AllowCIDRs, when non-empty, makes the policy default-DENY: a source IP not
	// matching any allow prefix is blocked. CIDR notation ("10.0.0.0/8").
	AllowCIDRs []string `yaml:"allow_cidrs" json:"allow_cidrs"`
	// DenyCIDRs are explicitly blocked prefixes.
	DenyCIDRs []string `yaml:"deny_cidrs" json:"deny_cidrs"`
	// Feeds are threat-intelligence feed files (treated as block lists).
	Feeds []FeedSpec `yaml:"feeds" json:"feeds"`
	// GeoIP enables country/ASN-based blocking via MaxMind databases.
	GeoIP *GeoIPSpec `yaml:"geoip" json:"geoip"`
}

// GeoIPSpec configures GeoIP/ASN-based blocking for the IP-reputation engine.
type GeoIPSpec struct {
	// DatabaseFile is the MaxMind GeoLite2/GeoIP2 Country .mmdb path.
	DatabaseFile string `yaml:"database_file" json:"database_file"`
	// ASNDatabaseFile is the MaxMind GeoLite2/GeoIP2 ASN .mmdb path.
	ASNDatabaseFile string `yaml:"asn_database_file" json:"asn_database_file"`
	// BlockCountries are ISO 3166-1 alpha-2 codes to block (e.g. ["KP","RU"]).
	BlockCountries []string `yaml:"block_countries" json:"block_countries"`
	// AllowCountries, when non-empty, makes geo default-DENY: any other country
	// is blocked.
	AllowCountries []string `yaml:"allow_countries" json:"allow_countries"`
	// BlockASNs are autonomous system numbers to block.
	BlockASNs []uint `yaml:"block_asns" json:"block_asns"`
	// OnMissing selects behavior for an IP absent from the database: "continue"
	// (default) or "block".
	OnMissing string `yaml:"on_missing" json:"on_missing"`
}

// FeedSpec describes one threat-intelligence feed file consumed by the
// IP-reputation engine.
type FeedSpec struct {
	// Name identifies the feed in block reasons and metrics.
	Name string `yaml:"name" json:"name"`
	// File is the path to the feed file (written by the management plane into the
	// watched config directory; never fetched over the network).
	File string `yaml:"file" json:"file"`
	// Format selects the parser: "cidr_lines" | "firehol_netset" | "spamhaus_json".
	Format string `yaml:"format" json:"format"`
	// Severity ranks a match: "low" | "medium" | "high" | "critical" (default medium).
	Severity string `yaml:"severity" json:"severity"`
}

// RateLimitSpec configures the per-key token-bucket rate-limit engine.
type RateLimitSpec struct {
	// RequestsPerSecond is the sustained allowed rate per key (> 0).
	RequestsPerSecond float64 `yaml:"requests_per_second" json:"requests_per_second"`
	// Burst is the bucket capacity; defaults to ceil(requests_per_second).
	Burst int `yaml:"burst" json:"burst"`
	// Key selects the limit dimension: "ip" (default), "host", or "header".
	Key string `yaml:"key" json:"key"`
	// Header is read for key=ip (first XFF token; default "X-Forwarded-For") or
	// key=header.
	Header string `yaml:"header" json:"header"`
}

// JWTSpec configures the JWT policy engine.
type JWTSpec struct {
	Issuer         string   `yaml:"issuer" json:"issuer"`
	Audience       string   `yaml:"audience" json:"audience"`
	Algorithms     []string `yaml:"algorithms" json:"algorithms"`
	HMACSecret     string   `yaml:"hmac_secret" json:"hmac_secret"`
	PublicKeyFile  string   `yaml:"public_key_file" json:"public_key_file"`
	RequiredClaims []string `yaml:"required_claims" json:"required_claims"`
	HeaderName     string   `yaml:"header_name" json:"header_name"`
	// Leeway is the clock-skew tolerance applied to exp/nbf/iat (e.g. "30s").
	// 0 means no tolerance (strict).
	Leeway Duration `yaml:"leeway" json:"leeway"`
}

// CorazaSpec configures the Coraza WAF engine (only usable in a binary built
// with the `coraza` build tag). `include_owasp` loads the OWASP Core Rule Set,
// which is embedded in the binary — no rule files need to be shipped.
type CorazaSpec struct {
	Directives     string   `yaml:"directives" json:"directives"`
	DirectivesFile string   `yaml:"directives_file" json:"directives_file"`
	IncludeOWASP   bool     `yaml:"include_owasp" json:"include_owasp"`
	ExcludeRuleIDs []string `yaml:"exclude_rule_ids" json:"exclude_rule_ids"`

	// CRS tuning (only meaningful with include_owasp). A zero value uses the CRS
	// default (paranoia 1, inbound threshold 5, outbound threshold 4). Lower
	// thresholds and higher paranoia block more aggressively (more false positives).
	ParanoiaLevel            int `yaml:"paranoia_level" json:"paranoia_level"`
	DetectionParanoiaLevel   int `yaml:"detection_paranoia_level" json:"detection_paranoia_level"`
	InboundAnomalyThreshold  int `yaml:"inbound_anomaly_threshold" json:"inbound_anomaly_threshold"`
	OutboundAnomalyThreshold int `yaml:"outbound_anomaly_threshold" json:"outbound_anomaly_threshold"`
}

// Checks groups the built-in check configuration consumed by the engine.
type Checks struct {
	Headers *HeaderChecks `yaml:"headers" json:"headers"`
	Body    *BodyChecks   `yaml:"body" json:"body"`
}

// HeaderChecks configures the built-in header inspection.
type HeaderChecks struct {
	// Forbidden header names cause a block when present.
	Forbidden []string `yaml:"forbidden" json:"forbidden"`
	// Required header names cause a block when absent.
	Required []string `yaml:"required" json:"required"`
	// MaxHeaderBytes caps the combined size of a single header's value; 0 = off.
	MaxHeaderValueBytes int64 `yaml:"max_header_value_bytes" json:"max_header_value_bytes"`
	// EnforceValidHost blocks requests with a missing/invalid Host/authority.
	EnforceValidHost bool `yaml:"enforce_valid_host" json:"enforce_valid_host"`
}

// BodyChecks configures the built-in body inspection.
type BodyChecks struct {
	// RequireJSON blocks bodies that are not valid JSON for JSON content types.
	RequireJSON bool `yaml:"require_json" json:"require_json"`
	// DetectSensitiveData enables the sensitive-data detection hook (Phase 3+).
	DetectSensitiveData bool `yaml:"detect_sensitive_data" json:"detect_sensitive_data"`
	// DLP enables data-loss-prevention: block or redact sensitive data in the
	// body (typically the response).
	DLP *DLPSpec `yaml:"dlp" json:"dlp"`
}

// DLPSpec configures data-loss prevention. The detector kinds are: credit_card,
// ssn, email, jwt, aws_access_key, private_key, google_api_key, slack_token,
// github_token. A kind listed in `block` blocks the message; a kind in `redact`
// is masked in place. Anything not listed is ignored.
type DLPSpec struct {
	// Direction selects where DLP runs: "response" (default), "request", or "both".
	Direction string `yaml:"direction" json:"direction"`
	// Block lists kinds that cause a block (e.g. private_key, aws_access_key).
	Block []string `yaml:"block" json:"block"`
	// Redact lists kinds masked in place (e.g. credit_card, ssn, email, jwt).
	Redact []string `yaml:"redact" json:"redact"`
}
