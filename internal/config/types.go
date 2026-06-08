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
}

// Domain scopes a set of routes to a host and (optionally) a listener.
type Domain struct {
	// Host is the request authority/Host this domain matches. Supports a single
	// leading-wildcard form ("*.example.com") and exact hosts.
	Host string `yaml:"host" json:"host"`
	// ListenerID optionally narrows the domain to a specific Envoy listener.
	ListenerID string `yaml:"listener_id" json:"listener_id"`
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
	JWT          *JWTSpec          `yaml:"jwt" json:"jwt"`
	Coraza       *CorazaSpec       `yaml:"coraza" json:"coraza"`
	RateLimit    *RateLimitSpec    `yaml:"rate_limit" json:"rate_limit"`
	IPReputation *IPReputationSpec `yaml:"ip_reputation" json:"ip_reputation"`
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
// with the `coraza` build tag).
type CorazaSpec struct {
	Directives     string   `yaml:"directives" json:"directives"`
	DirectivesFile string   `yaml:"directives_file" json:"directives_file"`
	IncludeOWASP   bool     `yaml:"include_owasp" json:"include_owasp"`
	ExcludeRuleIDs []string `yaml:"exclude_rule_ids" json:"exclude_rule_ids"`
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
}
