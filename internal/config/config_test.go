package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFiles writes name→content pairs into a fresh temp dir and returns it.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

const validDoc = `
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata:
  name: t
spec:
  defaults:
    mode: block
    timeout: 50ms
  domains:
    - host: api.example.com
      listener_id: l1
      routes:
        - match:
            path_prefix: /v1/
            methods: [GET, POST]
          policy:
            mode: detect
`

func TestParseValidYAML(t *testing.T) {
	f, err := Parse("t.yaml", []byte(validDoc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.APIVersion != APIVersionV1 || f.Kind != KindSecurityPolicy {
		t.Fatalf("envelope mismatch: %+v", f)
	}
	if len(f.Spec.Domains) != 1 || f.Spec.Domains[0].Host != "api.example.com" {
		t.Fatalf("domains wrong: %+v", f.Spec.Domains)
	}
	r := f.Spec.Domains[0].Routes[0]
	if r.Match.PathPrefix != "/v1/" || r.Policy.Mode == nil || *r.Policy.Mode != ModeDetect {
		t.Fatalf("route wrong: %+v", r)
	}
	if f.Spec.Defaults.Timeout == nil || f.Spec.Defaults.Timeout.AsDuration().String() != "50ms" {
		t.Fatalf("timeout parse wrong: %+v", f.Spec.Defaults.Timeout)
	}
}

func TestParseStrictRejectsUnknownField(t *testing.T) {
	doc := strings.Replace(validDoc, "  name: t", "  name: t\n  bogusField: x", 1)
	if _, err := Parse("t.yaml", []byte(doc)); err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

func TestParseJSON(t *testing.T) {
	doc := `{"apiVersion":"sentinel.elchi.io/v1","kind":"SecurityPolicy",
	"metadata":{"name":"j"},"spec":{"domains":[{"host":"a.com"}]}}`
	f, err := Parse("t.json", []byte(doc))
	if err != nil {
		t.Fatalf("Parse json: %v", err)
	}
	if f.Spec.Domains[0].Host != "a.com" {
		t.Fatalf("json domain wrong: %+v", f.Spec.Domains)
	}
}

func TestParseJSONRejectsUnknownField(t *testing.T) {
	doc := `{"apiVersion":"sentinel.elchi.io/v1","kind":"SecurityPolicy","nope":1}`
	if _, err := Parse("t.json", []byte(doc)); err == nil {
		t.Fatal("expected error for unknown JSON field")
	}
}

func TestLoadValidMultiFile(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"a.yaml": validDoc,
		"b.yaml": strings.Replace(validDoc, "api.example.com", "b.example.com", 1),
	})
	merged, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(merged.Domains) != 2 {
		t.Fatalf("want 2 domains, got %d", len(merged.Domains))
	}
	if len(merged.Sources) != 2 {
		t.Fatalf("want 2 sources, got %v", merged.Sources)
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if !errors.Is(err, ErrEmptyConfigDir) {
		t.Fatalf("want ErrEmptyConfigDir, got %v", err)
	}
}

func TestLoadInvalidApiVersion(t *testing.T) {
	doc := strings.Replace(validDoc, APIVersionV1, "bad/v2", 1)
	dir := writeFiles(t, map[string]string{"a.yaml": doc})
	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "apiVersion") {
		t.Fatalf("want apiVersion error, got %v", err)
	}
}

func TestValidateDuplicateDomainAcrossFiles(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"a.yaml": validDoc,
		"b.yaml": validDoc, // identical host+listener
	})
	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "duplicate domain") {
		t.Fatalf("want duplicate domain error, got %v", err)
	}
}

func TestValidateDuplicateRoute(t *testing.T) {
	doc := `
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: a.com
      routes:
        - match: {path_prefix: /v1/}
          policy: {mode: block}
        - match: {path_prefix: /v1/}
          policy: {mode: detect}
`
	dir := writeFiles(t, map[string]string{"a.yaml": doc})
	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "duplicate route") {
		t.Fatalf("want duplicate route error, got %v", err)
	}
}

func TestValidateInvalidRegex(t *testing.T) {
	doc := strings.Replace(validDoc, "path_prefix: /v1/", `path_regex: "([a-z"`, 1)
	dir := writeFiles(t, map[string]string{"a.yaml": doc})
	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "invalid regex") {
		t.Fatalf("want invalid regex error, got %v", err)
	}
}

func TestValidateInvalidActionCombo(t *testing.T) {
	doc := `
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: a.com
      routes:
        - match: {path_prefix: /v1/}
          policy:
            mode: off
            inspect_request_body: true
`
	dir := writeFiles(t, map[string]string{"a.yaml": doc})
	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "cannot inspect request body when mode is off") {
		t.Fatalf("want action combo error, got %v", err)
	}
}

// TestLoadShippedExamples guards the example configs against regressions and
// catches the YAML 1.1 gotcha where bare `off`/`on` parse as booleans.
func TestLoadShippedExamples(t *testing.T) {
	merged, err := Load("../../configs/examples")
	if err != nil {
		t.Fatalf("example configs must load cleanly: %v", err)
	}
	if len(merged.Domains) == 0 {
		t.Fatal("expected example domains")
	}
}

func TestValidatePipelineOrder(t *testing.T) {
	// Unknown stage name → error.
	doc := `
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: a.com
      routes:
        - match: {path_prefix: /}
          policy:
            pipeline: {request: ["fast_pre_checks", "bogus_stage"]}
`
	dir := writeFiles(t, map[string]string{"a.yaml": doc})
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "unknown stage") {
		t.Fatalf("unknown stage should fail validation, got %v", err)
	}

	// Valid reorder loads cleanly.
	ok := strings.Replace(doc, `["fast_pre_checks", "bogus_stage"]`, `["waf_engine", "body_checks"]`, 1)
	dir2 := writeFiles(t, map[string]string{"a.yaml": ok})
	if _, err := Load(dir2); err != nil {
		t.Fatalf("valid reorder should load: %v", err)
	}
}

func TestValidateJWTMixedKeysRejected(t *testing.T) {
	doc := `
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: a.com
      routes:
        - match: {path_prefix: /}
          policy:
            engines:
              jwt:
                algorithms: [HS256]
                hmac_secret: "s"
                public_key_file: "/etc/k.pem"
`
	dir := writeFiles(t, map[string]string{"a.yaml": doc})
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("mixing hmac_secret + public_key_file should be rejected, got %v", err)
	}
}

func TestValidateRejectsUnsafeJWTAlg(t *testing.T) {
	doc := `
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: a.com
      routes:
        - match: {path_prefix: /}
          policy:
            engines:
              jwt:
                algorithms: [none]
                hmac_secret: "s"
`
	dir := writeFiles(t, map[string]string{"a.yaml": doc})
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "algorithms") {
		t.Fatalf("alg=none should be rejected, got %v", err)
	}
}

func TestValidateRejectsZeroTimeout(t *testing.T) {
	doc := strings.Replace(validDoc, "mode: block", "mode: block\n    timeout: 0s", 1)
	dir := writeFiles(t, map[string]string{"a.yaml": doc})
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("timeout: 0 should be rejected, got %v", err)
	}
}

func TestValidateRejectsAbsurdBodyCap(t *testing.T) {
	doc := strings.Replace(validDoc, "mode: block", "mode: block\n    max_request_body_bytes: 9999999999", 1)
	dir := writeFiles(t, map[string]string{"a.yaml": doc})
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "max_request_body_bytes") {
		t.Fatalf("absurd body cap should be rejected, got %v", err)
	}
}

func TestValidateInvalidSamplingRate(t *testing.T) {
	doc := strings.Replace(validDoc, "mode: block", "mode: block\n    sampling_rate: 2.5", 1)
	dir := writeFiles(t, map[string]string{"a.yaml": doc})
	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "sampling_rate") {
		t.Fatalf("want sampling_rate error, got %v", err)
	}
}

func TestValidateGeoCountryOverlap(t *testing.T) {
	doc := `
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: a.com
      routes:
        - match: {path_prefix: /v1/}
          policy:
            mode: block
            engines:
              ip_reputation:
                geoip:
                  database_file: /tmp/x.mmdb
                  block_countries: ["GB", "RU"]
                  allow_countries: ["gb"]
`
	dir := writeFiles(t, map[string]string{"a.yaml": doc})
	_, err := Load(dir)
	if err == nil || !strings.Contains(err.Error(), "both block_countries and allow_countries") {
		t.Fatalf("want block/allow overlap error, got %v", err)
	}
}

func TestValidateBotFootguns(t *testing.T) {
	base := `
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: a.com
      routes:
        - match: {path_prefix: /v1/}
          policy:
            mode: block
            engines:
              bot:
`
	cases := map[string]struct{ frag, want string }{
		"empty deny substring": {
			"                user_agent: { deny_substrings: [\"sqlmap\", \"\"] }\n",
			"deny_substrings[1]",
		},
		"score layer no threshold": {
			"                heuristics: { require_accept_language: true, score_per_anomaly: 30 }\n",
			"score_threshold",
		},
		"negative ja4 score": {
			"                score_threshold: 50\n                tls_fingerprint: { score_ja4: { abc: -5 } }\n",
			"must be >= 0",
		},
	}
	for name, tc := range cases {
		dir := writeFiles(t, map[string]string{"a.yaml": base + tc.frag})
		_, err := Load(dir)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", name, tc.want, err)
		}
	}
}

func TestValidateJWTFootguns(t *testing.T) {
	base := `
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: a.com
      routes:
        - match: {path_prefix: /v1/}
          policy:
            mode: block
            engines:
              jwt:
`
	cases := map[string]struct{ frag, want string }{
		"leeway too large": {
			"                algorithms: [HS256]\n                hmac_secret: s\n                leeway: 24h\n",
			"must be <= 5m",
		},
		"HS alg with public key only": {
			"                algorithms: [HS256]\n                public_key_file: /tmp/k.pem\n",
			"needs hmac_secret",
		},
		"RS alg with hmac secret only": {
			"                algorithms: [RS256]\n                hmac_secret: s\n",
			"needs public_key_file",
		},
	}
	for name, tc := range cases {
		dir := writeFiles(t, map[string]string{"a.yaml": base + tc.frag})
		_, err := Load(dir)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", name, tc.want, err)
		}
	}
}

func TestValidateJWKSFootguns(t *testing.T) {
	base := `
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: a.com
      routes:
        - match: {path_prefix: /v1/}
          policy:
            mode: block
            engines:
              jwks:
`
	cases := map[string]struct{ frag, want string }{
		"HS alg with JWKS": {
			"                file: /tmp/j.json\n                algorithms: [HS256]\n",
			"asymmetric keys only",
		},
		"http url (MITM-able)": {
			"                url: http://idp.example.com/jwks\n                algorithms: [RS256]\n",
			"must use https",
		},
		"leeway too large": {
			"                file: /tmp/j.json\n                algorithms: [RS256]\n                leeway: 1h\n",
			"must be <= 5m",
		},
	}
	for name, tc := range cases {
		dir := writeFiles(t, map[string]string{"a.yaml": base + tc.frag})
		_, err := Load(dir)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", name, tc.want, err)
		}
	}
	// A loopback http URL is allowed (local IdP).
	ok := base + "                url: http://127.0.0.1:8443/jwks\n                algorithms: [RS256]\n"
	if _, err := Load(writeFiles(t, map[string]string{"a.yaml": ok})); err != nil {
		t.Errorf("loopback http JWKS URL should be allowed, got %v", err)
	}
}

func TestValidateHMACSignFootguns(t *testing.T) {
	base := `
apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: a.com
      routes:
        - match: {path_prefix: /v1/}
          policy:
            mode: block
            engines:
              hmac_sign:
`
	cases := map[string]struct{ frag, want string }{
		"weak shared secret": {
			"                secret: short\n",
			"at least 16 bytes",
		},
		"weak rotated secret": {
			"                secrets: {k1: short}\n",
			"at least 16 bytes",
		},
		"window too large": {
			"                secret: a-long-enough-shared-secret\n                window: 24h\n",
			"must be <= 1h0m0s",
		},
		"nonce_ttl too large": {
			"                secret: a-long-enough-shared-secret\n                nonce_ttl: 24h\n",
			"must be <= 1h0m0s",
		},
	}
	for name, tc := range cases {
		dir := writeFiles(t, map[string]string{"a.yaml": base + tc.frag})
		_, err := Load(dir)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", name, tc.want, err)
		}
	}
	// A strong secret with a sane window is accepted.
	ok := base + "                secret: a-long-enough-shared-secret\n                window: 300s\n"
	if _, err := Load(writeFiles(t, map[string]string{"a.yaml": ok})); err != nil {
		t.Errorf("strong secret with sane window should be allowed, got %v", err)
	}
}
