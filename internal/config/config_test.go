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
