package extproc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	// Register the Coraza factory (same blank import cmd/elchi-shield uses) so
	// `engines.coraza` policies compile in this test binary.
	_ "github.com/cloudnativeworks/elchi-shield/internal/engine/coraza"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline/stages"
	"github.com/cloudnativeworks/elchi-shield/internal/runtime"
	"github.com/cloudnativeworks/elchi-shield/internal/sensitive"
)

// procFromYAML loads a policy the exact way the daemon does (parse → validate →
// merge → compile engines → snapshot), so this exercises the REAL runtime path for
// the engine configs the API-Discovery suggestion emits — not hand-built structs.
func procFromYAML(t *testing.T, yamlStr string) *Processor {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(yamlStr), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	snap, err := runtime.NewSnapshot(cfg, time.Now())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return NewProcessor(Config{
		Store:   runtime.NewStore(snap),
		Pool:    pipeline.NewPool(),
		Catalog: stages.NewCatalog(stages.Deps{DefaultAllow: true, Detector: sensitive.New()}),
		MaxBody: 1 << 20,
	})
}

func respTrailers() *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseTrailers{
		ResponseTrailers: &extprocv3.HttpTrailers{},
	}}
}

func blockCode(t *testing.T, out []*extprocv3.ProcessingResponse) int {
	t.Helper()
	if len(out) == 0 || !isImmediate(out[len(out)-1]) {
		t.Fatalf("expected an immediate block, got %#v", out)
	}
	return int(out[len(out)-1].Response.(*extprocv3.ProcessingResponse_ImmediateResponse).ImmediateResponse.Status.Code)
}

// TestSuggested_JWT_BlocksMissingToken: a jwt route with the suggestion's HS256
// TestSuggested_RouteCoversAllMethods guards against the method-restriction bypass:
// the suggestion emits NO `methods` on the route match (the auth/WAF engines must
// apply to every method), so a request with a method the collector never observed
// must still hit the route and be blocked — not fall through to the file default.
func TestSuggested_RouteCoversAllMethods(t *testing.T) {
	pr := procFromYAML(t, `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: t }
spec:
  defaults: { mode: detect, fail_mode: fail_open }
  domains:
    - hosts: ["api.example.com"]
      routes:
        - match: { path_regex: "(?i)^/users/[^/]+/?$" }
          policy:
            mode: block
            fail_mode: fail_close
            engines:
              jwt: { issuer: "https://i/", audience: api, algorithms: [HS256], hmac_secret: "CHANGE_ME_placeholder_secret_0123456789" }
`)
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
		out := run(t, pr, reqHeadersEOS(":authority", "api.example.com", ":path", "/users/9", ":method", m))
		if c := blockCode(t, out); c != 403 {
			t.Fatalf("%s must be blocked (no method bypass), got %d", m, c)
		}
	}
}

// placeholder secret must BLOCK a request that carries no bearer token.
func TestSuggested_JWT_BlocksMissingToken(t *testing.T) {
	pr := procFromYAML(t, `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: t }
spec:
  domains:
    - hosts: ["api.example.com"]
      routes:
        - match: { path_prefix: "/" }
          policy:
            mode: block
            fail_mode: fail_close
            engines:
              jwt: { issuer: "https://i/", audience: api, algorithms: [HS256], hmac_secret: "CHANGE_ME_placeholder_secret_0123456789" }
`)
	out := run(t, pr, reqHeadersEOS(":authority", "api.example.com", ":path", "/x", ":method", "GET"))
	if c := blockCode(t, out); c != 403 {
		t.Fatalf("missing JWT must be 403, got %d", c)
	}
	// A bogus (unverifiable) token must also block.
	out = run(t, pr, reqHeadersEOS(":authority", "api.example.com", ":path", "/x", ":method", "GET", "authorization", "Bearer not.a.jwt"))
	if c := blockCode(t, out); c != 403 {
		t.Fatalf("bad JWT must be 403, got %d", c)
	}
}

// TestSuggested_APIKey_BlocksAll: an api_key route with the suggestion's all-zeros
// placeholder sha256 must DENY every request (no key, and any wrong key).
func TestSuggested_APIKey_BlocksAll(t *testing.T) {
	pr := procFromYAML(t, `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: t }
spec:
  domains:
    - hosts: ["api.example.com"]
      routes:
        - match: { path_prefix: "/" }
          policy:
            mode: block
            fail_mode: fail_close
            engines:
              api_key:
                source: header
                name: X-Api-Key
                keys: [ { sha256: "0000000000000000000000000000000000000000000000000000000000000000", subject: placeholder } ]
`)
	for _, hdr := range [][]string{
		{":authority", "api.example.com", ":path", "/x", ":method", "GET"},
		{":authority", "api.example.com", ":path", "/x", ":method", "GET", "x-api-key", "guessed-key"},
	} {
		if c := blockCode(t, run(t, pr, reqHeadersEOS(hdr...))); c != 403 {
			t.Fatalf("api_key must block (403), got %d for %v", c, hdr)
		}
	}
}

// TestSuggested_Bot_BlocksEmptyAndDenyUA: the suggestion's bot config must block an
// empty User-Agent and a deny-listed UA.
func TestSuggested_Bot_BlocksEmptyAndDenyUA(t *testing.T) {
	pr := procFromYAML(t, `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: t }
spec:
  domains:
    - hosts: ["api.example.com"]
      routes:
        - match: { path_prefix: "/" }
          policy:
            mode: block
            engines:
              bot:
                score_threshold: 50
                user_agent: { deny_substrings: ["sqlmap"], block_empty: true }
                heuristics: { require_accept: true, require_accept_language: true, score_per_anomaly: 25 }
`)
	// Deny-listed UA → hard block.
	if c := blockCode(t, run(t, pr, reqHeadersEOS(":authority", "api.example.com", ":path", "/x", ":method", "GET", "user-agent", "sqlmap/1.5"))); c != 403 {
		t.Fatalf("deny-listed UA must be 403, got %d", c)
	}
	// Empty UA → hard block.
	if c := blockCode(t, run(t, pr, reqHeadersEOS(":authority", "api.example.com", ":path", "/x", ":method", "GET", "user-agent", ""))); c != 403 {
		t.Fatalf("empty UA must be 403, got %d", c)
	}
	// HEURISTIC layer must be LIVE (regression guard for the dead-threshold bug):
	// a non-empty, non-deny UA missing BOTH Accept and Accept-Language reaches the
	// threshold (25+25=50) and blocks.
	if c := blockCode(t, run(t, pr, reqHeadersEOS(":authority", "api.example.com", ":path", "/x", ":method", "GET", "user-agent", "tool/1.0"))); c != 403 {
		t.Fatalf("missing Accept+Accept-Language must trip the heuristic (403), got %d", c)
	}
	// A legit browser (both headers present) must NOT be blocked — no false positive.
	clean := run(t, pr, reqHeadersEOS(":authority", "api.example.com", ":path", "/x", ":method", "GET", "user-agent", "Mozilla/5.0", "accept", "text/html", "accept-language", "en-US"))
	if len(clean) > 0 && isImmediate(clean[len(clean)-1]) {
		t.Fatal("a browser with Accept + Accept-Language must not be blocked by bot heuristics")
	}
}

// TestSuggested_RateLimit_HeaderKey: the suggestion keys rate_limit on a header so
// it enforces without use_remote_address — a flood must eventually 429.
func TestSuggested_RateLimit_HeaderKey(t *testing.T) {
	pr := procFromYAML(t, `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: t }
spec:
  domains:
    - hosts: ["api.example.com"]
      routes:
        - match: { path_prefix: "/" }
          policy:
            mode: block
            engines:
              rate_limit: { requests_per_second: 2, burst: 3, key: header, header: "X-Demo-Client" }
`)
	got429 := false
	for range 8 {
		out := run(t, pr, reqHeadersEOS(":authority", "api.example.com", ":path", "/x", ":method", "GET", "x-demo-client", "attacker"))
		if len(out) > 0 && isImmediate(out[len(out)-1]) {
			if int(out[len(out)-1].Response.(*extprocv3.ProcessingResponse_ImmediateResponse).ImmediateResponse.Status.Code) == 429 {
				got429 = true
				break
			}
		}
	}
	if !got429 {
		t.Fatal("rate_limit (key=header) must 429 under a flood")
	}
}

// TestSuggested_Coraza_BlocksSQLiInQuery: coraza with OWASP CRS must block an obvious
// SQLi in the query string even when the request has no body.
func TestSuggested_Coraza_BlocksSQLiInQuery(t *testing.T) {
	pr := procFromYAML(t, `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: t }
spec:
  domains:
    - hosts: ["api.example.com"]
      routes:
        - match: { path_prefix: "/" }
          policy:
            mode: block
            inspect_request_body: true
            engines:
              coraza: { include_owasp: true }
`)
	// Normal browser-ish headers on BOTH requests so the ONLY difference is the SQLi
	// payload (otherwise CRS's missing-header anomaly rules would block even a clean
	// request, masking what we're testing). The Host header is synthesized by the
	// coraza adapter from :authority when absent, so 920280 doesn't false-positive —
	// see TestCoraza_AuthorityOnlyNoFalsePositive.
	normal := []string{"host", "api.example.com", "user-agent", "Mozilla/5.0", "accept", "text/html", "accept-language", "en-US", "accept-encoding", "gzip"}
	sqli := append([]string{":authority", "api.example.com", ":path", "/items?id=1%27%20OR%20%271%27%3D%271%20--%20", ":method", "GET"}, normal...)
	if c := blockCode(t, run(t, pr, reqHeadersEOS(sqli...))); c != 403 {
		t.Fatalf("coraza must block SQLi in query (403), got %d", c)
	}
	// A clean request with the same normal headers must NOT be blocked.
	cleanReq := append([]string{":authority", "api.example.com", ":path", "/items?id=42", ":method", "GET"}, normal...)
	clean := run(t, pr, reqHeadersEOS(cleanReq...))
	if len(clean) > 0 && isImmediate(clean[len(clean)-1]) {
		code := int(clean[len(clean)-1].Response.(*extprocv3.ProcessingResponse_ImmediateResponse).ImmediateResponse.Status.Code)
		t.Fatalf("clean request must not be blocked, got immediate %d", code)
	}
}

// TestCoraza_AuthorityOnlyNoFalsePositive proves the fix for the production false
// positive where coraza 403'd EVERY request: Envoy (HTTP/2) forwards the authority
// as :authority, not a Host request header, so CRS rule 920280 ("Missing Host")
// fired on all traffic. The adapter now synthesizes a Host header from the derived
// host, so a clean :authority-only request is allowed while attacks still block.
func TestCoraza_AuthorityOnlyNoFalsePositive(t *testing.T) {
	pr := procFromYAML(t, `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: t }
spec:
  domains:
    - hosts: ["*"]
      routes:
        - match: { path_prefix: "/" }
          policy:
            mode: block
            inspect_request_body: true
            engines:
              coraza: { include_owasp: true }
`)
	imm := func(out []*extprocv3.ProcessingResponse) bool {
		return len(out) > 0 && isImmediate(out[len(out)-1])
	}
	// Clean request, :authority only, NO Host header (exactly what Envoy sends over
	// HTTP/2). Must NOT be blocked.
	clean := []string{":authority", "api.example.com", ":path", "/items?id=42", ":method", "GET", "user-agent", "Mozilla/5.0", "accept", "text/html"}
	if imm(run(t, pr, reqHeadersEOS(clean...))) {
		t.Fatal("clean :authority-only request must not be blocked (CRS 920280 regression)")
	}
	// An actual attack on the same :authority-only shape must still block.
	sqli := []string{":authority", "api.example.com", ":path", "/x?id=1%27%20OR%20%271%27%3D%271%20--%20", ":method", "GET", "user-agent", "Mozilla/5.0", "accept", "text/html"}
	if !imm(run(t, pr, reqHeadersEOS(sqli...))) {
		t.Fatal("SQLi on :authority-only request must still block")
	}
}

// TestSuggested_DLP_RedactsTraileredResponse: a DLP redact on a response whose body
// ends with HTTP TRAILERS (final body chunk carries end_of_stream=false) must still
// be redacted. The mutation can't be carried by the trailers message, so it must be
// applied at the body message — without the fix the un-redacted body leaks.
func TestSuggested_DLP_RedactsTraileredResponse(t *testing.T) {
	pr := procFromYAML(t, `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: t }
spec:
  domains:
    - hosts: ["api.example.com"]
      routes:
        - match: { path_prefix: "/" }
          policy:
            mode: block
            inspect_response_body: true
            max_response_body_bytes: 1048576
            checks:
              body:
                dlp: { direction: response, redact: [email] }
`)
	out := run(t, pr,
		reqHeadersEOS(":authority", "api.example.com", ":path", "/x", ":method", "GET"),
		respHeaders(":status", "200", "content-type", "application/json"),
		respBody(`{"email":"alice@example.com"}`, false), // EOS=false → trailers follow
		respTrailers(),
	)
	// One of the responses must be a body mutation whose body no longer contains the
	// raw email address.
	var mutated []byte
	for _, o := range out {
		if rb, ok := o.Response.(*extprocv3.ProcessingResponse_ResponseBody); ok {
			if bm := rb.ResponseBody.GetResponse().GetBodyMutation(); bm != nil {
				mutated = bm.GetBody()
			}
		}
	}
	if mutated == nil {
		t.Fatalf("trailered response with PII must produce a body mutation; got %#v", out)
	}
	if strings.Contains(string(mutated), "alice@example.com") {
		t.Fatalf("email must be redacted from the trailered response body, got %q", mutated)
	}
}

// TestSuggested_DLP_BlocksInboundSecret: the suggestion's DLP (direction:both,
// block hard secrets) must BLOCK a hard secret sent in the REQUEST body — the
// inbound-credential case the collector's secret_in_path signal targets.
func TestSuggested_DLP_BlocksInboundSecret(t *testing.T) {
	pr := procFromYAML(t, `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: { name: t }
spec:
  domains:
    - hosts: ["api.example.com"]
      routes:
        - match: { path_prefix: "/register" }
          policy:
            mode: block
            inspect_request_body: true
            inspect_response_body: true
            max_request_body_bytes: 1048576
            max_response_body_bytes: 1048576
            checks:
              body:
                dlp:
                  direction: both
                  block: [private_key, aws_access_key, google_api_key, slack_token, github_token]
                  redact: [email, ssn]
`)
	// AWS key in the REQUEST body → inbound hard-secret must block.
	out := run(t, pr,
		reqHeaders(":authority", "api.example.com", ":path", "/register", ":method", "POST", "content-type", "application/json"),
		reqBody(`{"key":"AKIAIOSFODNN7EXAMPLE"}`, true),
	)
	if c := blockCode(t, out); c != 403 {
		t.Fatalf("inbound AWS key must be blocked by DLP (403), got %d", c)
	}
	// A clean request body must pass.
	clean := run(t, pr,
		reqHeaders(":authority", "api.example.com", ":path", "/register", ":method", "POST", "content-type", "application/json"),
		reqBody(`{"name":"alice"}`, true),
	)
	if len(clean) > 0 && isImmediate(clean[len(clean)-1]) {
		t.Fatal("a clean request body must not be blocked by DLP")
	}
}
