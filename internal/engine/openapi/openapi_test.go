package openapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

type hdrs map[string]string

func (h hdrs) Header(name string) (string, bool) { v, ok := h[name]; return v, ok }
func (h hdrs) RangeHeaders(fn func(string, string) bool) {
	for k, v := range h {
		if !fn(k, v) {
			return
		}
	}
}

const spec = `
openapi: 3.0.0
info: {title: e2e, version: 1.0.0}
paths:
  /users/{id}:
    get:
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
        - {name: q, in: query, required: true, schema: {type: string}}
      responses: {'200': {description: ok}}
  /create:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties: {name: {type: string}}
      responses: {'200': {description: ok}}
`

func mkEngine(t *testing.T, body, rejectPath bool) *Engine {
	t.Helper()
	fp := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(fp, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(Config{SpecFile: fp, ValidateRequestBody: body, RejectUndeclaredPath: rejectPath})
	if err != nil {
		t.Fatal(err)
	}
	return e.(*Engine)
}

func req(method, path, ct, body string) *engine.Request {
	return &engine.Request{
		Direction: engine.DirectionRequest, Method: method, Host: "api.example.com",
		Path: path, ContentType: ct, Body: []byte(body), Headers: hdrs{},
	}
}

func inspect(t *testing.T, e *Engine, r *engine.Request) decision.Verdict {
	t.Helper()
	v, err := e.Inspect(context.Background(), r)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return v
}

func TestValidParams(t *testing.T) {
	e := mkEngine(t, false, false)
	if v := inspect(t, e, req("GET", "/users/5?q=hi", "", "")); v.Action == decision.Block {
		t.Fatalf("conforming request should pass, got %+v", v)
	}
}

func TestBadParamType(t *testing.T) {
	e := mkEngine(t, false, false)
	if v := inspect(t, e, req("GET", "/users/abc?q=hi", "", "")); v.Action != decision.Block {
		t.Fatal("non-integer path param should block")
	}
}

func TestMissingRequiredQuery(t *testing.T) {
	e := mkEngine(t, false, false)
	if v := inspect(t, e, req("GET", "/users/5", "", "")); v.Action != decision.Block {
		t.Fatal("missing required query param should block")
	}
}

func TestUndeclaredPath(t *testing.T) {
	e := mkEngine(t, false, true)
	if v := inspect(t, e, req("GET", "/nope", "", "")); v.RuleID != "openapi.undeclared_path" {
		t.Fatalf("undeclared path should block, got %+v", v)
	}
}

func TestRequestBodyValidation(t *testing.T) {
	e := mkEngine(t, true, false)
	if !e.RequiresBody() {
		t.Fatal("validate_request_body must set RequiresBody")
	}
	if v := inspect(t, e, req("POST", "/create", "application/json", `{"name":"alice"}`)); v.Action == decision.Block {
		t.Fatalf("conforming body should pass, got %+v", v)
	}
	if v := inspect(t, e, req("POST", "/create", "application/json", `{}`)); v.Action != decision.Block {
		t.Fatal("body missing required field should block")
	}
}

func TestBodyValidationOffSkipsBody(t *testing.T) {
	// Body validation OFF → the body isn't buffered (empty). A required-body
	// operation must NOT be rejected for the unbuffered body...
	e := mkEngine(t, false, false)
	if v := inspect(t, e, req("POST", "/create", "application/json", "")); v.Action == decision.Block {
		t.Fatalf("body-off must not reject a required-body op on an empty body, got %+v", v)
	}
	// ...but parameters are still validated.
	if v := inspect(t, e, req("GET", "/users/abc?q=hi", "", "")); v.Action != decision.Block {
		t.Fatal("parameters must still be validated when body validation is off")
	}
}

func TestBodyValidationOnStillChecksBody(t *testing.T) {
	e := mkEngine(t, true, false)
	if v := inspect(t, e, req("POST", "/create", "application/json", `{}`)); v.Action != decision.Block {
		t.Fatal("body-on must still reject a body missing a required field")
	}
}

func TestReasonDoesNotLeakSubmittedValue(t *testing.T) {
	// The block reason is auditable; it must not embed the request's submitted
	// value (potential PII/secret).
	e := mkEngine(t, false, false)
	const secret = "SUPERSECRET123"
	v := inspect(t, e, req("GET", "/users/"+secret+"?q=hi", "", ""))
	if v.Action != decision.Block {
		t.Fatal("a non-integer id should block")
	}
	if strings.Contains(v.Reason, secret) {
		t.Fatalf("audit reason leaked the submitted value: %q", v.Reason)
	}
}

func TestResponseDirectionPasses(t *testing.T) {
	e := mkEngine(t, false, true)
	v := inspect(t, e, &engine.Request{Direction: engine.DirectionResponse, Headers: hdrs{}})
	if v.Action == decision.Block {
		t.Fatal("openapi must not run on the response direction")
	}
}

func TestMetadata(t *testing.T) {
	e := mkEngine(t, false, false)
	if e.Name() != "openapi" {
		t.Errorf("name = %q", e.Name())
	}
	if err := e.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestBadSpec(t *testing.T) {
	if _, err := New(Config{SpecFile: "/nonexistent.yaml"}); err == nil {
		t.Fatal("missing spec file should error")
	}
}
