//go:build openapi

package openapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi-validator/paths"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

const engineName = "openapi"

// Engine validates requests against an OpenAPI 3.x specification.
type Engine struct {
	model        *v3.Document
	validator    validator.Validator
	requiresBody bool
	rejectPath   bool
}

// New loads and compiles the specification once on the cold path.
func New(cfg Config) (engine.SecurityEngine, error) {
	if cfg.SpecFile == "" {
		return nil, errors.New("openapi: spec_file is required")
	}
	data, err := os.ReadFile(cfg.SpecFile) //nolint:gosec // operator-controlled config path
	if err != nil {
		return nil, fmt.Errorf("openapi: read spec: %w", err)
	}
	doc, err := libopenapi.NewDocument(data)
	if err != nil {
		return nil, fmt.Errorf("openapi: parse spec: %w", err)
	}
	model, err := doc.BuildV3Model()
	if err != nil {
		return nil, fmt.Errorf("openapi: build model: %w", err)
	}
	v := validator.NewValidatorFromV3Model(&model.Model)
	return &Engine{
		model:        &model.Model,
		validator:    v,
		requiresBody: cfg.ValidateRequestBody,
		rejectPath:   cfg.RejectUndeclaredPath,
	}, nil
}

// Name implements engine.SecurityEngine.
func (*Engine) Name() string { return engineName }

// RequiresBody reports whether request-body validation is enabled.
func (e *Engine) RequiresBody() bool { return e.requiresBody }

// Close implements engine.SecurityEngine.
func (*Engine) Close() error { return nil }

// Inspect validates the request against the spec. Responses pass through.
func (e *Engine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	if req.Direction != engine.DirectionRequest {
		return decision.Verdict{}, nil
	}
	hr := toHTTPRequest(req)

	// Undeclared-path detection (shadow-endpoint): FindPath resolves the matching
	// PathItem; a nil item means the path isn't in the contract.
	if e.rejectPath {
		item, _, _ := paths.FindPath(hr, e.model, nil)
		if item == nil {
			return block("openapi.undeclared_path", "request path is not declared in the OpenAPI spec"), nil
		}
	}

	// ValidateHttpRequestSync validates path/query/header params and the request
	// body WITHOUT spawning goroutines (hot-path safe).
	ok, verrs := e.validator.ValidateHttpRequestSync(hr)
	if !ok {
		reason := "request does not conform to the OpenAPI spec"
		if len(verrs) > 0 && verrs[0] != nil {
			reason = verrs[0].Message
		}
		return block("openapi.invalid", reason), nil
	}
	return decision.Verdict{}, nil
}

// toHTTPRequest reconstructs a net/http.Request from the engine view for the
// validator (path/query/headers/body).
func toHTTPRequest(req *engine.Request) *http.Request {
	pathPart, query, _ := strings.Cut(req.Path, "?")
	u := &url.URL{Scheme: "http", Host: req.Host, Path: pathPart, RawQuery: query}
	hr := &http.Request{
		Method: req.Method,
		URL:    u,
		Host:   req.Host,
		Header: make(http.Header),
		Body:   io.NopCloser(bytes.NewReader(req.Body)),
	}
	hr.ContentLength = int64(len(req.Body))
	req.Headers.RangeHeaders(func(k, v string) bool {
		if !strings.HasPrefix(k, ":") {
			hr.Header.Add(k, v)
		}
		return true
	})
	if req.ContentType != "" && hr.Header.Get("Content-Type") == "" {
		hr.Header.Set("Content-Type", req.ContentType)
	}
	return hr
}

func block(ruleID, reason string) decision.Verdict {
	return decision.Verdict{
		Action:     decision.Block,
		Reason:     reason,
		RuleID:     ruleID,
		Engine:     engineName,
		Severity:   decision.SeverityMedium,
		StatusCode: decision.DefaultBlockStatus,
	}
}
