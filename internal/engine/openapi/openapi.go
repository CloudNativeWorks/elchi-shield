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
	verrors "github.com/pb33f/libopenapi-validator/errors"
	"github.com/pb33f/libopenapi-validator/parameters"
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

	// Resolve the operation once. A nil PathItem means the path isn't in the
	// contract — a positive-security engine blocks it either way; rejectPath only
	// selects the clearer rule id.
	item, ferrs, pathValue := paths.FindPath(hr, e.model, nil)
	if item == nil || len(ferrs) > 0 {
		if item == nil {
			return block("openapi.undeclared_path", "request path is not declared in the OpenAPI spec"), nil
		}
		return block("openapi.invalid", genericReason(ferrs)), nil
	}

	// With body validation on, validate everything (params + body); the body was
	// buffered because RequiresBody() reported true. With it off the body is NOT
	// buffered, so validating it would falsely reject a required-body operation on
	// an empty body — validate parameters only (path/query/header/cookie/security)
	// using the same set the full validator runs, minus the body.
	var ok bool
	var verrs []*verrors.ValidationError
	if e.requiresBody {
		ok, verrs = e.validator.ValidateHttpRequestSyncWithPathItem(hr, item, pathValue)
	} else {
		ok, verrs = validateParamsOnly(e.validator.GetParameterValidator(), hr, item, pathValue)
	}
	if !ok {
		return block("openapi.invalid", genericReason(verrs)), nil
	}
	return decision.Verdict{}, nil
}

// validateParamsOnly runs the parameter/security validators (everything the full
// sync validator runs except the request body), so disabling body validation
// doesn't reject requests for an unbuffered body.
func validateParamsOnly(pv parameters.ParameterValidator, hr *http.Request, item *v3.PathItem, pathValue string) (bool, []*verrors.ValidationError) {
	var all []*verrors.ValidationError
	for _, fn := range []func(*http.Request, *v3.PathItem, string) (bool, []*verrors.ValidationError){
		pv.ValidatePathParamsWithPathItem,
		pv.ValidateCookieParamsWithPathItem,
		pv.ValidateHeaderParamsWithPathItem,
		pv.ValidateQueryParamsWithPathItem,
		pv.ValidateSecurityWithPathItem,
	} {
		if okp, errs := fn(hr, item, pathValue); !okp {
			all = append(all, errs...)
		}
	}
	return len(all) == 0, all
}

// genericReason builds an audit-safe block reason from a validation error using
// ONLY structural, spec-derived fields (type/subtype/parameter name). It never
// surfaces Message/Reason/SchemaValidationErrors, which embed the submitted value
// and would leak request data (PII/secrets) into the audit log.
func genericReason(verrs []*verrors.ValidationError) string {
	const generic = "request does not conform to the OpenAPI spec"
	if len(verrs) == 0 || verrs[0] == nil {
		return generic
	}
	e0 := verrs[0]
	switch {
	case e0.ParameterName != "" && e0.ValidationSubType != "":
		return fmt.Sprintf("%s parameter %q does not conform to the OpenAPI spec", e0.ValidationSubType, e0.ParameterName)
	case e0.ParameterName != "":
		return fmt.Sprintf("parameter %q does not conform to the OpenAPI spec", e0.ParameterName)
	case e0.ValidationType != "":
		return e0.ValidationType + " does not conform to the OpenAPI spec"
	default:
		return generic
	}
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
