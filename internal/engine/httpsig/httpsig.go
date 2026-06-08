//go:build httpsig

package httpsig

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/yaronf/httpsign"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

const engineName = "httpsig"

// Engine verifies RFC 9421 HTTP Message Signatures (hmac-sha256).
type Engine struct {
	sigName      string
	verifier     httpsign.Verifier
	requiresBody bool
}

// New compiles the configuration into an Engine.
func New(cfg Config) (engine.SecurityEngine, error) {
	name := cfg.SignatureName
	if name == "" {
		name = "sig1"
	}
	covered := cfg.CoveredComponents
	if len(covered) == 0 {
		covered = []string{"@method", "@authority", "@path"}
	}
	fields := httpsign.Headers(covered...)

	vc := httpsign.NewVerifyConfig().SetAllowedAlgs([]string{"hmac-sha256"})
	if cfg.MaxAge > 0 {
		vc = vc.SetNotOlderThan(cfg.MaxAge).SetRejectExpired(true)
	}
	v, err := httpsign.NewHMACSHA256Verifier([]byte(cfg.Secret), vc, fields)
	if err != nil {
		return nil, err
	}

	requiresBody := false
	for _, c := range covered {
		if strings.EqualFold(c, "content-digest") {
			requiresBody = true
		}
	}
	return &Engine{sigName: name, verifier: *v, requiresBody: requiresBody}, nil
}

// Name implements engine.SecurityEngine.
func (*Engine) Name() string { return engineName }

// RequiresBody reports whether the covered components include content-digest.
func (e *Engine) RequiresBody() bool { return e.requiresBody }

// Close implements engine.SecurityEngine.
func (*Engine) Close() error { return nil }

// Inspect verifies the request signature. Responses pass through.
func (e *Engine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	if req.Direction != engine.DirectionRequest {
		return decision.Verdict{}, nil
	}
	hr := e.toHTTPRequest(req)
	if err := httpsign.VerifyRequest(e.sigName, e.verifier, hr); err != nil {
		return decision.Verdict{
			Action:     decision.Block,
			Reason:     "RFC 9421 signature verification failed",
			RuleID:     "httpsig.invalid",
			Engine:     engineName,
			Severity:   decision.SeverityHigh,
			StatusCode: decision.DefaultBlockStatus,
		}, nil
	}
	return decision.Verdict{}, nil
}

// toHTTPRequest reconstructs a net/http.Request from the engine view so the
// httpsign library can derive @method/@authority/@path/@query and read headers.
// Pseudo-headers (":authority", ":path", …) are not copied as real headers; they
// are represented by the request line instead.
func (e *Engine) toHTTPRequest(req *engine.Request) *http.Request {
	rawPath := req.Path
	pathPart, query, _ := strings.Cut(rawPath, "?")
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
	return hr
}
