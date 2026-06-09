package httpsig

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yaronf/httpsign"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/engine/auth"
)

const engineName = "httpsig"

// libDefaultMaxAge mirrors the yaronf/httpsign default `notOlderThan` window
// applied when MaxAge is unset; used to size the nonce replay-cache TTL so a
// recorded nonce lives exactly as long as a signature is accepted.
const libDefaultMaxAge = 10 * time.Second

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
		// Cover the query by default: omitting @query would let an attacker
		// replay a captured signature against a tampered query string.
		covered = []string{"@method", "@authority", "@path", "@query"}
	}
	fields := httpsign.Headers(covered...)

	// A shared, bounded replay cache rejects a reused `nonce` parameter within
	// the signature's validity window. The library only invokes the validator
	// when the signature actually carries a nonce, so this is zero-cost for
	// clients that don't send one (they remain bounded by the freshness window).
	window := cfg.MaxAge
	if window <= 0 {
		window = libDefaultMaxAge
	}
	replay := auth.NewReplayCache(window, time.Now)

	vc := httpsign.NewVerifyConfig().
		SetAllowedAlgs([]string{"hmac-sha256"}).
		SetNonceValidator(func(nonce string) error {
			if replay.SeenBefore(nonce) {
				return errors.New("nonce already used (replay)")
			}
			return nil
		})
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
		return block("httpsig.invalid", "RFC 9421 signature verification failed"), nil
	}
	// VerifyRequest only proves the signature covers the Content-Digest *header
	// value* — it does NOT recompute the digest from the body. Without this check
	// an attacker could keep the signed header and swap the body. Validate the
	// authenticated digest against the actual body before allowing.
	if e.requiresBody {
		cd := hr.Header.Values("Content-Digest")
		if len(cd) == 0 {
			return block("httpsig.digest_missing", "missing Content-Digest header"), nil
		}
		body := io.NopCloser(bytes.NewReader(req.Body))
		if err := httpsign.ValidateContentDigestHeader(cd, &body, []string{httpsign.DigestSha256, httpsign.DigestSha512}); err != nil {
			return block("httpsig.digest_mismatch", "Content-Digest does not match the request body"), nil
		}
	}
	return decision.Verdict{}, nil
}

func block(ruleID, reason string) decision.Verdict {
	return decision.Verdict{
		Action:     decision.Block,
		Reason:     reason,
		RuleID:     ruleID,
		Engine:     engineName,
		Severity:   decision.SeverityHigh,
		StatusCode: decision.DefaultBlockStatus,
	}
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
