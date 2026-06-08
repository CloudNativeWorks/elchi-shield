package stages

import (
	"context"
	"encoding/json"
	"mime"
	"strings"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
)

// SensitiveDataDetector is the hook interface for detecting sensitive data in a
// body (PII, secrets, tokens). It is intentionally generic so different scanners
// can be plugged in. A nil detector disables the check.
type SensitiveDataDetector interface {
	// Scan inspects body for sensitive data given its content type. It returns
	// whether something was found and a short kind label for attribution.
	Scan(ctx context.Context, contentType string, body []byte) (found bool, kind string)
}

// bodyGate decides whether the body must be buffered/inspected for this request,
// based on the policy and its engines, and whether the WAF stage runs. Engines
// come from the resolved policy (tx.Policy.Engines), so different domains/routes
// can run different engines.
type bodyGate struct{}

// BodyGate returns the body-gating stage.
func BodyGate() pipeline.Stage { return bodyGate{} }

func (bodyGate) Name() string          { return "body_gate" }
func (bodyGate) Phase() pipeline.Phase { return pipeline.PhaseBodyGate }

func (bodyGate) Process(_ context.Context, tx *pipeline.Transaction) pipeline.StageResult {
	p := tx.Policy
	if p == nil || !p.Enforcing() {
		return pipeline.Continue()
	}
	inspect := p.InspectRequestBody
	if tx.Direction == pipeline.DirectionResponse {
		inspect = p.InspectResponseBody
	}
	if p.Engines.RequiresBody() {
		inspect = true
	}
	tx.SetBodyRequired(inspect)
	// Only the body-phase WAF stage is gated here: header-only engines (e.g. JWT)
	// already ran at header time, so a policy with no body engines never buffers
	// the body just to run the WAF.
	tx.SetWAFEnabled(p.Engines.RequiresBody())
	return pipeline.Continue()
}

// bodyTruncationGuard is a STRUCTURAL body-phase stage that the catalog always
// prepends to the body inspect pipeline. It blocks a request whose body exceeded
// the size cap (was truncated), so an over-limit body is never inspected as
// clean. Unlike the body_checks size check, it is NOT reorderable and honors no
// skip list — an enforcing policy cannot opt out of it, closing the bypass where
// padding a payload past max_request_body_bytes hides it from the WAF.
type bodyTruncationGuard struct{}

// BodyTruncationGuard returns the structural truncation guard stage.
func BodyTruncationGuard() pipeline.Stage { return bodyTruncationGuard{} }

func (bodyTruncationGuard) Name() string          { return "body_truncation_guard" }
func (bodyTruncationGuard) Phase() pipeline.Phase { return pipeline.PhaseBody }

func (bodyTruncationGuard) Process(_ context.Context, tx *pipeline.Transaction) pipeline.StageResult {
	p := tx.Policy
	if p == nil || !p.Enforcing() {
		return pipeline.Continue()
	}
	if tx.BodyTruncated() {
		return deny(tx, "body.too_large", "body exceeded maximum size (truncated; not fully inspected)", decision.SeverityMedium)
	}
	return pipeline.Continue()
}

// bodyChecks runs the native body inspections: JSON validity and the
// sensitive-data hook. It only runs when the body phase is gated on.
type bodyChecks struct {
	detector SensitiveDataDetector
}

// BodyChecks returns the body-checks stage. detector may be nil to disable
// sensitive-data detection.
func BodyChecks(detector SensitiveDataDetector) pipeline.Stage {
	return &bodyChecks{detector: detector}
}

func (*bodyChecks) Name() string          { return config.StageBodyChecks }
func (*bodyChecks) Phase() pipeline.Phase { return pipeline.PhaseBody }

func (b *bodyChecks) Process(ctx context.Context, tx *pipeline.Transaction) pipeline.StageResult {
	p := tx.Policy
	if p == nil || !p.Enforcing() {
		return pipeline.Continue()
	}
	// Body truncation (over-limit) is enforced by the structural
	// bodyTruncationGuard (always prepended, non-skippable), not here.

	body := tx.Body()
	c := p.Checks

	if c.RequireJSON && !p.SkipsCheck(CheckJSON) && len(body) > 0 {
		// require_json means the endpoint only accepts JSON. Enforce it on BOTH the
		// declared content-type AND the bytes, so an attacker can't dodge JSON
		// validation by sending JSON-shaped (or any) bytes under a non-JSON
		// content-type (content-type juggling) — a backend that parses by shape
		// would still see it. A non-JSON content-type with a body is rejected; a
		// JSON content-type with invalid JSON is rejected.
		if !isJSONContentType(tx.ContentType) {
			return deny(tx, "body.unexpected_content_type",
				"non-JSON content-type on a JSON-only endpoint", decision.SeverityMedium)
		}
		if !json.Valid(body) {
			return deny(tx, "body.invalid_json", "body is not valid JSON", decision.SeverityMedium)
		}
	}

	if c.DetectSensitiveData && b.detector != nil && !p.SkipsCheck(CheckSensitiveData) {
		if found, kind := b.detector.Scan(ctx, tx.ContentType, body); found {
			return deny(tx, "body.sensitive_data", "sensitive data detected: "+kind, decision.SeverityHigh)
		}
	}

	return pipeline.Continue()
}

// isJSONContentType reports whether the media type denotes JSON
// (e.g. application/json or application/vnd.api+json). It parses the full media
// type (via mime.ParseMediaType) so stacked or malformed parameters
// ("application/json; charset=utf-8; charset=utf-7") can't change the verdict;
// a media type that fails to parse is treated as non-JSON.
func isJSONContentType(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		// Fall back to the part before the first ';' for lenient inputs that
		// ParseMediaType rejects but a browser/backend would accept.
		if i := strings.IndexByte(ct, ';'); i >= 0 {
			mediaType = ct[:i]
		} else {
			mediaType = ct
		}
		mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	}
	_, sub, ok := strings.Cut(mediaType, "/")
	if !ok {
		return false
	}
	return sub == "json" || strings.HasSuffix(sub, "+json")
}
