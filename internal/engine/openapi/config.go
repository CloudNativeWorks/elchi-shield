// Package openapi implements a body-phase positive-security engine: it validates
// each request against an OpenAPI 3.x specification, so only requests that
// conform to the declared contract pass. The real implementation depends on
// github.com/pb33f/libopenapi(-validator) and is compiled only into a binary
// built with the `openapi` build tag; the default lean binary gets a stub whose
// constructor returns engine.ErrNotImplemented (mirroring Coraza/httpsig).
package openapi

// Config configures the OpenAPI validation engine.
type Config struct {
	// SpecFile is the path to the OpenAPI 3.x document (YAML or JSON).
	SpecFile string
	// ValidateRequestBody validates the request body against the operation
	// schema (forces body buffering).
	ValidateRequestBody bool
	// RejectUndeclaredPath blocks a request whose path is not declared in the
	// spec (shadow-endpoint detection).
	RejectUndeclaredPath bool
}
