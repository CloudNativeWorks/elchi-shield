// Package httpsig implements an RFC 9421 (HTTP Message Signatures) verification
// engine. The implementation depends on github.com/yaronf/httpsign and is always
// compiled into the binary. See httpsig.go.
package httpsig

import "time"

// Config configures the RFC 9421 verification engine. The initial supported
// algorithm is hmac-sha256 (shared secret).
type Config struct {
	// Secret is the shared HMAC key.
	Secret string
	// SignatureName is the label expected in Signature-Input (default "sig1").
	SignatureName string
	// CoveredComponents are the message components the signature must cover
	// (default "@method", "@authority", "@path", "@query"). Derived components
	// start with "@"; anything else is a header name. Include "content-digest" to
	// bind the body — the engine then validates the digest against the actual
	// body (not just that the header is signed).
	CoveredComponents []string
	// MaxAge rejects a signature whose `created` parameter is older than this
	// (0 disables the age check).
	MaxAge time.Duration
}
