//go:build !httpsig

package httpsig

import (
	"fmt"

	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

// New returns ErrNotImplemented: the RFC 9421 engine is only available in a
// binary built with the `httpsig` build tag. Configuring it on a binary without
// the tag aborts the config reload with a clear error (last-good stays active).
func New(_ Config) (engine.SecurityEngine, error) {
	return nil, fmt.Errorf("http_signature engine requires the 'httpsig' build tag: %w", engine.ErrNotImplemented)
}
