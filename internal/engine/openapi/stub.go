//go:build !openapi

package openapi

import (
	"fmt"

	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

// New returns ErrNotImplemented: the OpenAPI validation engine is only available
// in a binary built with the `openapi` build tag. Configuring it without the tag
// aborts the config reload (last-good stays active).
func New(_ Config) (engine.SecurityEngine, error) {
	return nil, fmt.Errorf("openapi engine requires the 'openapi' build tag: %w", engine.ErrNotImplemented)
}
