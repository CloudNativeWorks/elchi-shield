//go:build coraza

package main

// Importing the adapter for its side effect (init registers the Coraza factory)
// makes `engines.coraza` policies usable in this binary. Built only with the
// `coraza` build tag: go build -tags coraza ./cmd/elchi-shield
import _ "github.com/cloudnativeworks/elchi-shield/internal/engine/coraza"
