package main

// Importing the adapter for its side effect (init registers the Coraza factory)
// makes `engines.coraza` policies usable in this binary. This blank import is
// always compiled, so the Coraza factory is always registered.
import _ "github.com/cloudnativeworks/elchi-shield/internal/engine/coraza"
