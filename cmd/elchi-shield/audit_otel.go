//go:build otel

package main

// Side-effect import: registers the OTEL audit exporter. Built only with the
// `otel` build tag.
import _ "github.com/cloudnativeworks/elchi-shield/internal/audit/otel"
