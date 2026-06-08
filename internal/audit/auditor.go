package audit

import (
	"context"
	"log/slog"
	"math/rand/v2"

	"github.com/cloudnativeworks/elchi-shield/internal/logging"
)

// Auditor emits audit events to an Exporter, isolating callers from export
// errors (which are logged, not propagated onto the request path). It holds no
// mutable state beyond the injected exporter/logger.
type Auditor struct {
	exp Exporter
	log *slog.Logger
}

// NewAuditor wraps exp. If exp is nil, a NopExporter is used so Emit is always
// safe to call.
func NewAuditor(exp Exporter, log *slog.Logger) *Auditor {
	if exp == nil {
		exp = NopExporter{}
	}
	return &Auditor{exp: exp, log: log}
}

// Emit exports ev, logging (never returning) any export error so auditing can
// never break request processing.
func (a *Auditor) Emit(ctx context.Context, ev *Event) {
	if err := a.exp.Export(ctx, ev); err != nil && a.log != nil {
		a.log.Warn("audit export failed", logging.Err(err))
	}
}

// Flush flushes the underlying exporter.
func (a *Auditor) Flush(ctx context.Context) error { return a.exp.Flush(ctx) }

// Close flushes and closes the underlying exporter.
func (a *Auditor) Close() error { return a.exp.Close() }

// Sample reports whether an event should be recorded given a per-policy sampling
// rate. A rate >= 1 always samples; <= 0 never samples; otherwise it samples
// probabilistically. Callers should bypass sampling for block events (always
// audit enforcement actions).
func Sample(rate float64) bool {
	if rate >= 1 {
		return true
	}
	if rate <= 0 {
		return false
	}
	return rand.Float64() < rate
}
