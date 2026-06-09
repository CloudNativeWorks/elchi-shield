// Package otel is an audit Exporter that emits events as OpenTelemetry logs over
// OTLP/HTTP. It is always compiled into the binary and registers itself with the
// audit package on init, so `--audit-exporter otel` is available.
package otel

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	"github.com/cloudnativeworks/elchi-shield/internal/audit"
	"github.com/cloudnativeworks/elchi-shield/internal/decision"
)

const scopeName = "elchi-shield"

func init() {
	audit.RegisterExporter("otel", func(opts audit.ExporterOptions) (audit.Exporter, error) {
		return New(opts)
	})
}

// Exporter emits audit events as OTEL log records through a batching provider.
type Exporter struct {
	provider *sdklog.LoggerProvider
	logger   otellog.Logger
}

// New builds the OTLP/HTTP log exporter and a batching logger provider.
func New(opts audit.ExporterOptions) (*Exporter, error) {
	httpOpts := []otlploghttp.Option{}
	if opts.Endpoint != "" {
		httpOpts = append(httpOpts, otlploghttp.WithEndpoint(opts.Endpoint))
	}
	if opts.Insecure {
		httpOpts = append(httpOpts, otlploghttp.WithInsecure())
	}
	exp, err := otlploghttp.New(context.Background(), httpOpts...)
	if err != nil {
		return nil, fmt.Errorf("otel: build exporter: %w", err)
	}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)))
	return &Exporter{provider: provider, logger: provider.Logger(scopeName)}, nil
}

// Export emits one event as an OTEL log record.
func (e *Exporter) Export(ctx context.Context, ev *audit.Event) error {
	d := ev.Decision
	var r otellog.Record
	r.SetTimestamp(ev.Timestamp)
	r.SetBody(otellog.StringValue("security decision: " + d.Action.String()))
	r.SetSeverity(severity(d.Severity))
	r.SetSeverityText(d.Severity.String())
	r.AddAttributes(
		otellog.String("instance", ev.Instance),
		otellog.String("request_id", ev.RequestID),
		otellog.String("phase", ev.Phase),
		otellog.String("direction", ev.Direction),
		otellog.String("action", d.Action.String()),
		otellog.String("reason", d.Reason),
		otellog.String("rule_id", d.RuleID),
		otellog.String("policy_id", d.PolicyID),
		otellog.String("engine", d.Engine),
		otellog.String("host", ev.Host),
		otellog.String("path", ev.Path),
		otellog.String("method", ev.Method),
		otellog.String("config_version", ev.ConfigVersion),
	)
	e.logger.Emit(ctx, r)
	return nil
}

// Flush forces the batch processor to export buffered records.
func (e *Exporter) Flush(ctx context.Context) error { return e.provider.ForceFlush(ctx) }

// Close shuts down the provider (flushing and releasing resources).
func (e *Exporter) Close() error { return e.provider.Shutdown(context.Background()) }

// severity maps our severity to an OTEL severity number.
func severity(s decision.Severity) otellog.Severity {
	switch s {
	case decision.SeverityCritical:
		return otellog.SeverityFatal1
	case decision.SeverityHigh:
		return otellog.SeverityError1
	case decision.SeverityMedium:
		return otellog.SeverityWarn1
	case decision.SeverityLow, decision.SeverityInfo:
		return otellog.SeverityInfo1
	default:
		return otellog.SeverityTrace1
	}
}
