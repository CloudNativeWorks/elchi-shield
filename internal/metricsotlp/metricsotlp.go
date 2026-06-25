// Package metricsotlp pushes shield's metrics to an OpenTelemetry Collector over
// OTLP/gRPC on an interval — the push/sink model (like Envoy's stats sink),
// instead of being scraped at /metrics. The collector then forwards them on
// (e.g. to VictoriaMetrics), so shield matches the rest of the fleet's pipeline.
//
// It bridges the EXISTING Prometheus registry into an OTLP PeriodicReader via
// the contrib Prometheus bridge, so the hot-path metric instruments are
// untouched: no rewrite, no extra per-request cost, no new allocations on the
// request path. The /metrics scrape endpoint keeps working for local debugging.
package metricsotlp

import (
	"context"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	prombridge "go.opentelemetry.io/contrib/bridges/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
)

// Options configures the OTLP metrics push.
type Options struct {
	Endpoint string        // collector address (OTLP/gRPC host:port); required
	Insecure bool          // plaintext gRPC (no TLS) — typical inside a trusted mesh
	Interval time.Duration // export cadence (default 15s)
	Instance string        // service.instance.id (the <hostname>-shield id)
}

// Start builds the OTLP push pipeline over the given Prometheus registry and
// begins exporting on Options.Interval. It returns a shutdown func (final flush
// + stop) to call on graceful shutdown. The gRPC connection is lazy, so Start
// succeeds even when the collector is momentarily unreachable — exports simply
// retry on the next tick, exactly like Envoy's stats sink (fire-and-forget).
func Start(ctx context.Context, reg *prometheus.Registry, opts Options) (func(context.Context) error, error) {
	if opts.Interval <= 0 {
		opts.Interval = 15 * time.Second
	}
	expOpts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(opts.Endpoint)}
	if opts.Insecure {
		expOpts = append(expOpts, otlpmetricgrpc.WithInsecure())
	}
	exp, err := otlpmetricgrpc.New(ctx, expOpts...)
	if err != nil {
		return nil, fmt.Errorf("metricsotlp: build exporter: %w", err)
	}

	// Identify this sidecar so the collector/VictoriaMetrics can distinguish
	// instances — mirrors the `instance` Prometheus label.
	res := resource.NewSchemaless(
		attribute.String("service.name", "elchi-shield"),
		attribute.String("service.instance.id", opts.Instance),
	)

	// The reader has no instruments of its own; the Prometheus bridge producer
	// supplies every metric by gathering shield's registry each cycle.
	reader := sdkmetric.NewPeriodicReader(exp,
		sdkmetric.WithInterval(opts.Interval),
		sdkmetric.WithProducer(prombridge.NewMetricProducer(prombridge.WithGatherer(reg))),
	)
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(res))
	return mp.Shutdown, nil
}
