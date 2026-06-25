package metricsotlp

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestStartAndShutdown proves the push pipeline builds over a registry and tears
// down cleanly, without a live collector (the gRPC dial is lazy). A long
// interval keeps any export from firing during the test.
func TestStartAndShutdown(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_total", Help: "t"})
	reg.MustRegister(c)
	c.Inc()

	shutdown, err := Start(context.Background(), reg, Options{
		Endpoint: "127.0.0.1:4317",
		Insecure: true,
		Interval: time.Hour, // never fires during the test
		Instance: "host-shield",
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if shutdown == nil {
		t.Fatal("Start returned a nil shutdown func")
	}
	// Shutdown attempts a final flush; with no collector it errors, which is
	// expected (in production it's just logged). The contract under test is that
	// the pipeline builds and tears down promptly without hanging or panicking.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = shutdown(ctx)
}
