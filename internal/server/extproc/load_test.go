package extproc

import (
	"context"
	"net"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline/stages"
	"github.com/cloudnativeworks/elchi-shield/internal/runtime"
)

// newBufServer starts the Processor on an in-memory gRPC listener and returns a
// connected client plus a cleanup func. This exercises the real gRPC + ext_proc
// path (serialization, streaming) without a network.
func newBufServer(b testing.TB, pr *Processor) (extprocv3.ExternalProcessorClient, func()) {
	b.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(serverOptions(0)...) // exercise the production tuning
	extprocv3.RegisterExternalProcessorServer(srv, pr)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		b.Fatal(err)
	}
	return extprocv3.NewExternalProcessorClient(conn), func() {
		_ = conn.Close()
		srv.Stop()
	}
}

// benchProcessor builds a Processor over a snapshot compiled from domains.
func benchProcessor(b *testing.B, domains ...config.Domain) *Processor {
	b.Helper()
	md := make([]config.MergedDomain, len(domains))
	for i, d := range domains {
		md[i] = config.MergedDomain{Domain: d, Source: "b"}
	}
	cfg := &config.MergedConfig{Domains: md, Sources: []string{"b"}}
	snap, err := runtime.NewSnapshot(cfg, time.Now())
	if err != nil {
		b.Fatal(err)
	}
	return NewProcessor(Config{
		Store:   runtime.NewStore(snap),
		Pool:    pipeline.NewPool(),
		Catalog: stages.NewCatalog(stages.Deps{DefaultAllow: true}),
		MaxBody: 1 << 20,
	})
}

// oneRequest opens a stream, sends request headers, reads the response, and
// closes — one full ext_proc transaction.
func oneRequest(b testing.TB, client extprocv3.ExternalProcessorClient, hdrs *extprocv3.ProcessingRequest) {
	stream, err := client.Process(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	if err := stream.Send(hdrs); err != nil {
		b.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		b.Fatal(err)
	}
	_ = stream.CloseSend()
}

func reportThroughput(b *testing.B, start time.Time) {
	elapsed := time.Since(start).Seconds()
	if elapsed > 0 {
		b.ReportMetric(float64(b.N)/elapsed, "req/s")
	}
}

// BenchmarkProcessBaseline: no matching policy (default allow) — the pure
// gRPC + pipeline-prelude overhead.
func BenchmarkProcessBaseline(b *testing.B) {
	pr := benchProcessor(b, config.Domain{Host: "api.example.com"})
	client, cleanup := newBufServer(b, pr)
	defer cleanup()
	msg := reqHeaders(":authority", "other.com", ":path", "/x", ":method", "GET")

	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			oneRequest(b, client, msg)
		}
	})
	reportThroughput(b, start)
}

// oneRequestWithBody runs a full body-buffering transaction: headers (no EOS) →
// recv the BUFFERED mode-override → body (EOS) → recv the body decision → close.
func oneRequestWithBody(b testing.TB, client extprocv3.ExternalProcessorClient, hdrs, body *extprocv3.ProcessingRequest) {
	stream, err := client.Process(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	if err := stream.Send(hdrs); err != nil {
		b.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil { // mode override
		b.Fatal(err)
	}
	if err := stream.Send(body); err != nil {
		b.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil { // body decision
		b.Fatal(err)
	}
	_ = stream.CloseSend()
}

// BenchmarkProcessRequestBody: a body-inspecting policy (the built-in
// sensitive-data detector over a buffered request body). Measures the extra cost
// of the BUFFERED mode-override + body round-trip + body scan vs the header path.
func BenchmarkProcessRequestBody(b *testing.B) {
	mode := config.ModeBlock
	yes := true
	pr := benchProcessor(b, config.Domain{Host: "api.example.com", Routes: []config.Route{{
		Match: config.Match{PathPrefix: "/"},
		Policy: config.PolicySpec{
			Mode:               &mode,
			InspectRequestBody: &yes,
			Checks:             config.Checks{Body: &config.BodyChecks{DetectSensitiveData: true}},
		},
	}}})
	client, cleanup := newBufServer(b, pr)
	defer cleanup()
	hdrs := reqHeaders(":authority", "api.example.com", ":path", "/v1/x", ":method", "POST", "content-type", "text/plain")
	body := reqBody("a clean request body with no secrets in it whatsoever", true)

	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			oneRequestWithBody(b, client, hdrs, body)
		}
	})
	reportThroughput(b, start)
}

// BenchmarkProcessHeaderChecks: a block-mode policy running header checks on a
// clean request (allowed) — the common enforced path.
func BenchmarkProcessHeaderChecks(b *testing.B) {
	mode := config.ModeBlock
	pr := benchProcessor(b, config.Domain{Host: "api.example.com", Routes: []config.Route{{
		Match: config.Match{PathPrefix: "/"},
		Policy: config.PolicySpec{Mode: &mode, Checks: config.Checks{Headers: &config.HeaderChecks{
			Forbidden: []string{"X-Debug"}, Required: []string{"X-Request-Id"}, EnforceValidHost: true,
		}}},
	}}})
	client, cleanup := newBufServer(b, pr)
	defer cleanup()
	msg := reqHeaders(":authority", "api.example.com", ":path", "/v1/x", ":method", "GET", "X-Request-Id", "abc")

	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			oneRequest(b, client, msg)
		}
	})
	reportThroughput(b, start)
}
