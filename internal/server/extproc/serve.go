package extproc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/cloudnativeworks/elchi-shield/internal/logging"
)

// DefaultMaxConcurrentStreams raises gRPC-Go's conservative default of 100
// streams per HTTP/2 connection. Envoy is a local, trusted peer, so the
// rapid-reset protection that motivates the low default does not apply; a higher
// limit prevents a busy listener queueing its own concurrent requests. It is
// bounded (not effectively-infinite) because each stream is a goroutine and may
// buffer a body — the real memory backstop is the global body budget, but the
// stream ceiling still caps goroutine/CPU fan-out.
const DefaultMaxConcurrentStreams = 8192

// serverOptions returns the tuned gRPC options shared by every ext_proc server.
func serverOptions(maxStreams uint32) []grpc.ServerOption {
	if maxStreams == 0 {
		maxStreams = DefaultMaxConcurrentStreams
	}
	return []grpc.ServerOption{
		grpc.MaxConcurrentStreams(maxStreams),
		// A bounded stream-worker pool (sized to CPUs) reuses goroutines/stacks
		// instead of spawning one goroutine per stream, cutting per-request churn.
		grpc.NumStreamWorkers(uint32(runtime.GOMAXPROCS(0))),
		grpc.SharedWriteBuffer(true), // reuse write buffers, fewer allocations
		// Larger HTTP/2 windows: ext_proc exchanges several small messages per
		// stream; bigger windows avoid mid-request WINDOW_UPDATE round-trips, and a
		// larger socket read buffer cuts read(2) syscalls. Memory cost is small (one
		// Envoy connection; streams are mostly blocked on Recv).
		grpc.InitialWindowSize(512 * 1024),  // 512 KiB per stream
		grpc.InitialConnWindowSize(2 << 20), // 2 MiB per connection
		grpc.ReadBufferSize(128 * 1024),     // 128 KiB socket read buffer
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true, // Envoy may ping on idle connections
		}),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
			// Cycle long-lived Envoy connections so per-connection resource accrual
			// is bounded and the process can rebalance; Envoy reconnects gracefully.
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 1 * time.Minute,
		}),
	}
}

// Server hosts the ext_proc gRPC service on a local listener (UDS preferred, or
// loopback TCP). It owns the gRPC server lifecycle and graceful shutdown.
type Server struct {
	grpc    *grpc.Server
	network string
	addr    string
	log     *slog.Logger
}

// NewServer registers proc on a new, tuned gRPC server. network is "unix" or
// "tcp". maxStreams of 0 uses DefaultMaxConcurrentStreams. Extra opts override
// the defaults.
func NewServer(proc *Processor, network, addr string, maxStreams uint32, log *slog.Logger, opts ...grpc.ServerOption) *Server {
	gs := grpc.NewServer(append(serverOptions(maxStreams), opts...)...)
	extprocv3.RegisterExternalProcessorServer(gs, proc)
	return &Server{grpc: gs, network: network, addr: addr, log: log}
}

// listen opens the listener, cleaning up a stale unix socket and tightening its
// permissions so only local, authorized peers can connect.
func (s *Server) listen() (net.Listener, error) {
	if s.network == "unix" {
		if err := os.Remove(s.addr); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("remove stale socket %q: %w", s.addr, err)
		}
	}
	ln, err := net.Listen(s.network, s.addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s %q: %w", s.network, s.addr, err)
	}
	if s.network == "unix" {
		if err := os.Chmod(s.addr, 0o660); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("chmod socket %q: %w", s.addr, err)
		}
	}
	return ln, nil
}

// Start binds the listener (returning any bind error synchronously) and serves
// in a background goroutine. It does not block, so callers can start several
// listeners and fail fast on the first that cannot bind.
func (s *Server) Start() error {
	ln, err := s.listen()
	if err != nil {
		return err
	}
	if s.log != nil {
		s.log.Info("ext_proc server listening", "network", s.network, "addr", s.addr)
	}
	go func() {
		if err := s.grpc.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) && s.log != nil {
			s.log.Error("ext_proc server stopped", "addr", s.addr, logging.Err(err))
		}
	}()
	return nil
}

// Shutdown gracefully drains in-flight streams, falling back to a hard stop if
// ctx is cancelled first.
func (s *Server) Shutdown(ctx context.Context) {
	done := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		s.grpc.Stop()
	}
}
