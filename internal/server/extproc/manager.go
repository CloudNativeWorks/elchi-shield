package extproc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
)

// ListenerSpec describes one ext_proc listener: an Envoy listener id and the
// local address it is served on.
type ListenerSpec struct {
	ID      string // listener_id stamped on transactions/audit (may be empty)
	Network string // "unix" or "tcp"
	Addr    string // socket path or host:port
}

// Manager runs one ext_proc gRPC server per Envoy listener inside a single
// process. Each server has its own socket, accept loop, and HTTP/2 connections,
// so a busy listener never contends with another at the transport level. All
// servers share the same lock-free Store, Catalog, Pool, Metrics, and Auditor
// (via the base Config), so there is no config duplication and no added locks —
// the only per-listener state is the listener id (and its metrics cursor).
type Manager struct {
	servers []*Server
	log     *slog.Logger
	budget  *bodyBudget
	streams *atomic.Int64 // live in-flight ext_proc streams across all listeners
}

// InFlightStreams reports the number of ext_proc streams currently being served
// across all listeners (for a live gauge).
func (m *Manager) InFlightStreams() int64 { return m.streams.Load() }

// InFlightBodyBytes reports the body bytes currently buffered across all streams.
func (m *Manager) InFlightBodyBytes() int64 { return m.budget.InUseBytes() }

// NewManager builds a Server (and a listener-scoped Processor) per spec from a
// shared base Config. base.ListenerID is ignored; each spec's ID is used.
func NewManager(base Config, specs []ListenerSpec, maxStreams uint32, log *slog.Logger) (*Manager, error) {
	if len(specs) == 0 {
		return nil, errors.New("extproc: at least one listener is required")
	}
	// One shared in-flight body budget and stream counter across every listener so
	// the bounds and gauges are process-wide, not per-listener.
	budget := newBodyBudget(base.MaxInFlightBodyBytes)
	streams := &atomic.Int64{}
	m := &Manager{log: log, budget: budget, streams: streams}
	// Bound a single ext_proc message (a buffered body chunk) to the body cap plus
	// headroom for headers/framing, instead of leaving gRPC's implicit 4 MiB
	// default — a deliberate, documented limit tied to the policy body cap.
	recvOpt := grpc.MaxRecvMsgSize(maxRecvMsgBytes(base.MaxBody))
	for _, s := range specs {
		cfg := base
		cfg.ListenerID = s.ID
		cfg.budget = budget
		cfg.streams = streams
		proc := NewProcessor(cfg)
		m.servers = append(m.servers, NewServer(proc, s.Network, s.Addr, maxStreams, log, recvOpt))
	}
	return m, nil
}

// maxRecvMsgBytes sizes the gRPC receive limit from the body cap plus 1 MiB of
// headroom (headers + framing), with a 4 MiB floor (gRPC's default) so a tiny
// body cap doesn't make legitimate messages fail.
func maxRecvMsgBytes(maxBody int64) int {
	const headroom = 1 << 20
	const floor = 4 << 20
	v := maxBody + headroom
	if v < floor {
		v = floor
	}
	return int(v)
}

// Start binds and serves every listener. It fails fast: if any listener cannot
// bind, already-started servers are stopped and the error is returned.
func (m *Manager) Start() error {
	for i, s := range m.servers {
		if err := s.Start(); err != nil {
			m.stopStarted(i)
			return fmt.Errorf("extproc: start listener %d: %w", i, err)
		}
	}
	return nil
}

// stopStarted hard-stops the first n servers (used to unwind a partial Start).
func (m *Manager) stopStarted(n int) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already-cancelled → Shutdown falls back to immediate Stop
	for i := range n {
		m.servers[i].Shutdown(ctx)
	}
}

// Shutdown gracefully drains every server concurrently.
func (m *Manager) Shutdown(ctx context.Context) {
	var wg sync.WaitGroup
	for _, s := range m.servers {
		wg.Add(1)
		go func(s *Server) {
			defer wg.Done()
			s.Shutdown(ctx)
		}(s)
	}
	wg.Wait()
}
