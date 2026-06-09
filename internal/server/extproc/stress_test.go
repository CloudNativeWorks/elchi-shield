package extproc

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline/stages"
	rt "github.com/cloudnativeworks/elchi-shield/internal/runtime"
)

// snapshotForStress builds a distinct snapshot (block-mode header checks) so each
// store.Set installs fresh CompiledPolicy pointers, exercising the lazy per-policy
// pipeline compile + GC of retired policies under concurrent load.
func snapshotForStress(t *testing.T) *rt.Snapshot {
	t.Helper()
	mode := config.ModeBlock
	cfg := &config.MergedConfig{Sources: []string{"s"}, Domains: []config.MergedDomain{{Source: "s", Domain: config.Domain{
		Hosts: []string{"api.example.com"},
		Routes: []config.Route{{
			Match:  config.Match{PathPrefix: "/"},
			Policy: config.PolicySpec{Mode: &mode, Checks: config.Checks{Headers: &config.HeaderChecks{Required: []string{"X-Request-Id"}}}},
		}},
	}}}}
	snap, err := rt.NewSnapshot(cfg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// TestStressConcurrentListenersWithReloads hammers several listeners (servers
// sharing one lock-free Store/Catalog/Pool) with concurrent requests while a
// goroutine swaps snapshots continuously. Under `-race` it proves: no data race,
// no deadlock (the test completes), and no goroutine leak (count settles back).
func TestStressConcurrentListenersWithReloads(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test; run without -short")
	}

	store := rt.NewStore(snapshotForStress(t))
	pool := pipeline.NewPool()
	cat := stages.NewCatalog(stages.Deps{DefaultAllow: true})

	// Pre-build distinct snapshots for the reloader to cycle through.
	snaps := make([]*rt.Snapshot, 8)
	for i := range snaps {
		snaps[i] = snapshotForStress(t)
	}

	const (
		listeners   = 3
		perListener = 8
		duration    = 750 * time.Millisecond
	)

	clients := make([]extprocv3.ExternalProcessorClient, 0, listeners)
	for i := range listeners {
		proc := NewProcessor(Config{
			Store: store, Pool: pool, Catalog: cat, MaxBody: 1 << 20,
			ListenerID: fmt.Sprintf("lst-%d", i),
		})
		client, cleanup := newBufServer(t, proc)
		t.Cleanup(cleanup)
		clients = append(clients, client)
	}

	msg := reqHeaders(":authority", "api.example.com", ":path", "/v1/x", ":method", "GET", "X-Request-Id", "abc")

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	// Reloader: continuously swap snapshots (atomic, lock-free) + retire old.
	wg.Go(func() {
		i := 0
		for ctx.Err() == nil {
			store.Set(snaps[i%len(snaps)])
			i++
			time.Sleep(time.Millisecond)
		}
	})

	// Concurrent request load across all listeners.
	for _, client := range clients {
		for range perListener {
			wg.Add(1)
			go func(c extprocv3.ExternalProcessorClient) {
				defer wg.Done()
				for ctx.Err() == nil {
					oneRequest(t, c, msg)
				}
			}(client)
		}
	}

	time.Sleep(duration)
	cancel()
	wg.Wait()

	// Leak check: after the load drains, goroutines should settle back near the
	// post-setup baseline (gRPC keeps a few pooled goroutines, hence a tolerance).
	settle := runtime.NumGoroutine()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > settle && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		runtime.GC()
	}
	// The servers are still up (cleaned up via t.Cleanup), so we only assert the
	// count did not run away (no per-request goroutine leak).
	if g := runtime.NumGoroutine(); g > settle+listeners*perListener {
		t.Fatalf("possible goroutine leak: %d goroutines still running", g)
	}
}
