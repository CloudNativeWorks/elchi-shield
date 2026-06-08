package pipeline

import (
	"context"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
)

// TestHotPathZeroAlloc machine-checks the "0-alloc hot path" invariant
// so a regression fails a normal `go test` run (no benchmark inspection needed).
// It uses testing.AllocsPerRun, which is deterministic for these paths.
func TestHotPathZeroAlloc(t *testing.T) {
	t.Run("pipeline_run_continue", func(t *testing.T) {
		p := mustBenchPipeline(t, 9)
		tx := &Transaction{Policy: pol(config.ModeBlock, config.FailOpen)}
		ctx := context.Background()
		if got := testing.AllocsPerRun(200, func() { _ = p.Run(ctx, tx) }); got != 0 {
			t.Fatalf("Pipeline.Run (continue) must be 0 allocs/op, got %v", got)
		}
	})

	t.Run("pool_acquire_release", func(t *testing.T) {
		pool := NewPool()
		if got := testing.AllocsPerRun(200, func() {
			tx := pool.Acquire()
			tx.Host = "api.example.com"
			pool.Release(tx)
		}); got != 0 {
			t.Fatalf("Pool Acquire/Release must be 0 allocs/op, got %v", got)
		}
	})
}

func mustBenchPipeline(t *testing.T, n int) *Pipeline {
	t.Helper()
	stages := make([]Stage, 0, n)
	for i := 0; i < n; i++ {
		stages = append(stages, benchStage("s", PhasePreCheck))
	}
	p, err := New("alloc", stages, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
