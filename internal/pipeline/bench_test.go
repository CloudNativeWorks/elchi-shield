package pipeline

import (
	"context"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
)

// benchStage is a minimal continue stage with no per-call allocation.
func benchStage(name string, phase Phase) Stage {
	return NewStageFunc(name, phase, func(_ context.Context, _ *Transaction) StageResult {
		return Continue()
	})
}

func buildBenchPipeline(b *testing.B, n int) *Pipeline {
	b.Helper()
	stages := make([]Stage, 0, n)
	for range n {
		stages = append(stages, benchStage("s", PhasePreCheck))
	}
	p, err := New("bench", stages, nil)
	if err != nil {
		b.Fatal(err)
	}
	return p
}

// BenchmarkRunContinue measures the hot-path continue chain. The Transaction is
// reused (as it is in production via the pool), so the only allocation should be
// the single returned *Decision per run.
func BenchmarkRunContinue(b *testing.B) {
	for _, n := range []int{1, 4, 9} {
		p := buildBenchPipeline(b, n)
		tx := &Transaction{Policy: pol(config.ModeBlock, config.FailOpen)}
		ctx := context.Background()
		b.Run(name(n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = p.Run(ctx, tx)
			}
		})
	}
}

// BenchmarkRunGatedSkip measures the path where body/WAF stages are gated off —
// the executor must skip them cheaply.
func BenchmarkRunGatedSkip(b *testing.B) {
	stages := []Stage{
		benchStage("pre", PhasePreCheck),
		benchStage("body", PhaseBody), // gated off (bodyRequired=false)
		benchStage("waf", PhaseWAF),   // gated off (wafEnabled=false)
		benchStage("final", PhaseFinal),
	}
	p, err := New("bench", stages, nil)
	if err != nil {
		b.Fatal(err)
	}
	tx := &Transaction{Policy: pol(config.ModeBlock, config.FailOpen)}
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = p.Run(ctx, tx)
	}
}

// BenchmarkPoolAcquireRelease measures Transaction recycling cost.
func BenchmarkPoolAcquireRelease(b *testing.B) {
	pool := NewPool()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tx := pool.Acquire()
		tx.Host = "api.example.com"
		pool.Release(tx)
	}
}

func name(n int) string {
	switch n {
	case 1:
		return "1stage"
	case 4:
		return "4stages"
	default:
		return "9stages"
	}
}

// BenchmarkHeaderLookup measures Transaction.Header (linear scan) at a realistic
// header count, with the target header last (worst case).
func BenchmarkHeaderLookup(b *testing.B) {
	tx := &Transaction{}
	for i := range 30 {
		tx.Headers = append(tx.Headers, Header{Name: "x-pad-" + string(rune('a'+i)), Value: "v"})
	}
	tx.Headers = append(tx.Headers, Header{Name: "content-type", Value: "application/json"})
	b.ReportAllocs()
	for b.Loop() {
		_, _ = tx.Header("content-type")
	}
}
