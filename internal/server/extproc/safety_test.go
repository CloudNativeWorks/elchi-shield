package extproc

import (
	"context"
	"testing"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/policy"
)

// panicStream panics in Recv to exercise the Process-level panic recovery.
type panicStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (p panicStream) Context() context.Context                  { return p.ctx }
func (panicStream) Send(*extprocv3.ProcessingResponse) error    { return nil }
func (panicStream) Recv() (*extprocv3.ProcessingRequest, error) { panic("boom in recv") }

func TestProcessRecoversPanic(t *testing.T) {
	pr := buildProcessor(t)
	err := pr.Process(panicStream{ctx: context.Background()})
	if status.Code(err) != codes.Internal {
		t.Fatalf("a panic must be recovered into codes.Internal, got %v", err)
	}
	// The key assertion is simply that we got here — the process did not crash.
}

// TestRunInspectAppliesTimeout verifies the per-policy timeout is wired into the
// inspect context (the executor enforces ctx deadlines; this checks the deadline
// is actually set when policy.Timeout > 0).
func TestRunInspectAppliesTimeout(t *testing.T) {
	pr := buildProcessor(t)

	var sawDeadline bool
	st := pipeline.NewStageFunc("probe", pipeline.PhasePreCheck, func(ctx context.Context, _ *pipeline.Transaction) pipeline.StageResult {
		_, sawDeadline = ctx.Deadline()
		return pipeline.Continue()
	})
	p, err := pipeline.New("probe", []pipeline.Stage{st}, nil)
	if err != nil {
		t.Fatal(err)
	}

	r := config.DefaultPolicy()
	r.Timeout = 50_000_000 // 50ms
	tx := &pipeline.Transaction{Policy: policy.FromResolved("t", r)}

	pr.runInspect(context.Background(), tx, p)
	if !sawDeadline {
		t.Fatal("policy.Timeout should be applied as a context deadline")
	}

	// With Timeout == 0, no deadline is imposed.
	r2 := config.DefaultPolicy()
	r2.Timeout = 0
	tx2 := &pipeline.Transaction{Policy: policy.FromResolved("t", r2)}
	sawDeadline = false
	pr.runInspect(context.Background(), tx2, p)
	if sawDeadline {
		t.Fatal("Timeout==0 should impose no deadline")
	}
}
