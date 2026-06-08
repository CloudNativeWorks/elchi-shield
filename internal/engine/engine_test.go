package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
)

type fakeEngine struct {
	name         string
	requiresBody bool
	verdict      decision.Verdict
	err          error
}

func (f *fakeEngine) Name() string       { return f.name }
func (f *fakeEngine) RequiresBody() bool { return f.requiresBody }
func (f *fakeEngine) Close() error       { return nil }
func (f *fakeEngine) Inspect(context.Context, *Request) (decision.Verdict, error) {
	return f.verdict, f.err
}

func TestSetMostSevereWins(t *testing.T) {
	set := NewSet(
		&fakeEngine{name: "a", verdict: decision.Verdict{Action: decision.Continue}},
		&fakeEngine{name: "b", verdict: decision.Verdict{Action: decision.Block, Severity: decision.SeverityHigh, RuleID: "r1"}},
		&fakeEngine{name: "c", verdict: decision.Verdict{Action: decision.Block, Severity: decision.SeverityLow, RuleID: "r2"}},
	)
	v, err := set.Inspect(context.Background(), &Request{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if v.Action != decision.Block || v.Severity != decision.SeverityHigh || v.RuleID != "r1" {
		t.Fatalf("most severe block should win: %+v", v)
	}
}

func TestSetBlockBeatsError(t *testing.T) {
	set := NewSet(
		&fakeEngine{name: "err", err: errors.New("boom")},
		&fakeEngine{name: "block", verdict: decision.Verdict{Action: decision.Block, Severity: decision.SeverityCritical}},
	)
	v, err := set.Inspect(context.Background(), &Request{})
	if v.Action != decision.Block {
		t.Fatalf("block verdict should be reported: %+v", v)
	}
	if err == nil {
		t.Fatal("engine error should still be surfaced")
	}
}

func TestSetRequiresBody(t *testing.T) {
	noBody := NewSet(&fakeEngine{name: "h"})
	if noBody.RequiresBody() {
		t.Fatal("no engine requires body")
	}
	withBody := NewSet(&fakeEngine{name: "h"}, &fakeEngine{name: "b", requiresBody: true})
	if !withBody.RequiresBody() {
		t.Fatal("one engine requires body → set requires body")
	}
}

func TestEmptySetIsNoOp(t *testing.T) {
	var set *Set
	if set.Len() != 0 || set.RequiresBody() {
		t.Fatal("nil set should be empty")
	}
	v, err := NewSet().Inspect(context.Background(), &Request{})
	if err != nil || v.Action == decision.Block {
		t.Fatalf("empty set should not block: %+v %v", v, err)
	}
}

func TestCorazaNotBuilt(t *testing.T) {
	// Without the `coraza` build tag the factory is unregistered.
	if corazaFactory != nil {
		t.Skip("coraza adapter is built in")
	}
	if _, err := NewCoraza(CorazaConfig{}); !errors.Is(err, ErrNotImplemented) {
		t.Error("Coraza should be ErrNotImplemented without the build tag")
	}
}

func TestInspectSumsScores(t *testing.T) {
	set := NewSet(
		&fakeEngine{name: "a", verdict: decision.Verdict{Action: decision.Continue, Score: 30}},
		&fakeEngine{name: "b", verdict: decision.Verdict{Action: decision.Continue, Score: 50}},
		&fakeEngine{name: "c", verdict: decision.Verdict{Action: decision.Continue}},
	)
	v, err := set.InspectHeaderPhase(context.Background(), &Request{Direction: DirectionRequest})
	if err != nil {
		t.Fatal(err)
	}
	if v.Score != 80 {
		t.Fatalf("scores should sum to 80, got %d", v.Score)
	}
	if v.Action == decision.Block {
		t.Fatal("non-blocking scoring engines should not produce a block verdict")
	}
}
