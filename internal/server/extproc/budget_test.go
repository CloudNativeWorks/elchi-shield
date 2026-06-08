package extproc

import "testing"

func TestBodyBudgetAcquireRelease(t *testing.T) {
	b := newBodyBudget(100)
	if got := b.Acquire(60); got != 60 {
		t.Fatalf("first acquire = %d, want 60", got)
	}
	if got := b.Acquire(60); got != 40 {
		t.Fatalf("over-budget acquire should grant the remainder 40, got %d", got)
	}
	if got := b.Acquire(1); got != 0 {
		t.Fatalf("exhausted budget should grant 0, got %d", got)
	}
	b.Release(100)
	if got := b.Acquire(80); got != 80 {
		t.Fatalf("after release acquire = %d, want 80", got)
	}
	if b.InUseBytes() != 80 {
		t.Fatalf("inUse = %d, want 80", b.InUseBytes())
	}
}

func TestBodyBudgetDisabled(t *testing.T) {
	var nilB *bodyBudget
	if got := nilB.Acquire(1000); got != 1000 {
		t.Fatalf("nil budget should grant full amount, got %d", got)
	}
	zero := newBodyBudget(0)
	if got := zero.Acquire(1 << 30); got != 1<<30 {
		t.Fatalf("zero-limit budget should be disabled (grant all), got %d", got)
	}
	nilB.Release(10) // must not panic
}
