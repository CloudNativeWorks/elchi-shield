package runtime

import (
	"sync"
	"testing"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
)

func cfg(host string) *config.MergedConfig {
	return &config.MergedConfig{
		Domains: []config.MergedDomain{{Domain: config.Domain{Host: host}, Source: "a.yaml"}},
		Sources: []string{"a.yaml"},
	}
}

func TestNewSnapshotHashStableAndDistinct(t *testing.T) {
	now := time.Unix(0, 0)
	s1, err := NewSnapshot(cfg("a.com"), now)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewSnapshot(cfg("a.com"), now)
	if err != nil {
		t.Fatal(err)
	}
	if s1.Hash() != s2.Hash() {
		t.Fatalf("identical config should hash equal: %s vs %s", s1.Hash(), s2.Hash())
	}
	if s1.Version() != s1.Hash()[:versionLen] {
		t.Fatalf("version should be hash prefix: %s vs %s", s1.Version(), s1.Hash())
	}

	s3, _ := NewSnapshot(cfg("b.com"), now)
	if s1.Hash() == s3.Hash() {
		t.Fatal("different config should hash differently")
	}
}

func TestEmptySnapshot(t *testing.T) {
	s := EmptySnapshot(time.Now())
	if !s.IsEmpty() {
		t.Fatal("EmptySnapshot should report IsEmpty")
	}
	if s.DomainCount() != 0 {
		t.Fatalf("empty domain count: %d", s.DomainCount())
	}
	if s.Version() != emptyVersion {
		t.Fatalf("empty version: %s", s.Version())
	}
}

func TestStoreNeverNilAndAtomicSwap(t *testing.T) {
	store := NewStore(nil)
	if store.Load() == nil {
		t.Fatal("Load must never return nil")
	}
	if !store.Load().IsEmpty() {
		t.Fatal("nil-seeded store should hold empty snapshot")
	}

	snap, _ := NewSnapshot(cfg("a.com"), time.Now())
	store.Set(snap)
	if store.Load().Version() != snap.Version() {
		t.Fatal("Set should install new snapshot")
	}

	// nil Set is a no-op (invariant: active snapshot always exists).
	store.Set(nil)
	if store.Load().Version() != snap.Version() {
		t.Fatal("nil Set must not clear active snapshot")
	}
}

// TestStoreKeepLastGood models the reload contract: a failed reload must not
// disturb the active snapshot. We only swap on success, so when a reload fails
// (and therefore does not call Set) Load keeps returning the previous snapshot.
func TestStoreKeepLastGood(t *testing.T) {
	good, _ := NewSnapshot(cfg("good.com"), time.Now())
	store := NewStore(good)

	// A failed reload never calls Set, so the active snapshot is unchanged.
	if store.Load().Version() != good.Version() {
		t.Fatal("failed reload must keep last good snapshot active")
	}
}

func TestStoreConcurrentReadsDuringSwap(t *testing.T) {
	store := NewStore(EmptySnapshot(time.Now()))
	var wg sync.WaitGroup

	// Writers swapping snapshots.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				snap, _ := NewSnapshot(cfg("h.com"), time.Now())
				store.Set(snap)
			}
		}(i)
	}
	// Readers loading concurrently — must never see nil, never tear.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				if s := store.Load(); s == nil {
					t.Error("Load returned nil during swap")
					return
				}
			}
		}()
	}
	wg.Wait()
}
