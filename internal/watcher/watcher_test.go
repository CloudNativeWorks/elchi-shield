package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/runtime"
)

func validDoc(host string) string {
	return `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - hosts: ["` + host + `"]
      routes:
        - match: {path_prefix: /v1/}
          policy: {mode: block}
`
}

const invalidDoc = `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - hosts: ["a.com"]
      routes:
        - match: {path_regex: "([bad"}
          policy: {mode: block}
`

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// waitFor polls cond until true or the deadline, failing the test on timeout.
func waitFor(t *testing.T, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", msg)
}

func startWatcher(t *testing.T, dir string, r *runtime.Reloader) {
	t.Helper()
	w, err := New(dir, 50*time.Millisecond, func() { _, _, _ = r.Reload() }, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = w.Run(ctx) }()
	// Give fsnotify time to register the directory before edits.
	time.Sleep(100 * time.Millisecond)
}

func TestWatcherAppliesNewConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", validDoc("api.example.com"))

	store := runtime.NewStore(runtime.EmptySnapshot(time.Now()))
	r := runtime.NewReloader(store, dir, time.Now)
	if _, _, err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	v0 := store.Load().Version()

	startWatcher(t, dir, r)

	writeFile(t, dir, "b.yaml", validDoc("b.example.com"))
	waitFor(t, "active version to change after new file", func() bool {
		return store.Load().Version() != v0
	})
}

// TestWatcherWaitsForMissingDir proves the watcher starts even when the config
// directory does not exist yet, then picks up config once the dir appears — it
// must not hard-fail at startup.
func TestWatcherWaitsForMissingDir(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "elchi-shield") // does not exist yet

	store := runtime.NewStore(runtime.EmptySnapshot(time.Now()))
	r := runtime.NewReloader(store, dir, time.Now)
	v0 := store.Load().Version()

	w, err := New(dir, 50*time.Millisecond, func() { _, _, _ = r.Reload() }, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()

	// The watcher should be waiting, not have returned an error.
	select {
	case err := <-errCh:
		t.Fatalf("watcher returned early before dir existed: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	// Create the directory and drop a config in; the watcher must self-heal and
	// apply it.
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "a.yaml", validDoc("api.example.com"))
	waitFor(t, "config applied after dir appears", func() bool {
		return store.Load().Version() != v0
	})
}

func TestWatcherKeepsLastGoodOnInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", validDoc("api.example.com"))

	store := runtime.NewStore(runtime.EmptySnapshot(time.Now()))
	r := runtime.NewReloader(store, dir, time.Now)
	if _, _, err := r.Reload(); err != nil {
		t.Fatal(err)
	}
	good := store.Load().Version()

	startWatcher(t, dir, r)

	// Write an invalid file; the active version must stay the last-good one.
	writeFile(t, dir, "bad.yaml", invalidDoc)
	// Allow the debounced reload to run, then confirm the version is unchanged.
	time.Sleep(400 * time.Millisecond)
	if store.Load().Version() != good {
		t.Fatalf("invalid config must not change active version: %s != %s",
			store.Load().Version(), good)
	}
}
