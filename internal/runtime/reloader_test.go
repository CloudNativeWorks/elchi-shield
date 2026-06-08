package runtime

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func validDoc(host string) string {
	return `apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: ` + host + `
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
    - host: a.com
      routes:
        - match: {path_regex: "([bad"}
          policy: {mode: block}
`

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReloaderAppliesUnchangedAndKeepsLastGood(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.yaml", validDoc("api.example.com"))

	store := NewStore(EmptySnapshot(time.Unix(0, 0)))
	r := NewReloader(store, dir, func() time.Time { return time.Unix(0, 0) })

	// First load applies.
	out, snap, err := r.Reload()
	if err != nil || out != OutcomeApplied {
		t.Fatalf("first reload: out=%v err=%v", out, err)
	}
	good := snap.Version()
	if store.Load().Version() != good {
		t.Fatal("store should hold the applied snapshot")
	}

	// Re-reading identical config is a no-op.
	if out, _, _ := r.Reload(); out != OutcomeUnchanged {
		t.Fatalf("identical config should be unchanged, got %v", out)
	}

	// An invalid edit must NOT disturb the active snapshot.
	write(t, dir, "a.yaml", invalidDoc)
	out, _, err = r.Reload()
	if out != OutcomeFailed || err == nil {
		t.Fatalf("invalid config should fail: out=%v err=%v", out, err)
	}
	if store.Load().Version() != good {
		t.Fatal("failed reload must keep last-good snapshot active")
	}

	// Restoring valid config applies again.
	write(t, dir, "a.yaml", validDoc("api2.example.com"))
	if out, _, _ := r.Reload(); out != OutcomeApplied {
		t.Fatalf("valid edit should apply, got %v", out)
	}
	if store.Load().Version() == good {
		t.Fatal("new config should change the active version")
	}
}

func TestReloaderEmptyDirKeepsCurrent(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.yaml", validDoc("api.example.com"))
	store := NewStore(EmptySnapshot(time.Unix(0, 0)))
	r := NewReloader(store, dir, func() time.Time { return time.Unix(0, 0) })
	r.Reload()
	good := store.Load().Version()

	// Remove all config files → keep last good.
	if err := os.Remove(filepath.Join(dir, "a.yaml")); err != nil {
		t.Fatal(err)
	}
	out, _, err := r.Reload()
	if out != OutcomeEmpty || err != nil {
		t.Fatalf("empty dir: out=%v err=%v", out, err)
	}
	if store.Load().Version() != good {
		t.Fatal("emptied dir must keep last-good snapshot")
	}
}
