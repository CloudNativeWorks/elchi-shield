package runtime

import (
	"testing"
	"time"
)

func TestReloadStatus(t *testing.T) {
	s := NewReloadStatus()

	// Empty: no error, no failures.
	if e, n, _ := s.Snapshot(); e != "" || n != 0 {
		t.Fatalf("empty snapshot = %q,%d; want '',0", e, n)
	}

	at := time.Unix(1000, 0)
	s.RecordFailure("api.yaml: secret must be at least 64 bytes", at)
	if e, n, fa := s.Snapshot(); e == "" || n != 1 || !fa.Equal(at) {
		t.Fatalf("after failure = %q,%d,%v", e, n, fa)
	}

	// A second failure advances the count and updates the reason.
	s.RecordFailure("api.yaml: invalid regex", time.Unix(2000, 0))
	if e, n, _ := s.Snapshot(); e != "api.yaml: invalid regex" || n != 2 {
		t.Fatalf("second failure = %q,%d; want 'invalid regex',2", e, n)
	}

	// Success clears the error but keeps the failure history.
	s.RecordSuccess()
	if e, n, _ := s.Snapshot(); e != "" || n != 2 {
		t.Fatalf("after success = %q,%d; want '',2", e, n)
	}
}
