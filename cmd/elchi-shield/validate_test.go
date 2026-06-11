package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunValidate(t *testing.T) {
	// Usage errors.
	if code := runValidate(nil); code != 2 {
		t.Fatalf("no args: want exit 2, got %d", code)
	}
	if code := runValidate([]string{"a", "b"}); code != 2 {
		t.Fatalf("extra args: want exit 2, got %d", code)
	}

	// Empty directory is valid ("clear").
	empty := t.TempDir()
	if code := runValidate([]string{empty}); code != 0 {
		t.Fatalf("empty dir: want exit 0, got %d", code)
	}

	// A config file with unknown fields (strict decode) is invalid.
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "api.yaml"), []byte("spec:\n  totally_unknown_field: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runValidate([]string{bad}); code != 1 {
		t.Fatalf("invalid config: want exit 1, got %d", code)
	}

	// Malformed YAML is invalid.
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "api.yaml"), []byte("spec: : :\n  - ]["), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runValidate([]string{broken}); code != 1 {
		t.Fatalf("malformed yaml: want exit 1, got %d", code)
	}
}
