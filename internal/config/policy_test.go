package config

import (
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }

func TestResolveInheritanceOrder(t *testing.T) {
	base := DefaultPolicy()
	fileDefaults := PolicySpec{Mode: ptr(ModeDetect), Timeout: ptr(Duration(100 * time.Millisecond))}
	domain := PolicySpec{FailMode: ptr(FailClose)}
	route := PolicySpec{Mode: ptr(ModeShadow), SamplingRate: ptr(0.5)}

	got := Resolve(base, fileDefaults, domain, route)

	if got.Mode != ModeShadow {
		t.Errorf("route should win mode: got %v", got.Mode)
	}
	if got.FailMode != FailClose {
		t.Errorf("domain should set fail mode: got %v", got.FailMode)
	}
	if got.Timeout != 100*time.Millisecond {
		t.Errorf("file default timeout should apply: got %v", got.Timeout)
	}
	if got.SamplingRate != 0.5 {
		t.Errorf("route sampling should apply: got %v", got.SamplingRate)
	}
	// Untouched field keeps built-in default.
	if got.MaxRequestBodyBytes != base.MaxRequestBodyBytes {
		t.Errorf("untouched field changed: got %d", got.MaxRequestBodyBytes)
	}
}

func TestResolveSkipChecksUnion(t *testing.T) {
	got := Resolve(DefaultPolicy(),
		PolicySpec{SkipChecks: []string{"sqli"}},
		PolicySpec{SkipChecks: []string{"xss", "sqli"}},
	)
	if !got.SkipsCheck("sqli") || !got.SkipsCheck("xss") {
		t.Fatalf("skip checks should union: %v", got.SkipChecks)
	}
	if got.SkipsCheck("rce") {
		t.Fatalf("unexpected skip: %v", got.SkipChecks)
	}
}

func TestMergeLaterFileWinsDefaults(t *testing.T) {
	a := ParsedFile{Name: "a.yaml", File: &File{Spec: Spec{Defaults: PolicySpec{Mode: ptr(ModeBlock)}}}}
	b := ParsedFile{Name: "b.yaml", File: &File{Spec: Spec{Defaults: PolicySpec{Mode: ptr(ModeDetect)}}}}
	// Pass in non-sorted order to prove Merge sorts deterministically.
	merged := Merge([]ParsedFile{b, a})
	if merged.FileDefaults.Mode == nil || *merged.FileDefaults.Mode != ModeDetect {
		t.Fatalf("later (b) file should win: %+v", merged.FileDefaults.Mode)
	}
	if len(merged.Sources) != 2 || merged.Sources[0] != "a.yaml" {
		t.Fatalf("sources should be sorted: %v", merged.Sources)
	}
}
