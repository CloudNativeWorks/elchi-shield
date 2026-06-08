package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestComponentTagsRecords(t *testing.T) {
	var buf bytes.Buffer
	log := Component(New(Options{Output: &buf}), "watcher")
	log.Info("started")

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatalf("not JSON: %v (%q)", err, buf.String())
	}
	if rec[KeyComponent] != "watcher" {
		t.Fatalf("component field missing/wrong: %#v", rec)
	}
}

func TestErrAttr(t *testing.T) {
	var buf bytes.Buffer
	log := New(Options{Output: &buf})
	log.Error("boom", Err(errors.New("disk full")))

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if rec[KeyError] != "disk full" {
		t.Fatalf("error field missing/wrong: %#v", rec)
	}
}

func TestAddSourceShortensPath(t *testing.T) {
	var buf bytes.Buffer
	log := New(Options{Output: &buf, AddSource: true})
	log.Info("hi")

	out := buf.String()
	if !strings.Contains(out, "logging_test.go") {
		t.Fatalf("source should include this test file's base name: %q", out)
	}
	if strings.Contains(out, "/internal/logging/") {
		t.Fatalf("source path should be shortened to base name, got full path: %q", out)
	}
}

func TestNewJSONLogsAtConfiguredLevel(t *testing.T) {
	var buf bytes.Buffer
	log := New(Options{Level: "warn", Format: FormatJSON, Output: &buf})

	log.Info("info should be filtered")
	log.Warn("warn should appear", "k", "v")

	out := buf.String()
	if strings.Contains(out, "info should be filtered") {
		t.Fatalf("info record leaked at warn level: %q", out)
	}
	if !strings.Contains(out, "warn should appear") {
		t.Fatalf("warn record missing: %q", out)
	}

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &rec); err != nil {
		t.Fatalf("output is not valid JSON: %v (%q)", err, out)
	}
	if rec["k"] != "v" {
		t.Fatalf("attribute missing in record: %#v", rec)
	}
}

func TestNewDefaultsToInfoJSON(t *testing.T) {
	var buf bytes.Buffer
	log := New(Options{Output: &buf})
	log.Debug("debug filtered by default")
	log.Info("info kept by default")

	if strings.Contains(buf.String(), "debug filtered") {
		t.Fatalf("debug should be filtered at default level: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "info kept") {
		t.Fatalf("info should appear at default level: %q", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"INFO":    slog.LevelInfo,
		"Warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"":        slog.LevelInfo,
		"bogus":   slog.LevelInfo,
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}
