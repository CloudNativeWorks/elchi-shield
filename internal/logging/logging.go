// Package logging provides a small factory for building the application's
// structured logger plus a shared attribute vocabulary, so the whole codebase
// logs consistently and is easy to read, filter, and debug.
//
// Conventions (keep these — they make logs predictable):
//
//   - Every record carries an "instance" (stamped in main) and, for subsystem
//     logs, a "component" field (see Component) so you can tell at a glance where
//     a line came from and filter by it (e.g. component=extproc).
//   - Use the Key* constants for well-known fields instead of ad-hoc strings, so
//     a given fact always lives under the same key (request_id, policy_id, ...).
//   - Log errors with Err(err) so failures are always under "error".
//   - Levels: Error = the process/operator must act (bind failed, reload failed);
//     Warn = degraded but handled (audit drop, retired-snapshot close error);
//     Info = lifecycle + enforced blocks; Debug = per-request allow decisions and
//     fine-grained detail. The request path never logs above Debug on the happy
//     path, so production at Info stays quiet.
//
// The rest of the codebase depends only on *slog.Logger and never on a global
// logger or ad-hoc setup.
package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Well-known structured-log attribute keys. Using these constants keeps field
// names consistent across the codebase so logs are filterable and predictable.
const (
	KeyComponent     = "component"      // subsystem origin (extproc, watcher, config, ...)
	KeyError         = "error"          // an error value (use Err)
	KeyRequestID     = "request_id"     // Envoy x-request-id (or a minted id)
	KeyListener      = "listener"       // Envoy listener id
	KeyPolicyID      = "policy_id"      // resolved policy scope
	KeyPhase         = "phase"          // request_headers/request_body/response_*
	KeyAction        = "action"         // allow/block/detect/shadow
	KeyRuleID        = "rule_id"        // attribution of a finding
	KeyEngine        = "engine"         // engine that produced the finding
	KeyReason        = "reason"         // short, payload-free decision reason
	KeySeverity      = "severity"       // finding severity
	KeyStatusCode    = "status_code"    // HTTP status returned on a block
	KeyHost          = "host"           // request authority/host
	KeyMethod        = "method"         // HTTP method
	KeyPath          = "path"           // request path (query-stripped)
	KeyDurationMs    = "duration_ms"    // elapsed milliseconds
	KeyConfigVersion = "config_version" // active config version/hash
)

// Format selects the encoding of log records.
type Format string

const (
	// FormatJSON emits one JSON object per record (recommended for production).
	FormatJSON Format = "json"
	// FormatText emits human-readable key=value lines (handy for local dev).
	FormatText Format = "text"
)

// Options configures the logger built by New.
type Options struct {
	// Level is the minimum level to emit (debug, info, warn, error).
	Level string
	// Format is "json" or "text". Defaults to JSON when empty.
	Format Format
	// Output is where records are written. Defaults to os.Stdout when nil.
	Output io.Writer
	// AddSource includes the source file:line in records when true (great for
	// debugging; the path is shortened to base name for readability).
	AddSource bool
}

// New builds a *slog.Logger from Options. It never returns nil and applies sane
// defaults so callers can pass a zero Options for a reasonable logger.
func New(opts Options) *slog.Logger {
	out := opts.Output
	if out == nil {
		out = os.Stdout
	}

	handlerOpts := &slog.HandlerOptions{
		Level:       parseLevel(opts.Level),
		AddSource:   opts.AddSource,
		ReplaceAttr: replaceAttr,
	}

	var handler slog.Handler
	switch opts.Format {
	case FormatText:
		handler = slog.NewTextHandler(out, handlerOpts)
	default: // FormatJSON and unknown values
		handler = slog.NewJSONHandler(out, handlerOpts)
	}

	return slog.New(handler)
}

// Component returns a child logger tagged with the component name so every record
// it emits is attributable to its subsystem (filter by component=...). A nil
// parent falls back to the default logger.
func Component(parent *slog.Logger, name string) *slog.Logger {
	if parent == nil {
		parent = slog.Default()
	}
	return parent.With(slog.String(KeyComponent, name))
}

// Err returns the standard error attribute (under KeyError). Prefer it over
// ad-hoc keys so failures are always logged under the same field. A nil error
// yields an empty value (callers normally log only on a non-nil error).
func Err(err error) slog.Attr {
	if err == nil {
		return slog.String(KeyError, "")
	}
	return slog.String(KeyError, err.Error())
}

// replaceAttr normalizes records for readability:
//   - shortens the source file path to its base name (so "source" reads as
//     "processor.go:123", not an absolute path);
//   - renders durations as human-readable strings ("300ms", "15s") instead of
//     raw nanoseconds, so JSON logs match the text format and are easy to scan.
//     (Numeric latency fields are logged explicitly as duration_ms floats.)
func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	switch {
	case a.Key == slog.SourceKey:
		if src, ok := a.Value.Any().(*slog.Source); ok && src != nil {
			src.File = filepath.Base(src.File)
		}
	case a.Value.Kind() == slog.KindDuration:
		return slog.String(a.Key, a.Value.Duration().String())
	}
	return a
}

// parseLevel maps a case-insensitive level name to slog.Level, defaulting to
// Info for empty or unrecognized values.
func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
