package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
)

// ErrNotImplemented is returned by exporter stubs that are designed but not yet
// built (ClickHouse, Kafka, OTEL).
var ErrNotImplemented = errors.New("audit exporter not implemented")

// Exporter is a pluggable audit sink. Implementations must be safe for
// concurrent use. The service is not coupled to any particular sink — it depends
// only on this interface.
type Exporter interface {
	// Export writes one event. It must not block the request path for long;
	// slow sinks should buffer internally.
	Export(ctx context.Context, ev *Event) error
	// Flush forces any buffered events out.
	Flush(ctx context.Context) error
	// Close flushes and releases resources.
	Close() error
}

// NopExporter discards all events. Useful as a default when auditing is off.
type NopExporter struct{}

// Export discards the event.
func (NopExporter) Export(context.Context, *Event) error { return nil }

// Flush is a no-op.
func (NopExporter) Flush(context.Context) error { return nil }

// Close is a no-op.
func (NopExporter) Close() error { return nil }

// FileExporter appends events as JSON lines (NDJSON) to a local file. It is the
// initial, always-available sink; remote sinks plug in behind Exporter later.
type FileExporter struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
}

// NewFileExporter opens (creating/appending) the file at path for audit output.
func NewFileExporter(path string) (*FileExporter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("audit: open %q: %w", path, err)
	}
	return &FileExporter{f: f, w: bufio.NewWriter(f)}, nil
}

// Export writes one NDJSON line.
func (e *FileExporter) Export(_ context.Context, ev *Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.w.Write(b); err != nil {
		return err
	}
	return e.w.WriteByte('\n')
}

// Flush flushes the buffer to the underlying file.
func (e *FileExporter) Flush(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.w.Flush()
}

// Close flushes and closes the file, reporting both errors if both fail.
func (e *FileExporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return errors.Join(e.w.Flush(), e.f.Close())
}

// The following remote exporters are designed but intentionally unimplemented;
// their constructors return ErrNotImplemented so the wiring exists without a
// half-working sink. Each will satisfy Exporter when built (Phase 9).

// NewClickHouseExporter will batch-insert events into ClickHouse.
func NewClickHouseExporter(ClickHouseConfig) (Exporter, error) { return nil, ErrNotImplemented }

// ClickHouseConfig holds the (future) ClickHouse sink configuration.
type ClickHouseConfig struct {
	DSN       string
	Table     string
	BatchSize int
}

// NewKafkaExporter will publish events to a Kafka topic.
func NewKafkaExporter(KafkaConfig) (Exporter, error) { return nil, ErrNotImplemented }

// KafkaConfig holds the (future) Kafka sink configuration.
type KafkaConfig struct {
	Brokers []string
	Topic   string
}

// NewOTELExporter will emit events as OpenTelemetry logs/spans.
func NewOTELExporter(OTELConfig) (Exporter, error) { return nil, ErrNotImplemented }

// OTELConfig holds the (future) OTEL sink configuration.
type OTELConfig struct {
	Endpoint string
	Insecure bool
}
