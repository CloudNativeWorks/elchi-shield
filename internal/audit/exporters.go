package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ExporterOptions configures a registered exporter. Fields are sink-specific;
// each factory reads what it needs.
type ExporterOptions struct {
	DSN           string // ClickHouse DSN
	Endpoint      string // OTEL collector endpoint
	Table         string // ClickHouse table
	BatchSize     int
	FlushInterval time.Duration // ClickHouse: time-based flush so low-traffic rows land promptly (0 = size-only)
	TTLDays       int           // ClickHouse: row TTL in days (0 = no TTL)
	Insecure      bool
}

// ExporterFactory constructs an exporter from options.
type ExporterFactory func(ExporterOptions) (Exporter, error)

// ExportFailCounter is implemented by sinks that batch/flush asynchronously and
// can therefore drop events AFTER Export returns nil (e.g. the ClickHouse batch
// exporter losing a batch when the server disk is full). The metric layer adds
// this to the queue-level failure count so such losses stay observable.
type ExportFailCounter interface {
	FailedWrites() uint64
}

// exporterRegistry holds factories registered at init time by adapter
// subpackages (clickhouse, otel). The "file" sink is built in directly. Mutation
// happens only during package init (single goroutine), before any reads.
var exporterRegistry = map[string]ExporterFactory{}

// RegisterExporter installs a named exporter factory. Called from an adapter
// subpackage's init().
func RegisterExporter(name string, f ExporterFactory) {
	exporterRegistry[name] = f
}

// NewExporter builds a registered exporter by name. It returns a clear error if
// the named exporter is not compiled into this binary.
func NewExporter(name string, opts ExporterOptions) (Exporter, error) {
	f, ok := exporterRegistry[name]
	if !ok {
		return nil, fmt.Errorf("%w: audit exporter %q (build with its tag to enable)", ErrNotImplemented, name)
	}
	return f(opts)
}

// MultiExporter fans an event out to several exporters, joining their errors.
type MultiExporter struct {
	exporters []Exporter
}

// NewMultiExporter combines exporters; nil entries are dropped.
func NewMultiExporter(exporters ...Exporter) *MultiExporter {
	filtered := make([]Exporter, 0, len(exporters))
	for _, e := range exporters {
		if e != nil {
			filtered = append(filtered, e)
		}
	}
	return &MultiExporter{exporters: filtered}
}

// Export sends ev to every exporter.
func (m *MultiExporter) Export(ctx context.Context, ev *Event) error {
	var errs []error
	for _, e := range m.exporters {
		if err := e.Export(ctx, ev); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Flush flushes every exporter.
func (m *MultiExporter) Flush(ctx context.Context) error {
	errs := make([]error, 0, len(m.exporters))
	for _, e := range m.exporters {
		errs = append(errs, e.Flush(ctx))
	}
	return errors.Join(errs...)
}

// Close closes every exporter.
func (m *MultiExporter) Close() error {
	errs := make([]error, 0, len(m.exporters))
	for _, e := range m.exporters {
		errs = append(errs, e.Close())
	}
	return errors.Join(errs...)
}

// BufferedExporter wraps an exporter with an async, bounded queue drained by a
// pool of workers, so Export never blocks the request path and export throughput
// scales across listeners. Events beyond the queue capacity are dropped (and
// counted) rather than backing up traffic — availability over completeness.
//
// An optional rate limiter caps the non-finding ("allow") event stream off the
// request goroutine (in the workers); findings (block/detect/shadow) always
// export. This keeps the request path lock-free.
type BufferedExporter struct {
	inner     Exporter
	limiter   *RateLimiter
	queue     chan *Event
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	dropped   atomic.Uint64
	failed    atomic.Uint64
}

// NewBufferedExporter wraps inner with a queue of the given capacity drained by
// `workers` goroutines (default 1). limiter may be nil (no rate cap). Call Close
// to stop the workers and flush.
func NewBufferedExporter(inner Exporter, capacity, workers int, limiter *RateLimiter) *BufferedExporter {
	if capacity <= 0 {
		capacity = 1024
	}
	if workers <= 0 {
		workers = 1
	}
	b := &BufferedExporter{
		inner:   inner,
		limiter: limiter,
		queue:   make(chan *Event, capacity),
		done:    make(chan struct{}),
	}
	for range workers {
		b.wg.Add(1)
		go b.run()
	}
	return b
}

// exportTimeout bounds a single inner-sink Export so a hung sink can't stall the
// audit drain workers.
const exportTimeout = 5 * time.Second

func (b *BufferedExporter) run() {
	defer b.wg.Done()
	for {
		select {
		case ev := <-b.queue:
			b.export(ev)
		case <-b.done:
			// Drain whatever is buffered, then exit. The data channel is never
			// closed, so senders can never send on a closed channel.
			for {
				select {
				case ev := <-b.queue:
					b.export(ev)
				default:
					return
				}
			}
		}
	}
}

// export applies the rate cap (findings bypass) and writes to the inner sink.
// An inner-sink error (e.g. ClickHouse unreachable) is counted so a silently
// failing/wedged remote sink is observable — the event is lost either way (the
// request path is never blocked), but operators can see it via Failed().
//
// A recover() guards the worker: a panic from a third-party sink dependency must
// not kill the drain goroutine (which would silently stop ALL audit), mirroring
// the request-path panic recovery. The lost event is counted as failed.
func (b *BufferedExporter) export(ev *Event) {
	defer func() {
		if r := recover(); r != nil {
			b.failed.Add(1)
		}
	}()
	if !isFinding(ev) && !b.limiter.Allow() {
		b.dropped.Add(1)
		return
	}
	// Per-event deadline so a wedged inner sink (a hung write) sheds one slow event
	// instead of blocking the drain worker — and, with both workers blocked, silently
	// stopping ALL audit until the sink recovers.
	ctx, cancel := context.WithTimeout(context.Background(), exportTimeout)
	defer cancel()
	if err := b.inner.Export(ctx, ev); err != nil {
		b.failed.Add(1)
	}
}

// Export enqueues ev without blocking. If the queue is full or the exporter is
// closing, ev is dropped (and counted). The `done` guard makes Export safe to
// call concurrently with Close — it never sends on a closed channel.
func (b *BufferedExporter) Export(_ context.Context, ev *Event) error {
	select {
	case <-b.done:
		b.dropped.Add(1)
		return nil
	default:
	}
	select {
	case b.queue <- ev:
	case <-b.done:
		b.dropped.Add(1)
	default:
		b.dropped.Add(1)
	}
	return nil
}

// Dropped returns the number of events dropped due to a full queue or rate cap.
func (b *BufferedExporter) Dropped() uint64 { return b.dropped.Load() }

// Failed returns the number of events the inner sink failed to write — both the
// errors Export returns synchronously AND the rows an async/batched sink drops
// after the fact (via ExportFailCounter, e.g. ClickHouse rejecting inserts when
// its disk is full). The request path is never affected; this surfaces a
// degraded/wedged sink for monitoring.
func (b *BufferedExporter) Failed() uint64 {
	n := b.failed.Load()
	if fc, ok := b.inner.(ExportFailCounter); ok {
		n += fc.FailedWrites()
	}
	return n
}

// QueueLen returns the current depth of the async queue (for a live gauge).
func (b *BufferedExporter) QueueLen() int { return len(b.queue) }

// Flush waits (respecting ctx) for the queue to drain, then flushes the inner
// exporter. It honors the caller's deadline rather than a hard-coded one.
func (b *BufferedExporter) Flush(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for len(b.queue) > 0 {
		select {
		case <-ctx.Done():
			return b.inner.Flush(ctx)
		case <-ticker.C:
		}
	}
	return b.inner.Flush(ctx)
}

// Close signals the workers to drain and stop (the data channel is never closed,
// so concurrent Export calls are always safe), waits for them, then closes the
// inner exporter. It is idempotent.
func (b *BufferedExporter) Close() error {
	b.closeOnce.Do(func() { close(b.done) })
	b.wg.Wait()
	return b.inner.Close()
}
