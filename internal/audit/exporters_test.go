package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// recordExporter records exported events.
type recordExporter struct {
	mu     sync.Mutex
	events []*Event
}

func (r *recordExporter) Export(_ context.Context, ev *Event) error {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	return nil
}
func (r *recordExporter) Flush(context.Context) error { return nil }
func (r *recordExporter) Close() error                { return nil }
func (r *recordExporter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func TestMultiExporterFanOut(t *testing.T) {
	a, b := &recordExporter{}, &recordExporter{}
	m := NewMultiExporter(a, nil, b)
	if err := m.Export(context.Background(), &Event{RequestID: "1"}); err != nil {
		t.Fatal(err)
	}
	if a.count() != 1 || b.count() != 1 {
		t.Fatalf("both exporters should receive the event: a=%d b=%d", a.count(), b.count())
	}
}

func TestBufferedExporterDeliversAndDrains(t *testing.T) {
	inner := &recordExporter{}
	b := NewBufferedExporter(inner, 16, 2, nil)
	for range 5 {
		_ = b.Export(context.Background(), &Event{RequestID: "x"})
	}
	if err := b.Close(); err != nil { // Close drains the queue
		t.Fatal(err)
	}
	if inner.count() != 5 {
		t.Fatalf("buffered exporter should deliver all events, got %d", inner.count())
	}
}

// blockingExporter blocks in Export until released, to exercise the drop path.
type blockingExporter struct {
	release chan struct{}
}

func (e *blockingExporter) Export(context.Context, *Event) error {
	<-e.release
	return nil
}
func (e *blockingExporter) Flush(context.Context) error { return nil }
func (e *blockingExporter) Close() error                { return nil }

func TestBufferedExporterDropsWhenFull(t *testing.T) {
	inner := &blockingExporter{release: make(chan struct{})}
	b := NewBufferedExporter(inner, 1, 1, nil)
	// First is picked by the worker (blocks in inner). Second fills the cap-1
	// queue. Subsequent events are dropped.
	for range 6 {
		_ = b.Export(context.Background(), &Event{})
		time.Sleep(time.Millisecond)
	}
	if b.Dropped() == 0 {
		t.Fatal("expected some events to be dropped when the queue is full")
	}
	close(inner.release)
}

func TestBufferedExporterCloseIsSafe(t *testing.T) {
	b := NewBufferedExporter(&recordExporter{}, 4, 2, nil)
	// Concurrent Export while closing must not panic (send-on-closed-channel).
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = b.Export(context.Background(), &Event{})
		}()
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil { // idempotent
		t.Fatal(err)
	}
	_ = b.Export(context.Background(), &Event{}) // dropped, no panic
	wg.Wait()
}

func TestExporterRegistry(t *testing.T) {
	RegisterExporter("test-sink", func(opts ExporterOptions) (Exporter, error) {
		return NopExporter{}, nil
	})
	if _, err := NewExporter("test-sink", ExporterOptions{}); err != nil {
		t.Fatalf("registered exporter should build: %v", err)
	}
	_, err := NewExporter("nonexistent", ExporterOptions{})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("unknown exporter should be ErrNotImplemented: %v", err)
	}
}
