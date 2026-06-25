package clickhouse

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/column"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/cloudnativeworks/elchi-shield/internal/audit"
	"github.com/cloudnativeworks/elchi-shield/internal/decision"
)

// fakeBatch is a controllable driver.Batch: it records appended rows and can be
// made to fail on Append/Send to exercise the recovery paths.
type fakeBatch struct {
	rows      [][]any
	appendErr error
	sendErr   error
	sends     int
}

func (b *fakeBatch) Append(v ...any) error {
	if b.appendErr != nil {
		return b.appendErr
	}
	b.rows = append(b.rows, v)
	return nil
}
func (b *fakeBatch) Send() error { b.sends++; return b.sendErr }

// unused driver.Batch methods (no-op stubs to satisfy the interface)
func (b *fakeBatch) Abort() error                  { return nil }
func (b *fakeBatch) AppendStruct(any) error        { return nil }
func (b *fakeBatch) Column(int) driver.BatchColumn { return nil }
func (b *fakeBatch) Flush() error                  { return nil }
func (b *fakeBatch) IsSent() bool                  { return false }
func (b *fakeBatch) Rows() int                     { return len(b.rows) }
func (b *fakeBatch) Columns() []column.Interface   { return nil }
func (b *fakeBatch) Close() error                  { return nil }

// fakeConn is a controllable driver.Conn that hands out fakeBatches and records
// Exec (DDL) statements. prepareErr, when set, fails PrepareBatch.
type fakeConn struct {
	execs      []string
	execErr    error // when set, every Exec (DDL) fails — simulates a no-DDL-grant user
	batches    []*fakeBatch
	prepareErr error
	closed     int
}

func (c *fakeConn) Exec(_ context.Context, query string, _ ...any) error {
	c.execs = append(c.execs, query)
	return c.execErr
}
func (c *fakeConn) PrepareBatch(_ context.Context, _ string, _ ...driver.PrepareBatchOption) (driver.Batch, error) {
	if c.prepareErr != nil {
		return nil, c.prepareErr
	}
	b := &fakeBatch{}
	c.batches = append(c.batches, b)
	return b, nil
}
func (c *fakeConn) Close() error { c.closed++; return nil }

// current returns the most recently prepared batch.
func (c *fakeConn) current() *fakeBatch { return c.batches[len(c.batches)-1] }

// unused driver.Conn methods
func (c *fakeConn) Contributors() []string                            { return nil }
func (c *fakeConn) ServerVersion() (*driver.ServerVersion, error)     { return nil, nil }
func (c *fakeConn) Select(context.Context, any, string, ...any) error { return nil }
func (c *fakeConn) Query(context.Context, string, ...any) (driver.Rows, error) {
	return nil, nil
}
func (c *fakeConn) QueryRow(context.Context, string, ...any) driver.Row     { return nil }
func (c *fakeConn) AsyncInsert(context.Context, string, bool, ...any) error { return nil }
func (c *fakeConn) Ping(context.Context) error                              { return nil }
func (c *fakeConn) Stats() driver.Stats                                     { return driver.Stats{} }

func testEvent() *audit.Event {
	return &audit.Event{
		Timestamp: time.Unix(1000, 0).UTC(),
		Instance:  "edge1-shield",
		NodeID:    "lst1::proj-1::10.0.0.1",
		ProjectID: "proj-1",
		Listener:  "lst1",
		RequestID: "req-1",
		Phase:     "request_headers",
		Direction: "request",
		Decision: decision.Decision{
			Action: decision.Block, Severity: decision.SeverityHigh,
			Reason: "blocked", RuleID: "942100", PolicyID: "p1", Engine: "coraza",
			StatusCode: 403,
		},
		Host:          "api.example.com",
		Path:          "/x",
		Method:        "POST",
		ConfigVersion: "v1",
	}
}

// TestEnsureTableCreatesAndMigrates proves ensureTable issues the CREATE, the
// idempotent ADD COLUMN IF NOT EXISTS for each newer column (the upgrade path),
// and the rollup table + materialized view.
func TestEnsureTableCreatesAndMigrates(t *testing.T) {
	conn := &fakeConn{}
	exp, err := newExporter(conn, audit.ExporterOptions{})
	if err != nil {
		t.Fatalf("newExporter: %v", err)
	}
	defer exp.Close()

	// 1 CREATE + 4 ALTER + 1 rollup CREATE + 1 MV CREATE.
	if len(conn.execs) != 7 {
		t.Fatalf("expected 7 execs, got %d: %v", len(conn.execs), conn.execs)
	}
	if !strings.Contains(conn.execs[0], "CREATE TABLE IF NOT EXISTS") {
		t.Errorf("first exec should be CREATE, got %q", conn.execs[0])
	}
	for _, col := range []string{"node_id", "project_id", "listener", "status_code"} {
		found := false
		for _, q := range conn.execs[1:] {
			if strings.Contains(q, "ADD COLUMN IF NOT EXISTS") && strings.Contains(q, col) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing ADD COLUMN IF NOT EXISTS for %q", col)
		}
	}
	// The rollup table + MV must be provisioned (the backend summary reads them).
	var hasRollup, hasMV bool
	for _, q := range conn.execs {
		if strings.Contains(q, "AggregatingMergeTree") && strings.Contains(q, "_1m") {
			hasRollup = true
		}
		if strings.Contains(q, "CREATE MATERIALIZED VIEW IF NOT EXISTS") && strings.Contains(q, "countState()") {
			hasMV = true
		}
	}
	if !hasRollup {
		t.Error("missing the _1m AggregatingMergeTree rollup table")
	}
	if !hasMV {
		t.Error("missing the rollup materialized view")
	}
}

// TestExportColumnOrder proves Append receives all 19 values in the exact DDL
// order — the positional INSERT depends on this.
func TestExportColumnOrder(t *testing.T) {
	conn := &fakeConn{}
	exp, err := newExporter(conn, audit.ExporterOptions{BatchSize: 100}) // no auto-flush
	if err != nil {
		t.Fatalf("newExporter: %v", err)
	}
	defer exp.Close()

	if err := exp.Export(context.Background(), testEvent()); err != nil {
		t.Fatalf("Export: %v", err)
	}
	row := conn.current().rows[0]
	if len(row) != 19 {
		t.Fatalf("expected 19 columns, got %d", len(row))
	}
	// Spot-check the identity + status columns at their DDL positions.
	if row[2] != "lst1::proj-1::10.0.0.1" {
		t.Errorf("col[2] node_id = %v", row[2])
	}
	if row[3] != "proj-1" {
		t.Errorf("col[3] project_id = %v", row[3])
	}
	if row[4] != "lst1" {
		t.Errorf("col[4] listener = %v", row[4])
	}
	if sc, ok := row[17].(uint16); !ok || sc != 403 {
		t.Errorf("col[17] status_code = %v (want uint16 403)", row[17])
	}
}

// TestRecoversFromSendFailure is the critical regression guard for the batch-
// poisoning fix: a transient Send() failure must NOT permanently wedge the
// exporter — the next event must land in a fresh batch and succeed.
func TestRecoversFromSendFailure(t *testing.T) {
	conn := &fakeConn{}
	exp, err := newExporter(conn, audit.ExporterOptions{BatchSize: 1}) // flush every event
	if err != nil {
		t.Fatalf("newExporter: %v", err)
	}
	defer exp.Close()

	batchA := conn.current()
	batchA.sendErr = errors.New("clickhouse disk full")

	// First event: appends to A, flush triggers A.Send() which fails. The error
	// is swallowed (audit never reports up the request path) but the lost row is
	// counted, and the batch is replaced so the exporter doesn't wedge.
	if err := exp.Export(context.Background(), testEvent()); err != nil {
		t.Fatalf("Export must swallow sink errors, got %v", err)
	}
	if exp.FailedWrites() != 1 {
		t.Fatalf("the dropped row must be counted; FailedWrites=%d", exp.FailedWrites())
	}
	if len(conn.batches) != 2 {
		t.Fatalf("send failure should renew the batch; got %d batches", len(conn.batches))
	}

	// Second event: must land in the fresh batch (no permanent wedge).
	if err := exp.Export(context.Background(), testEvent()); err != nil {
		t.Fatalf("exporter did not recover after a send failure: %v", err)
	}
	if len(batchA.rows) != 1 {
		t.Errorf("the recovered event must NOT be appended to the spent batch A")
	}
	if len(conn.batches) != 3 {
		t.Fatalf("expected a 3rd batch after the successful flush, got %d", len(conn.batches))
	}
	if exp.FailedWrites() != 1 {
		t.Fatalf("the recovered write must not be counted as dropped; FailedWrites=%d", exp.FailedWrites())
	}
}

// TestRecoversFromAppendFailure proves a failed Append also rebuilds the batch.
func TestRecoversFromAppendFailure(t *testing.T) {
	conn := &fakeConn{}
	exp, err := newExporter(conn, audit.ExporterOptions{BatchSize: 100})
	if err != nil {
		t.Fatalf("newExporter: %v", err)
	}
	defer exp.Close()

	conn.current().appendErr = errors.New("bad row")
	if err := exp.Export(context.Background(), testEvent()); err != nil {
		t.Fatalf("Export must swallow append errors, got %v", err)
	}
	if exp.FailedWrites() != 1 {
		t.Fatalf("the dropped row must be counted; FailedWrites=%d", exp.FailedWrites())
	}
	if len(conn.batches) != 2 {
		t.Fatalf("append failure should renew the batch; got %d batches", len(conn.batches))
	}
	if err := exp.Export(context.Background(), testEvent()); err != nil {
		t.Fatalf("exporter did not recover after an append failure: %v", err)
	}
}

// TestDDLDeniedStillInserts proves the least-privilege path: a CH user with only
// INSERT (all DDL denied) against a pre-provisioned table still comes up and
// exports — ensureDatabase/ensureTable are best-effort, PrepareBatch is the gate.
func TestDDLDeniedStillInserts(t *testing.T) {
	conn := &fakeConn{execErr: errors.New("not enough privileges: CREATE TABLE")}
	exp, err := newExporter(conn, audit.ExporterOptions{BatchSize: 100})
	if err != nil {
		t.Fatalf("newExporter must succeed when only DDL is denied (table pre-exists): %v", err)
	}
	defer exp.Close()
	if err := exp.Export(context.Background(), testEvent()); err != nil {
		t.Fatalf("Export should work for an INSERT-only user: %v", err)
	}
	if got := len(conn.current().rows); got != 1 {
		t.Fatalf("event should be appended despite DDL denial; rows=%d", got)
	}
	if exp.FailedWrites() != 0 {
		t.Fatalf("no drops expected when INSERT works; FailedWrites=%d", exp.FailedWrites())
	}
}

// TestConcurrentExportNoRace drives many goroutines through Export with the
// network Send now happening outside the batch mutex — the regression guard for
// the throughput refactor. Under -race it proves no data race, and the row
// accounting proves nothing is lost or double-sent when batches detach + send
// concurrently. (Run: go test -race -run TestConcurrentExportNoRace ./...)
func TestConcurrentExportNoRace(t *testing.T) {
	conn := &fakeConn{}
	exp, err := newExporter(conn, audit.ExporterOptions{BatchSize: 8})
	if err != nil {
		t.Fatalf("newExporter: %v", err)
	}

	const goroutines, perG = 8, 250
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range perG {
				_ = exp.Export(context.Background(), testEvent())
			}
		})
	}
	wg.Wait()
	_ = exp.Flush(context.Background()) // drain the final partial batch
	_ = exp.Close()

	// Every event must land in a batch that was Sent (no loss, no double-send).
	delivered := 0
	for _, b := range conn.batches {
		if b.sends > 0 {
			delivered += len(b.rows)
		}
	}
	if exp.FailedWrites() != 0 {
		t.Fatalf("healthy sink must not drop; FailedWrites=%d", exp.FailedWrites())
	}
	if want := goroutines * perG; delivered != want {
		t.Fatalf("accounting mismatch: delivered=%d want=%d", delivered, want)
	}
}

// TestCloseIsIdempotent proves a double Close closes the connection exactly once.
func TestCloseIsIdempotent(t *testing.T) {
	conn := &fakeConn{}
	exp, err := newExporter(conn, audit.ExporterOptions{})
	if err != nil {
		t.Fatalf("newExporter: %v", err)
	}
	_ = exp.Close()
	_ = exp.Close()
	if conn.closed != 1 {
		t.Fatalf("expected conn.Close once, got %d", conn.closed)
	}
}
