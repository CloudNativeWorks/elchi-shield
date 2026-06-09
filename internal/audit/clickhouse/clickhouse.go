// Package clickhouse is an audit Exporter that batch-inserts events into
// ClickHouse. It is always compiled into the binary and registers itself with
// the audit package on init, so `--audit-exporter clickhouse` is available.
package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"sync"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/cloudnativeworks/elchi-shield/internal/audit"
)

const defaultTable = "elchi_shield_audit"

func init() {
	audit.RegisterExporter("clickhouse", func(opts audit.ExporterOptions) (audit.Exporter, error) {
		return New(opts)
	})
}

// Exporter batches events and flushes them to ClickHouse.
type Exporter struct {
	conn      driver.Conn
	table     string
	batchSize int

	mu      sync.Mutex
	batch   driver.Batch
	pending int
}

// New connects to ClickHouse using the DSN in opts, ensures the audit table
// exists, and prepares the first insert batch.
func New(opts audit.ExporterOptions) (*Exporter, error) {
	o, err := ch.ParseDSN(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: parse dsn: %w", err)
	}
	conn, err := ch.Open(o)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: open: %w", err)
	}
	table := opts.Table
	if table == "" {
		table = defaultTable
	}
	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}

	e := &Exporter{conn: conn, table: table, batchSize: batchSize}
	if err := e.ensureTable(context.Background()); err != nil {
		return nil, err
	}
	if err := e.newBatch(context.Background()); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Exporter) ensureTable(ctx context.Context) error {
	ddl := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		ts DateTime64(3),
		instance String,
		request_id String,
		phase String,
		direction String,
		action String,
		severity String,
		reason String,
		rule_id String,
		policy_id String,
		engine String,
		host String,
		path String,
		method String,
		config_version String
	) ENGINE = MergeTree ORDER BY ts`, e.table)
	if err := e.conn.Exec(ctx, ddl); err != nil {
		return fmt.Errorf("clickhouse: ensure table: %w", err)
	}
	return nil
}

func (e *Exporter) newBatch(ctx context.Context) error {
	b, err := e.conn.PrepareBatch(ctx, "INSERT INTO "+e.table)
	if err != nil {
		return fmt.Errorf("clickhouse: prepare batch: %w", err)
	}
	e.batch = b
	e.pending = 0
	return nil
}

// Export appends an event to the current batch, sending it when it reaches the
// configured size.
func (e *Exporter) Export(ctx context.Context, ev *audit.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	d := ev.Decision
	if err := e.batch.Append(
		ev.Timestamp, ev.Instance, ev.RequestID, ev.Phase, ev.Direction,
		d.Action.String(), d.Severity.String(), d.Reason, d.RuleID, d.PolicyID, d.Engine,
		ev.Host, ev.Path, ev.Method, ev.ConfigVersion,
	); err != nil {
		return fmt.Errorf("clickhouse: append: %w", err)
	}
	e.pending++
	if e.pending >= e.batchSize {
		return e.flushLocked(ctx)
	}
	return nil
}

func (e *Exporter) flushLocked(ctx context.Context) error {
	if e.pending == 0 {
		return nil
	}
	if err := e.batch.Send(); err != nil {
		return fmt.Errorf("clickhouse: send: %w", err)
	}
	return e.newBatch(ctx)
}

// Flush sends any buffered rows.
func (e *Exporter) Flush(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.flushLocked(ctx)
}

// Close flushes and closes the connection, reporting both errors if both fail.
func (e *Exporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return errors.Join(e.flushLocked(context.Background()), e.conn.Close())
}
