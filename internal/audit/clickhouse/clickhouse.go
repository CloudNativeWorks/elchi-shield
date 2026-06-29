// Package clickhouse is an audit Exporter that batch-inserts events into
// ClickHouse. It is always compiled into the binary and registers itself with
// the audit package on init, so `--audit-exporter clickhouse` is available.
package clickhouse

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/cloudnativeworks/elchi-shield/internal/audit"
)

const (
	defaultTable = "elchi_shield_audit"
	// defaultTTLDays matches the collector's RETENTION_DAYS default (7) so audit
	// and api-event retention line up across the platform.
	defaultTTLDays = 7
)

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
	ttlDays   int

	mu      sync.Mutex
	batch   driver.Batch
	pending int

	// dropped counts audit ROWS lost because ClickHouse rejected the write
	// (e.g. the server disk is full) — surfaced via FailedWrites() so the loss is
	// observable regardless of which code path (inline or ticker flush) hit it.
	dropped atomic.Uint64

	// stop signals the optional periodic-flush goroutine to exit; wg waits for it.
	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// FailedWrites returns the number of audit rows dropped because ClickHouse
// rejected the write (e.g. a full server disk). It satisfies
// audit.ExportFailCounter so the metric layer can surface sink-side losses that
// the per-call Export return value can't (batched/async writes).
func (e *Exporter) FailedWrites() uint64 { return e.dropped.Load() }

// New connects to ClickHouse using the DSN in opts, ensures the audit table
// exists, and prepares the first insert batch. When opts.FlushInterval > 0 a
// background goroutine flushes partial batches on that cadence so low-traffic
// rows land promptly instead of waiting for the batch to fill.
func New(opts audit.ExporterOptions) (*Exporter, error) {
	o, err := ch.ParseDSN(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: parse dsn: %w", err)
	}
	// A throwing materialized view aborts the source INSERT by default, so a broken
	// or absent rollup MV (e.g. its target table was dropped, or a least-privilege
	// deploy created the MV but not the rollup table) would fail EVERY audit insert
	// and silently kill the whole audit stream. Audit is best-effort: tell ClickHouse
	// to log-and-skip MV errors so a rollup problem can never take down the primary
	// audit write. (Operator DSN settings still win.)
	if o.Settings == nil {
		o.Settings = ch.Settings{}
	}
	if _, set := o.Settings["materialized_views_ignore_errors"]; !set {
		o.Settings["materialized_views_ignore_errors"] = 1
	}
	// Server-side insert batching. Many edge sidecars each stream audit rows to the
	// same central ClickHouse; without batching every flush creates a fresh part, so
	// part/merge pressure scales with the edge count (the classic many-small-inserts
	// anti-pattern). async_insert tells ClickHouse to coalesce inserts across ALL
	// writers into larger parts, and wait_for_async_insert=0 lets shield's insert
	// return without blocking on the server-side flush. Audit is already async +
	// drop-on-full + sampled, so the small in-flight window an async buffer can lose
	// on a ClickHouse crash is acceptable. (Operator DSN settings still win.)
	if _, set := o.Settings["async_insert"]; !set {
		o.Settings["async_insert"] = 1
	}
	if _, set := o.Settings["wait_for_async_insert"]; !set {
		o.Settings["wait_for_async_insert"] = 0
	}
	// Best-effort: create the target database if it doesn't exist yet on a fresh
	// central ClickHouse (the collector/installer normally provisions it) via a
	// transient connection to the always-present `default` DB — mirroring
	// elchi-collector's bootstrap. Swallow the error: a hardened, least-privilege
	// shield user may lack the CREATE DATABASE grant (the grant is checked even for
	// the IF-NOT-EXISTS no-op). When the DB already exists this is a harmless no-op;
	// when it's genuinely missing and uncreatable, the readiness gate below
	// (PrepareBatch) fails and buildAuditor degrades observably. Never block boot.
	if db := o.Auth.Database; db != "" && db != "default" {
		_ = ensureDatabase(o, db)
	}
	conn, err := ch.Open(o)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: open: %w", err)
	}
	return newExporter(conn, opts)
}

// ensureDatabase creates the target database via a short-lived connection to the
// `default` database (which always exists), so the main connection can then bind
// to it. The db name comes from the operator's DSN (not user input); it is
// backtick-quoted defensively.
func ensureDatabase(o *ch.Options, db string) error {
	admin := *o // shallow copy; only the default database differs
	admin.Auth.Database = "default"
	c, err := ch.Open(&admin)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.Exec(ctx, "CREATE DATABASE IF NOT EXISTS `"+db+"`")
}

// newExporter builds the exporter over an already-open connection. It is split
// out from New so tests can inject a fake driver.Conn and exercise the batching/
// recovery logic without a live ClickHouse.
func newExporter(conn driver.Conn, opts audit.ExporterOptions) (*Exporter, error) {
	table := opts.Table
	if table == "" {
		table = defaultTable
	}
	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}
	ttlDays := opts.TTLDays
	if ttlDays <= 0 {
		ttlDays = defaultTTLDays
	}

	e := &Exporter{conn: conn, table: table, batchSize: batchSize, ttlDays: ttlDays, stop: make(chan struct{})}
	// Best-effort schema bootstrap (CREATE TABLE + idempotent ALTERs). Swallow
	// errors so a least-privilege INSERT-only user against a pre-provisioned table
	// still works; PrepareBatch below is the real readiness gate (it needs only
	// INSERT). If the table genuinely can't be used, PrepareBatch fails and the
	// caller degrades to no-audit (non-fatal).
	e.ensureTable(context.Background())
	if err := e.newBatch(context.Background()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if opts.FlushInterval > 0 {
		e.wg.Add(1)
		go e.flushLoop(opts.FlushInterval)
	}
	return e, nil
}

// ensureTable best-effort provisions the schema. Errors are intentionally
// swallowed (not returned): a least-privilege INSERT-only user can't run DDL,
// but the table is normally provisioned centrally and PrepareBatch (INSERT) is
// the real readiness gate. A genuinely-missing/unusable table surfaces there.
func (e *Exporter) ensureTable(ctx context.Context) {
	// Storage is kept small at the source: repetitive columns use
	// LowCardinality(String) (dictionary-encoded), the timestamp uses
	// DoubleDelta+ZSTD, and the free-text/high-cardinality columns use ZSTD — the
	// same shape the collector's api_events_raw uses. Combined with daily
	// PARTITION BY + the row TTL, this bounds the table both in size (compression)
	// and in time (old partitions are dropped whole). Ingest VOLUME is throttled
	// separately on the shield side (per-policy sampling_rate + --audit-max-per-sec
	// for the allow stream; findings are always kept).
	ddl := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		ts DateTime64(3) CODEC(DoubleDelta, ZSTD),
		instance LowCardinality(String),
		node_id LowCardinality(String),
		project_id LowCardinality(String),
		listener LowCardinality(String),
		request_id String CODEC(ZSTD),
		phase LowCardinality(String),
		direction LowCardinality(String),
		action LowCardinality(String),
		severity LowCardinality(String),
		reason String CODEC(ZSTD),
		rule_id LowCardinality(String),
		policy_id LowCardinality(String),
		engine LowCardinality(String),
		host LowCardinality(String),
		path String CODEC(ZSTD),
		method LowCardinality(String),
		status_code UInt16 CODEC(ZSTD),
		config_version LowCardinality(String)
	) ENGINE = MergeTree
	PARTITION BY toYYYYMMDD(ts)
	ORDER BY (project_id, ts)
	TTL toDateTime(ts) + INTERVAL %d DAY`, e.table, e.ttlDays)
	_ = e.conn.Exec(ctx, ddl)
	// Idempotently add the columns a CREATE-IF-NOT-EXISTS would skip on a table
	// from an older shield version. Without this, an upgrade against a
	// pre-existing table would INSERT 19 values into a narrower table and fail on
	// every event. (ORDER BY/PARTITION can't be retrofitted in place — a layout
	// change needs a fresh/renamed table; the columns are what the INSERT needs.)
	// Types mirror the CREATE above so a migrated table matches a fresh one.
	for _, col := range []string{
		"node_id LowCardinality(String)", "project_id LowCardinality(String)",
		"listener LowCardinality(String)", "status_code UInt16",
	} {
		_ = e.conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s", e.table, col))
	}
	e.ensureRollup(ctx)
}

// ensureRollup best-effort provisions a per-minute AggregatingMergeTree rollup
// (`<table>_1m`) and a materialized view that forward-fills it from the raw
// table — mirroring the collector's api_events_1m. The rollup carries exactly the
// dimensions the backend summary groups/filters by (project_id, node_id, engine,
// action, severity) so a wide-window summary can aggregate it via countMerge
// instead of scanning raw rows. The MV only sees inserts made AFTER it exists (no
// backfill — that keeps it multi-instance-safe, since every edge runs this), so
// the summary is exact for data ingested once the rollup is in place. The backend
// reads it only when explicitly enabled (default off), so this is a no-op until an
// operator opts in. Errors are swallowed like the rest of ensureTable.
func (e *Exporter) ensureRollup(ctx context.Context) {
	rollup := e.table + "_1m"
	// `bucket` is deliberately second-resolution DateTime (1-minute buckets need no
	// sub-second); toStartOfMinute(ts) of the raw DateTime64(3) casts losslessly.
	// TTL is on `bucket` and pinned to the SAME retention as raw (e.ttlDays) — unlike
	// the collector's 1m rollup (30d > raw 7d), shield's rollup is purely a scan-cost
	// optimization over the raw window, NOT an extended-history store.
	_ = e.conn.Exec(ctx, fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		bucket DateTime CODEC(DoubleDelta, ZSTD),
		project_id LowCardinality(String),
		node_id LowCardinality(String),
		engine LowCardinality(String),
		action LowCardinality(String),
		severity LowCardinality(String),
		events_count AggregateFunction(count)
	) ENGINE = AggregatingMergeTree
	PARTITION BY toYYYYMMDD(bucket)
	ORDER BY (project_id, node_id, engine, action, severity, bucket)
	TTL bucket + INTERVAL %d DAY`, rollup, e.ttlDays))
	// Exclude empty-project rows (Envoy sent no node attribute): the backend always
	// scopes by a non-empty project_id, so they'd be dead aggregate state nothing
	// reads. `CREATE MATERIALIZED VIEW IF NOT EXISTS` is multi-instance-idempotent
	// (one MV per DB by name) so the many edges sharing a central CH don't double-count.
	_ = e.conn.Exec(ctx, fmt.Sprintf(`CREATE MATERIALIZED VIEW IF NOT EXISTS %s_mv TO %s AS
	SELECT
		toStartOfMinute(ts) AS bucket,
		project_id, node_id, engine, action, severity,
		countState() AS events_count
	FROM %s
	WHERE project_id != ''
	GROUP BY bucket, project_id, node_id, engine, action, severity`, rollup, rollup, e.table))
}

// flushLoop periodically flushes any buffered rows until Close signals stop.
func (e *Exporter) flushLoop(interval time.Duration) {
	defer e.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			_ = e.Flush(context.Background())
		}
	}
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

// Export appends an event to the current batch. When the batch fills it is
// detached under the lock and sent OUTSIDE the lock, so concurrent audit workers
// pipeline their network Sends instead of serializing on the batch mutex (the
// Send of a full batch is the dominant cost; PrepareBatch of the replacement is
// small and stays under the lock).
func (e *Exporter) Export(ctx context.Context, ev *audit.Event) error {
	e.mu.Lock()
	if e.batch == nil {
		// A previous PrepareBatch failed and left no batch; recover before append.
		if err := e.newBatch(ctx); err != nil {
			e.dropped.Add(1)
			e.mu.Unlock()
			return nil
		}
	}
	d := ev.Decision
	if err := e.batch.Append(
		ev.Timestamp, ev.Instance, ev.NodeID, ev.ProjectID, ev.Listener,
		ev.RequestID, ev.Phase, ev.Direction,
		d.Action.String(), d.Severity.String(), d.Reason, d.RuleID, d.PolicyID, d.Engine,
		ev.Host, ev.Path, ev.Method, uint16(d.StatusCode), ev.ConfigVersion,
	); err != nil {
		// A failed Append can poison the whole batch, so renewing it discards this
		// row AND the rows already staged in it. Count all of them (pending + the
		// failed one) so FailedWrites() doesn't under-report the silent loss. One bad
		// row can't wedge the exporter; audit never reports up the request path.
		e.dropped.Add(uint64(e.pending) + 1)
		e.renewBatch(ctx)
		e.mu.Unlock()
		return nil
	}
	e.pending++
	if e.pending < e.batchSize {
		e.mu.Unlock()
		return nil
	}
	batch, n := e.detachLocked(ctx)
	e.mu.Unlock()
	e.send(batch, n) // network round-trip OUTSIDE the lock
	return nil
}

// detachLocked removes the full batch for sending and prepares a fresh one for
// continued appends, both under e.mu; the caller sends the returned batch with
// the lock released. Must hold e.mu.
func (e *Exporter) detachLocked(ctx context.Context) (driver.Batch, int) {
	b, n := e.batch, e.pending
	e.renewBatch(ctx)
	return b, n
}

// renewBatch prepares a fresh empty batch (resetting pending), or leaves e.batch
// nil if PrepareBatch fails so the next Export re-prepares. Must hold e.mu.
func (e *Exporter) renewBatch(ctx context.Context) {
	b, err := e.conn.PrepareBatch(ctx, "INSERT INTO "+e.table)
	if err != nil {
		e.batch, e.pending = nil, 0
		return
	}
	e.batch, e.pending = b, 0
}

// send flushes a detached batch with the lock released. A failure (e.g. a full
// ClickHouse disk) loses the whole batch; the rows are counted so the loss is
// observable via FailedWrites() → audit_export_errors_total, and swallowed so
// audit stays fully off the request path. Safe to call concurrently: each batch
// is owned by exactly one caller and clickhouse-go pools the connections, so two
// workers can Send different batches at once.
func (e *Exporter) send(b driver.Batch, n int) {
	if b == nil || n == 0 {
		return
	}
	if err := b.Send(); err != nil {
		e.dropped.Add(uint64(n))
	}
}

// Flush sends any buffered rows (called by the periodic ticker).
func (e *Exporter) Flush(ctx context.Context) error {
	e.mu.Lock()
	if e.pending == 0 {
		e.mu.Unlock()
		return nil
	}
	b, n := e.detachLocked(ctx)
	e.mu.Unlock()
	e.send(b, n)
	return nil
}

// Close stops the periodic-flush goroutine, flushes any buffered rows, and
// closes the connection. It is idempotent: the teardown runs at most once, so a
// second Close never re-flushes or double-closes the connection.
func (e *Exporter) Close() error {
	var err error
	e.closeOnce.Do(func() {
		close(e.stop)
		e.wg.Wait()
		e.mu.Lock()
		b, n := e.batch, e.pending
		e.batch, e.pending = nil, 0
		conn := e.conn
		e.mu.Unlock()
		e.send(b, n) // final flush outside the lock
		err = conn.Close()
	})
	return err
}
