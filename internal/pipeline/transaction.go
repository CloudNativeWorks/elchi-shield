package pipeline

import (
	"strings"
	"sync"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
	"github.com/cloudnativeworks/elchi-shield/internal/policy"
	"github.com/cloudnativeworks/elchi-shield/internal/runtime"
)

// Direction distinguishes the request pipeline from the response pipeline so
// direction-aware stages (header checks, body gating, ...) can be reused.
type Direction uint8

const (
	DirectionRequest Direction = iota
	DirectionResponse
)

// String renders the direction for logs/metrics.
func (d Direction) String() string {
	if d == DirectionResponse {
		return "response"
	}
	return "request"
}

// Header is a single HTTP header. A small slice of these is cheaper than a map
// for the handful of headers a typical request carries and avoids map allocation
// on the hot path.
type Header struct {
	Name  string
	Value string
}

// BodyBudget bounds total body bytes buffered/decoded across all streams. It is
// implemented by the ext_proc server's shared budget and injected per stream so
// the decode stage can charge the bytes it materializes (a decompressed body)
// against the same process-wide bound as raw buffered bodies.
type BodyBudget interface {
	// Acquire reserves up to n bytes, returning the amount actually granted.
	Acquire(n int64) int64
	// Release returns n previously-acquired bytes.
	Release(n int64)
}

// Transaction holds all per-request state for one pipeline run. It is pooled and
// reused (see Pool); stages must keep their state here, never in the Stage
// itself. The same Transaction instance is reused by the response pipeline of
// the same stream, with Direction flipped, so the pinned request Policy/Snapshot
// remain available.
type Transaction struct {
	RequestID string
	Direction Direction

	// Snapshot is the runtime config pinned for the whole stream.
	Snapshot *runtime.Snapshot

	// Extracted request attributes (filled by the context-init stage).
	ListenerID  string
	Host        string
	Path        string
	Method      string
	ContentType string
	SourceIP    string
	Headers     []Header

	// Policy is the resolved policy for this request (filled by policy-resolve).
	// The per-request timeout from the policy is applied by the ext_proc server
	// as a context deadline, not stored here.
	Policy *policy.CompiledPolicy

	// gating flags, set by the body-gate / policy stages.
	bodyRequired bool
	wafEnabled   bool

	// bodyTruncated is set when the body exceeded the policy size cap during
	// buffering (the over-limit body check acts on it).
	bodyTruncated bool

	// bodyInspected is set once the body inspect pipeline has run for the current
	// direction, so the body is inspected exactly once whether the terminal
	// end-of-stream arrives on the headers, a body chunk, or the trailers message.
	bodyInspected bool

	// bodyReserved is the cumulative bytes this stream has reserved from the
	// shared body budget (charged as chunks are buffered, released at stream end).
	// It is server-owned bookkeeping kept here because the Transaction is the
	// per-stream state holder.
	bodyReserved int64

	// budget is the shared in-flight body-byte budget (set per stream by the
	// server); the decode stage charges materialized decoded bytes against it.
	budget BodyBudget

	// body is the bounded request/response body buffer, grown lazily only when
	// inspection is enabled.
	body []byte

	// result is the executor's running decision for the current phase. It lives on
	// the (pooled) Transaction so the common allow path returns a pointer into
	// already-heap-resident memory instead of allocating a Decision per phase. It
	// is overwritten at the start of each Pipeline.Run and consumed synchronously
	// before the next Run, so reuse across the header/body/response pipelines of a
	// stream is safe.
	result decision.Decision

	// findings holds the individual recorded (non-enforced) findings of the
	// current phase in detect/shadow mode — each already tagged with the mode
	// action — so the server can audit EVERY detection, not just the aggregate.
	// Reset at the start of each Pipeline.Run; empty in block/allow paths (a block
	// short-circuits, an allow records nothing). It is a decision slice, so the
	// Transaction stays free of any audit dependency.
	findings []decision.Decision

	// engReq is the reusable engine request view filled by the WAF stage. Pooling
	// it on the (heap-resident) Transaction avoids a per-engine-stage heap
	// allocation. The WAF stage overwrites every field before each use.
	engReq engine.Request
}

// EngineRequest returns the reusable, pooled engine.Request to fill for an engine
// inspection, avoiding a per-stage allocation. The caller must set every field.
func (tx *Transaction) EngineRequest() *engine.Request { return &tx.engReq }

// Header returns the first value of the named header (case-insensitive) and
// whether it was present.
func (tx *Transaction) Header(name string) (string, bool) {
	for i := range tx.Headers {
		if strings.EqualFold(tx.Headers[i].Name, name) {
			return tx.Headers[i].Value, true
		}
	}
	return "", false
}

// RangeHeaders calls fn for each header, stopping early if fn returns false.
// It lets engines iterate headers without copying.
func (tx *Transaction) RangeHeaders(fn func(name, value string) bool) {
	for i := range tx.Headers {
		if !fn(tx.Headers[i].Name, tx.Headers[i].Value) {
			return
		}
	}
}

// BodyRequired reports whether body-gated stages should run.
func (tx *Transaction) BodyRequired() bool { return tx.bodyRequired }

// SetBodyRequired enables/disables body-gated stages for this request.
func (tx *Transaction) SetBodyRequired(v bool) { tx.bodyRequired = v }

// WAFEnabled reports whether WAF-gated stages should run.
func (tx *Transaction) WAFEnabled() bool { return tx.wafEnabled }

// SetWAFEnabled enables/disables WAF-gated stages for this request.
func (tx *Transaction) SetWAFEnabled(v bool) { tx.wafEnabled = v }

// Findings returns the per-phase recorded (detect/shadow) findings, each tagged
// with the mode action. Empty for block/allow phases. Read-only view.
func (tx *Transaction) Findings() []decision.Decision { return tx.findings }

// AppendBody appends chunk to the bounded body buffer, never growing past max
// bytes. It returns the bytes actually stored and whether the limit was hit
// (truncated). A max of 0 stores nothing.
func (tx *Transaction) AppendBody(chunk []byte, max int64) (stored int, truncated bool) {
	if max <= 0 {
		return 0, len(chunk) > 0
	}
	remaining := max - int64(len(tx.body))
	if remaining <= 0 {
		return 0, len(chunk) > 0
	}
	if int64(len(chunk)) > remaining {
		tx.body = append(tx.body, chunk[:remaining]...)
		return int(remaining), true
	}
	tx.body = append(tx.body, chunk...)
	return len(chunk), false
}

// Body returns the buffered body bytes (read-only view).
func (tx *Transaction) Body() []byte { return tx.body }

// ReplaceBody swaps the buffered body for an inspection-ready form (e.g. the
// decompressed bytes when the request carried a Content-Encoding). The buffer is
// only ever used for inspection — never forwarded — so replacing it is safe and
// lets every downstream inspector see the decoded payload.
func (tx *Transaction) ReplaceBody(b []byte) { tx.body = b }

// BodyTruncated reports whether the body exceeded the configured size cap.
func (tx *Transaction) BodyTruncated() bool { return tx.bodyTruncated }

// SetBodyTruncated records that the body exceeded the configured size cap.
func (tx *Transaction) SetBodyTruncated(v bool) { tx.bodyTruncated = v }

// BodyInspected reports whether the body inspect pipeline already ran for the
// current direction.
func (tx *Transaction) BodyInspected() bool { return tx.bodyInspected }

// SetBodyInspected marks the body inspect pipeline as having run, so a later
// terminal message (body EOS, then trailers) does not run it twice.
func (tx *Transaction) SetBodyInspected(v bool) { tx.bodyInspected = v }

// BodyReserved reports the cumulative body-budget bytes reserved by this stream.
func (tx *Transaction) BodyReserved() int64 { return tx.bodyReserved }

// AddBodyReserved adds n to the stream's reserved-byte tally.
func (tx *Transaction) AddBodyReserved(n int64) { tx.bodyReserved += n }

// SetBudget injects the shared body budget for this stream (server-owned).
func (tx *Transaction) SetBudget(b BodyBudget) { tx.budget = b }

// ReserveBody charges n bytes against the shared budget, tracking the grant for
// release at stream end. It returns true only if the full amount was granted; a
// short grant means the process-wide body budget is exhausted and the caller
// should fail closed. A nil budget (tests / disabled) always grants.
func (tx *Transaction) ReserveBody(n int64) bool {
	if tx.budget == nil || n <= 0 {
		return true
	}
	got := tx.budget.Acquire(n)
	tx.bodyReserved += got
	return got == n
}

// PolicyID returns the resolved policy id, or "" when no policy is set.
func (tx *Transaction) PolicyID() string {
	if tx.Policy == nil {
		return ""
	}
	return tx.Policy.ID
}

// BeginResponse flips the Transaction to the response direction for the response
// pipeline of the same stream. It clears the request-specific headers, content
// type, body, and gating flags while preserving the pinned snapshot, resolved
// policy, request id, and request attributes (host/path/method) so the response
// is governed by the request's policy.
func (tx *Transaction) BeginResponse() {
	tx.Direction = DirectionResponse
	tx.Headers = tx.Headers[:0]
	tx.ContentType = ""
	tx.body = tx.body[:0]
	tx.bodyTruncated = false
	tx.bodyInspected = false
	tx.bodyRequired = false
	tx.wafEnabled = false
	// Release the request body's budget reservation now that it is no longer
	// resident, so the response body is charged against the full budget — not one
	// still counting the freed request body (which would spuriously truncate/block
	// legitimate responses under budget pressure). The stream-end release then
	// covers only the response reservation; zeroing avoids a double release.
	if tx.budget != nil && tx.bodyReserved > 0 {
		tx.budget.Release(tx.bodyReserved)
		tx.bodyReserved = 0
	}
}

// retainedBodyCap bounds the body-buffer capacity kept on a pooled Transaction.
// A single large request (up to the configured body cap, which may be MiBs) must
// not pin that much memory on every pooled Transaction indefinitely: when the
// buffer grew past this, Reset drops it so GC can reclaim it and the next large
// body reallocates. Small buffers are retained to avoid churn on the hot path.
const retainedBodyCap = 64 << 10 // 64 KiB

// retainedHeaderCap bounds the Headers-slice capacity kept on a pooled
// Transaction, so a header-flood request cannot leave a large backing array
// pinned on a pooled Transaction (multiplied across sync.Pool shards). A typical
// request has well under this many headers.
const retainedHeaderCap = 256

// Reset clears the Transaction for reuse, preserving allocated slice capacity to
// minimize future allocations (except an oversized body buffer, which is dropped
// so the pool does not retain large per-request allocations — see
// retainedBodyCap).
func (tx *Transaction) Reset() {
	tx.RequestID = ""
	tx.Direction = DirectionRequest
	tx.Snapshot = nil
	tx.ListenerID = ""
	tx.Host = ""
	tx.Path = ""
	tx.Method = ""
	tx.ContentType = ""
	tx.SourceIP = ""
	if cap(tx.Headers) > retainedHeaderCap {
		tx.Headers = nil
	} else {
		tx.Headers = tx.Headers[:0]
	}
	tx.Policy = nil
	tx.bodyRequired = false
	tx.wafEnabled = false
	tx.bodyTruncated = false
	tx.bodyInspected = false
	tx.bodyReserved = 0
	if cap(tx.body) > retainedBodyCap {
		tx.body = nil
	} else {
		tx.body = tx.body[:0]
	}
	tx.engReq = engine.Request{} // drop references to the body/headers
	tx.budget = nil
	tx.findings = tx.findings[:0]
}

// Pool recycles Transaction objects to avoid per-request allocation. It is not a
// global: callers (the ext_proc server) construct and own one Pool, satisfying
// the no-global-mutable-state rule.
type Pool struct {
	p sync.Pool
}

// NewPool returns a ready-to-use Transaction pool.
func NewPool() *Pool {
	return &Pool{p: sync.Pool{New: func() any { return &Transaction{} }}}
}

// Acquire returns a clean Transaction.
func (pool *Pool) Acquire() *Transaction {
	return pool.p.Get().(*Transaction)
}

// Release resets tx and returns it to the pool. The caller must not use tx
// afterwards.
func (pool *Pool) Release(tx *Transaction) {
	tx.Reset()
	pool.p.Put(tx)
}
