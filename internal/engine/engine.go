// Package engine defines the pluggable security-engine contract and a set type
// that runs multiple engines per request and aggregates their verdicts. The
// built-in native checks (header/body) live in the stages package; engines are
// for heavier, swappable backends (Coraza, JWT policy, OpenAPI, custom
// detectors).
//
// Engines operate on a narrow, read-only Request rather than the pipeline
// Transaction, so the engine package depends only on decision. This keeps it a
// near-leaf and lets policies hold compiled engines without an import cycle.
package engine

import (
	"context"
	"errors"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
)

// ErrNotImplemented is returned by engine constructors that are not built into
// this binary (e.g. Coraza without the build tag).
var ErrNotImplemented = errors.New("engine not implemented")

// Direction distinguishes request from response inspection.
type Direction uint8

const (
	DirectionRequest Direction = iota
	DirectionResponse
)

// HeaderView gives engines read-only, case-insensitive header access plus
// iteration, without copying. It is satisfied by the pipeline Transaction.
type HeaderView interface {
	Header(name string) (value string, ok bool)
	RangeHeaders(fn func(name, value string) bool)
}

// Request is the read-only view of a transaction an engine inspects. It is built
// per WAF-stage invocation and never mutated by engines.
type Request struct {
	Direction   Direction
	Host        string
	Path        string
	Method      string
	ContentType string
	SourceIP    string // originating client IP (derived once, X-Forwarded-For/X-Real-IP)
	Body        []byte
	Headers     HeaderView
}

// SecurityEngine is a swappable inspection backend. Implementations must be safe
// for concurrent use across requests. Inspect is direction-aware (req.Direction)
// so one engine can handle both request and response inspection.
type SecurityEngine interface {
	// Name identifies the engine in decisions, audit events, and metrics.
	Name() string
	// RequiresBody reports whether the engine needs the body buffered.
	RequiresBody() bool
	// Inspect evaluates req and returns a verdict. A non-block verdict
	// (decision.Continue/Allow) means "no finding".
	Inspect(ctx context.Context, req *Request) (decision.Verdict, error)
	// Close releases engine resources (rulesets, compiled programs).
	Close() error
}

// Set is an ordered collection of engines run together for one request. It is
// immutable after construction and safe for concurrent use.
type Set struct {
	engines []SecurityEngine
}

// NewSet builds an engine set. Nil engines are dropped.
func NewSet(engines ...SecurityEngine) *Set {
	filtered := make([]SecurityEngine, 0, len(engines))
	for _, e := range engines {
		if e != nil {
			filtered = append(filtered, e)
		}
	}
	return &Set{engines: filtered}
}

// Len returns the number of engines.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.engines)
}

// Names returns the engine names in this set (for introspection/explainability).
func (s *Set) Names() []string {
	if s == nil {
		return nil
	}
	names := make([]string, len(s.engines))
	for i, e := range s.engines {
		names[i] = e.Name()
	}
	return names
}

// RequiresBody reports whether any engine needs the body buffered.
func (s *Set) RequiresBody() bool {
	if s == nil {
		return false
	}
	for _, e := range s.engines {
		if e.RequiresBody() {
			return true
		}
	}
	return false
}

// HasHeaderEngines reports whether any engine can run at header time (does not
// require the body). Such engines run in the header phase so a header-only
// policy (e.g. JWT validation) never forces the body to be buffered.
func (s *Set) HasHeaderEngines() bool {
	if s == nil {
		return false
	}
	for _, e := range s.engines {
		if !e.RequiresBody() {
			return true
		}
	}
	return false
}

// Inspect runs every engine and aggregates with "most severe wins" (see inspect).
func (s *Set) Inspect(ctx context.Context, req *Request) (decision.Verdict, error) {
	return s.inspect(ctx, req, nil)
}

// InspectHeaderPhase runs only the engines that do not require the body, so they
// can evaluate at header time (e.g. JWT). Body-requiring engines are skipped.
func (s *Set) InspectHeaderPhase(ctx context.Context, req *Request) (decision.Verdict, error) {
	return s.inspect(ctx, req, func(e SecurityEngine) bool { return !e.RequiresBody() })
}

// InspectBodyPhase runs only the engines that require the body, so they evaluate
// once the body is buffered. Header-only engines (already run at header time) are
// skipped to avoid double evaluation.
func (s *Set) InspectBodyPhase(ctx context.Context, req *Request) (decision.Verdict, error) {
	return s.inspect(ctx, req, func(e SecurityEngine) bool { return e.RequiresBody() })
}

// inspect runs the engines matching want (nil = all) and aggregates with "most
// severe wins". It returns the worst verdict seen and a joined error of any
// engine failures. A Block verdict takes precedence over errors (fail toward
// blocking on a confirmed finding); otherwise the caller applies the policy fail
// posture.
//
// The request deadline is checked before each engine so a multi-engine set
// cannot run past the policy timeout. A single synchronous engine call is not
// preempted mid-flight (Go cannot interrupt CPU-bound work, and detaching it
// would accumulate goroutines under load); it runs to completion and back-
// pressures the stream, which is the deliberate, leak-free behavior.
func (s *Set) inspect(ctx context.Context, req *Request, want func(SecurityEngine) bool) (decision.Verdict, error) {
	if s == nil {
		return decision.Verdict{}, nil
	}
	var worst decision.Verdict
	var totalScore int
	var errs []error
	for _, e := range s.engines {
		if want != nil && !want(e) {
			continue
		}
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		v, err := e.Inspect(ctx, req)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// Collaborative anomaly score, summed across engines. Only POSITIVE
		// contributions count: a negative score (a buggy/misconfigured engine) must
		// never subtract from the total and mask an attack below the threshold.
		if v.Score > 0 {
			totalScore += v.Score
		}
		if v.Action == decision.Block && v.Severity >= worst.Severity {
			worst = v
		} else if worst.Action != decision.Block && v.Severity > worst.Severity {
			worst = v
		}
	}
	worst.Score = totalScore
	return worst, errors.Join(errs...)
}

// Close closes every engine, joining any errors.
func (s *Set) Close() error {
	if s == nil {
		return nil
	}
	var errs []error
	for _, e := range s.engines {
		if err := e.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
