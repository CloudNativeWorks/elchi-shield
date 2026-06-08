package pipeline

import "context"

// StageFunc adapts a plain function into a Stage. It is used by the concrete
// stages package and by tests to build stages without a bespoke type each time.
// The wrapped function must follow the same rules as Stage.Process (stateless,
// no panics, respect ctx).
type StageFunc struct {
	name  string
	phase Phase
	fn    func(ctx context.Context, tx *Transaction) StageResult
}

// NewStageFunc wraps fn as a Stage with the given name and phase.
func NewStageFunc(name string, phase Phase, fn func(ctx context.Context, tx *Transaction) StageResult) StageFunc {
	return StageFunc{name: name, phase: phase, fn: fn}
}

// Name implements Stage.
func (s StageFunc) Name() string { return s.name }

// Phase implements Stage.
func (s StageFunc) Phase() Phase { return s.phase }

// Process implements Stage.
func (s StageFunc) Process(ctx context.Context, tx *Transaction) StageResult {
	return s.fn(ctx, tx)
}

// Builder assembles a Pipeline incrementally while preserving stage order. It is
// a cold-path convenience (used when compiling the default pipelines); the
// resulting Pipeline is immutable.
type Builder struct {
	name   string
	stages []Stage
	obs    Observer
}

// NewBuilder starts a Builder for a named pipeline.
func NewBuilder(name string) *Builder { return &Builder{name: name} }

// WithObserver sets the metrics observer (optional; defaults to no-op).
func (b *Builder) WithObserver(obs Observer) *Builder {
	b.obs = obs
	return b
}

// Add appends one or more stages in order.
func (b *Builder) Add(stages ...Stage) *Builder {
	b.stages = append(b.stages, stages...)
	return b
}

// Build validates ordering and returns the immutable Pipeline.
func (b *Builder) Build() (*Pipeline, error) {
	return New(b.name, b.stages, b.obs)
}
