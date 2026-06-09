// Package graphql implements a body-phase GraphQL security guard: it parses the
// query once and enforces configurable abuse limits — maximum selection depth,
// alias count, root/total field counts, batched-operation count, and an
// introspection block — with a fragment-cycle bound so the guard cannot itself
// be DoS'd. It is pure-Go (vektah/gqlparser) and ships in the lean binary.
//
// The engine only acts on requests that look like GraphQL (POST + a matching
// content-type, and an optional path allow-list); anything else passes straight
// through so non-GraphQL routes are never penalized.
package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

const engineName = "graphql"

// Config configures the GraphQL guard. A zero limit disables that specific check.
type Config struct {
	ContentTypes       []string // default: application/json, application/graphql
	Paths              []string // optional path prefixes; empty = any path
	MaxDepth           int
	MaxAliases         int
	MaxRootFields      int
	MaxTotalFields     int
	MaxOperations      int // batched (JSON array) operation cap; 0 → 1
	BlockIntrospection bool
	MaxFragmentDepth   int // fragment-spread recursion bound (default 32)
	// MaxComplexity bounds the TOTAL selection nodes walked per operation (after
	// fragment expansion). It is a hard backstop against a fragment "bomb" — a
	// tiny query whose fragments fan out to exponential nodes — that the
	// cycle-only bound cannot stop. Default 100000; always enforced.
	MaxComplexity int
}

// defaultMaxComplexity is the per-operation node-visit budget when MaxComplexity
// is unset. Generous for real queries (hundreds–thousands of nodes), tight
// enough that an expanding fragment bomb aborts in well under a millisecond.
const defaultMaxComplexity = 100000

// Engine is the compiled, immutable GraphQL guard.
type Engine struct {
	contentTypes []string
	paths        []string
	cfg          Config
	maxFragDepth int
	maxNodes     int
}

// New compiles the configuration into an Engine.
func New(cfg Config) (*Engine, error) {
	cts := cfg.ContentTypes
	if len(cts) == 0 {
		cts = []string{"application/json", "application/graphql"}
	}
	for i := range cts {
		cts[i] = strings.ToLower(cts[i])
	}
	fragDepth := cfg.MaxFragmentDepth
	if fragDepth <= 0 {
		fragDepth = 32
	}
	maxNodes := cfg.MaxComplexity
	if maxNodes <= 0 {
		maxNodes = defaultMaxComplexity
	}
	return &Engine{contentTypes: cts, paths: cfg.Paths, cfg: cfg, maxFragDepth: fragDepth, maxNodes: maxNodes}, nil
}

// Name implements engine.SecurityEngine.
func (*Engine) Name() string { return engineName }

// RequiresBody implements engine.SecurityEngine: the guard parses the body.
func (*Engine) RequiresBody() bool { return true }

// Close implements engine.SecurityEngine.
func (*Engine) Close() error { return nil }

// Inspect parses and checks a GraphQL request. Non-GraphQL requests and
// responses pass through.
func (e *Engine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	if req.Direction != engine.DirectionRequest || req.Method != http.MethodPost {
		return decision.Verdict{}, nil
	}
	if !e.gated(req) {
		return decision.Verdict{}, nil
	}
	queries, ok := extractQueries(req)
	if !ok {
		return decision.Verdict{}, nil // not a recognizable GraphQL body → don't penalize
	}
	if e.cfg.MaxOperations > 0 && len(queries) > e.cfg.MaxOperations {
		return block("graphql.batch", fmt.Sprintf("batched operations %d exceed max %d", len(queries), e.cfg.MaxOperations)), nil
	}
	for _, q := range queries {
		if v, blocked := e.checkQuery(q); blocked {
			return v, nil
		}
	}
	return decision.Verdict{}, nil
}

// gated reports whether the request matches the GraphQL content-type (and path
// allow-list, if configured).
func (e *Engine) gated(req *engine.Request) bool {
	ct := strings.ToLower(req.ContentType)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if !slices.Contains(e.contentTypes, ct) {
		return false
	}
	if len(e.paths) == 0 {
		return true
	}
	path := pathOnly(req.Path)
	for _, p := range e.paths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// checkQuery parses one GraphQL document and enforces the limits.
func (e *Engine) checkQuery(q string) (decision.Verdict, bool) {
	if strings.TrimSpace(q) == "" {
		return decision.Verdict{}, false
	}
	doc, err := parser.ParseQuery(&ast.Source{Input: q, Name: "query"})
	if err != nil {
		return block("graphql.parse_error", "GraphQL query failed to parse"), true
	}
	fragments := make(map[string]*ast.FragmentDefinition, len(doc.Fragments))
	for _, f := range doc.Fragments {
		fragments[f.Name] = f
	}
	// A single document can carry many operations; cap them here too (the JSON
	// batch array is capped separately in Inspect) so a thousand operations in one
	// query can't each trigger a full walk.
	if e.cfg.MaxOperations > 0 && len(doc.Operations) > e.cfg.MaxOperations {
		return block("graphql.operations", fmt.Sprintf("operations %d exceed max %d", len(doc.Operations), e.cfg.MaxOperations)), true
	}
	for _, op := range doc.Operations {
		st := &stats{}
		visited := make(map[string]int)
		e.walk(op.SelectionSet, 1, fragments, visited, st)

		// A bomb that blew the node budget is blocked rather than analyzed further.
		if st.aborted {
			return block("graphql.complexity", "query is too complex to analyze safely"), true
		}
		if e.cfg.MaxRootFields > 0 && st.rootFields > e.cfg.MaxRootFields {
			return block("graphql.root_fields", "too many root fields"), true
		}
		if e.cfg.MaxDepth > 0 && st.depth > e.cfg.MaxDepth {
			return block("graphql.depth", fmt.Sprintf("query depth %d exceeds max %d", st.depth, e.cfg.MaxDepth)), true
		}
		if e.cfg.MaxAliases > 0 && st.aliases > e.cfg.MaxAliases {
			return block("graphql.aliases", "too many aliases"), true
		}
		if e.cfg.MaxTotalFields > 0 && st.fields > e.cfg.MaxTotalFields {
			return block("graphql.total_fields", "too many fields"), true
		}
		if e.cfg.BlockIntrospection && st.introspection {
			return block("graphql.introspection", "introspection is not allowed"), true
		}
	}
	return decision.Verdict{}, false
}

type stats struct {
	depth         int
	fields        int
	rootFields    int // fields at depth 1, counted THROUGH top-level fragments
	aliases       int
	introspection bool
	nodes         int  // total selections visited (fragment-expanded)
	aborted       bool // node budget exceeded → stop and block
}

// walk is a depth-first traversal accumulating stats. Fragment spreads are
// followed with a per-fragment recursion bound (cycle guard) AND a total
// node-visit budget (st.nodes vs e.maxNodes) so neither a cyclic fragment nor a
// non-cyclic fragment that fans out exponentially can hang the guard.
func (e *Engine) walk(sel ast.SelectionSet, depth int, frags map[string]*ast.FragmentDefinition, visited map[string]int, st *stats) {
	if st.aborted {
		return
	}
	if depth > st.depth {
		st.depth = depth
	}
	for _, s := range sel {
		st.nodes++
		if st.nodes > e.maxNodes {
			st.aborted = true
			return
		}
		switch f := s.(type) {
		case *ast.Field:
			st.fields++
			// Root fields are those at depth 1, including ones exposed via a
			// top-level fragment spread or inline fragment (both walked at the same
			// depth) — so MaxRootFields can't be dodged by wrapping them in a
			// fragment.
			if depth == 1 {
				st.rootFields++
			}
			if f.Alias != "" && f.Alias != f.Name {
				st.aliases++
			}
			if f.Name == "__schema" || f.Name == "__type" {
				st.introspection = true
			}
			if len(f.SelectionSet) > 0 {
				e.walk(f.SelectionSet, depth+1, frags, visited, st)
			}
		case *ast.InlineFragment:
			e.walk(f.SelectionSet, depth, frags, visited, st)
		case *ast.FragmentSpread:
			if visited[f.Name] >= e.maxFragDepth {
				continue
			}
			def := frags[f.Name]
			if def == nil {
				continue
			}
			visited[f.Name]++
			e.walk(def.SelectionSet, depth, frags, visited, st)
			visited[f.Name]--
		}
		if st.aborted {
			return
		}
	}
}

// extractQueries pulls the GraphQL query strings from the request body. It
// supports a single JSON object {"query": "..."}, a JSON array of such objects
// (batching), and a raw application/graphql body. Returns ok=false when the body
// is not a recognizable GraphQL payload.
func extractQueries(req *engine.Request) ([]string, bool) {
	ct := strings.ToLower(req.ContentType)
	if strings.HasPrefix(ct, "application/graphql") {
		return []string{string(req.Body)}, true
	}
	trimmed := strings.TrimSpace(string(req.Body))
	if trimmed == "" {
		return nil, false
	}
	switch trimmed[0] {
	case '{':
		var obj struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(req.Body, &obj); err != nil || obj.Query == "" {
			return nil, false
		}
		return []string{obj.Query}, true
	case '[':
		var arr []struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(req.Body, &arr); err != nil {
			return nil, false
		}
		out := make([]string, 0, len(arr))
		for _, o := range arr {
			if o.Query != "" {
				out = append(out, o.Query)
			}
		}
		return out, len(out) > 0
	}
	return nil, false
}

func pathOnly(p string) string {
	before, _, _ := strings.Cut(p, "?")
	return before
}

func block(ruleID, reason string) decision.Verdict {
	return decision.Verdict{
		Action:     decision.Block,
		Reason:     reason,
		RuleID:     ruleID,
		Engine:     engineName,
		Severity:   decision.SeverityMedium,
		StatusCode: decision.DefaultBlockStatus,
	}
}
