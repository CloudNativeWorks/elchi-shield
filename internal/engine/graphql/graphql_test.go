package graphql

import (
	"context"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

type hdrs map[string]string

func (h hdrs) Header(name string) (string, bool) { v, ok := h[name]; return v, ok }
func (h hdrs) RangeHeaders(fn func(string, string) bool) {
	for k, v := range h {
		if !fn(k, v) {
			return
		}
	}
}

func post(body string) *engine.Request {
	return &engine.Request{
		Direction: engine.DirectionRequest, Method: "POST", Path: "/graphql",
		ContentType: "application/json", Body: []byte(body), Headers: hdrs{},
	}
}

func jsonQ(q string) string {
	return `{"query":` + quote(q) + `}`
}
func quote(s string) string {
	out := []byte{'"'}
	for _, r := range []byte(s) {
		switch r {
		case '"', '\\':
			out = append(out, '\\', r)
		case '\n':
			out = append(out, '\\', 'n')
		case '\t':
			out = append(out, '\\', 't')
		default:
			out = append(out, r)
		}
	}
	return string(append(out, '"'))
}

func inspect(t *testing.T, e *Engine, req *engine.Request) decision.Verdict {
	t.Helper()
	v, err := e.Inspect(context.Background(), req)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	return v
}

func TestDepthLimit(t *testing.T) {
	e, _ := New(Config{MaxDepth: 3})
	shallow := jsonQ(`{ a { b { c } } }`)    // depth 3
	deep := jsonQ(`{ a { b { c { d } } } }`) // depth 4
	if v := inspect(t, e, post(shallow)); v.Action == decision.Block {
		t.Fatalf("depth-3 query within limit should pass, got %+v", v)
	}
	if v := inspect(t, e, post(deep)); v.RuleID != "graphql.depth" {
		t.Fatalf("depth-4 query should block, got %+v", v)
	}
}

func TestAliasLimit(t *testing.T) {
	e, _ := New(Config{MaxAliases: 2})
	q := jsonQ(`{ a: f b: f c: f }`) // 3 aliases
	if v := inspect(t, e, post(q)); v.RuleID != "graphql.aliases" {
		t.Fatalf("3 aliases should block, got %+v", v)
	}
}

func TestRootFieldsLimit(t *testing.T) {
	e, _ := New(Config{MaxRootFields: 2})
	if v := inspect(t, e, post(jsonQ(`{ a b c }`))); v.RuleID != "graphql.root_fields" {
		t.Fatalf("3 root fields should block, got %+v", v)
	}
	if v := inspect(t, e, post(jsonQ(`{ a b }`))); v.Action == decision.Block {
		t.Fatal("2 root fields should pass")
	}
}

func TestIntrospectionBlock(t *testing.T) {
	e, _ := New(Config{BlockIntrospection: true})
	if v := inspect(t, e, post(jsonQ(`{ __schema { types { name } } }`))); v.RuleID != "graphql.introspection" {
		t.Fatalf("introspection should block, got %+v", v)
	}
	// __typename is allowed.
	if v := inspect(t, e, post(jsonQ(`{ a __typename }`))); v.Action == decision.Block {
		t.Fatal("__typename should not be treated as introspection")
	}
}

func TestBatchLimit(t *testing.T) {
	e, _ := New(Config{MaxOperations: 2, MaxDepth: 10})
	batch := `[{"query":"{a}"},{"query":"{b}"},{"query":"{c}"}]`
	if v := inspect(t, e, post(batch)); v.RuleID != "graphql.batch" {
		t.Fatalf("3 batched ops should block, got %+v", v)
	}
}

func TestParseError(t *testing.T) {
	e, _ := New(Config{MaxDepth: 5})
	if v := inspect(t, e, post(jsonQ(`{ a { `))); v.RuleID != "graphql.parse_error" {
		t.Fatalf("malformed query should block, got %+v", v)
	}
}

func TestFragmentCycleBounded(t *testing.T) {
	// A cyclic fragment must not hang the guard (bounded recursion).
	e, _ := New(Config{MaxDepth: 50, MaxFragmentDepth: 8})
	q := jsonQ(`query { ...A } fragment A on T { x ...B } fragment B on T { y ...A }`)
	done := make(chan decision.Verdict, 1)
	go func() { v, _ := e.Inspect(context.Background(), post(q)); done <- v }()
	select {
	case <-done:
	default:
		// give it a moment; the point is it terminates
	}
	if v := inspect(t, e, post(q)); v.Action != decision.Block && v.Action != decision.Continue {
		t.Fatalf("cyclic fragment should be handled, got %+v", v)
	}
}

func TestNonGraphQLPassThrough(t *testing.T) {
	e, _ := New(Config{MaxDepth: 1})
	// GET request → pass.
	get := &engine.Request{Direction: engine.DirectionRequest, Method: "GET", ContentType: "application/json", Headers: hdrs{}}
	if v := inspect(t, e, get); v.Action == decision.Block {
		t.Fatal("non-POST should pass through")
	}
	// Wrong content-type → pass.
	other := post(jsonQ(`{ a { b { c } } }`))
	other.ContentType = "text/plain"
	if v := inspect(t, e, other); v.Action == decision.Block {
		t.Fatal("non-GraphQL content-type should pass through")
	}
	// Non-GraphQL JSON body (no query field) → pass.
	if v := inspect(t, e, post(`{"hello":"world"}`)); v.Action == decision.Block {
		t.Fatal("JSON without a query field should pass through")
	}
}

func TestRawGraphQLContentType(t *testing.T) {
	e, _ := New(Config{MaxDepth: 2})
	req := post(`{ a { b { c } } }`)
	req.ContentType = "application/graphql"
	req.Body = []byte(`{ a { b { c } } }`)
	if v := inspect(t, e, req); v.RuleID != "graphql.depth" {
		t.Fatalf("raw application/graphql body should be analyzed, got %+v", v)
	}
}

func TestResponseDirectionPasses(t *testing.T) {
	e, _ := New(Config{MaxDepth: 1})
	v := inspect(t, e, &engine.Request{Direction: engine.DirectionResponse, Headers: hdrs{}})
	if v.Action == decision.Block {
		t.Fatal("graphql must not run on the response direction")
	}
}

func TestMetadata(t *testing.T) {
	e, _ := New(Config{MaxDepth: 1})
	if e.Name() != "graphql" || !e.RequiresBody() {
		t.Error("graphql should be a body-phase engine named graphql")
	}
	if err := e.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}
