package graphql

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

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

func TestFragmentBombBounded(t *testing.T) {
	// A non-cyclic fragment fan-out (each Fi spreads F(i+1) twice) expands to 2^n
	// nodes. The node budget must abort and block in well under a second, not hang.
	var b strings.Builder
	b.WriteString("query { ...F0 } ")
	const n = 40
	for i := range n {
		fmt.Fprintf(&b, "fragment F%d on T { ...F%d ...F%d } ", i, i+1, i+1)
	}
	fmt.Fprintf(&b, "fragment F%d on T { x }", n)
	e, _ := New(Config{MaxDepth: 1000, MaxTotalFields: 100000})
	req := &engine.Request{Direction: engine.DirectionRequest, Method: "POST", Path: "/graphql",
		ContentType: "application/graphql", Body: []byte(b.String()), Headers: hdrs{}}

	done := make(chan decision.Verdict, 1)
	go func() { v, _ := e.Inspect(context.Background(), req); done <- v }()
	select {
	case v := <-done:
		if v.RuleID != "graphql.complexity" {
			t.Fatalf("fragment bomb should be blocked as too complex, got %+v", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fragment bomb hung the guard (node budget not enforced)")
	}
}

func TestRootFieldsThroughFragmentNotBypassed(t *testing.T) {
	// Wrapping root fields in a top-level fragment / inline fragment must NOT dodge
	// MaxRootFields — they are still root fields.
	e, _ := New(Config{MaxRootFields: 2})
	viaFragment := jsonQ(`query { ...R } fragment R on Query { a b c }`)
	if v := inspect(t, e, post(viaFragment)); v.RuleID != "graphql.root_fields" {
		t.Fatalf("root fields via a fragment spread should still count, got %+v", v)
	}
	viaInline := jsonQ(`query { ... on Query { a b c } }`)
	if v := inspect(t, e, post(viaInline)); v.RuleID != "graphql.root_fields" {
		t.Fatalf("root fields via an inline fragment should still count, got %+v", v)
	}
}

func TestOperationsPerDocumentCapped(t *testing.T) {
	// Many operations inside ONE query document (not a JSON batch array) are capped.
	e, _ := New(Config{MaxOperations: 2, MaxDepth: 10})
	q := jsonQ(`query A { a } query B { b } query C { c }`)
	if v := inspect(t, e, post(q)); v.RuleID != "graphql.operations" {
		t.Fatalf("3 operations in one document should block, got %+v", v)
	}
}

func TestGraphQLOverGET(t *testing.T) {
	// A deep query moved to GET (?query=) must still be inspected, not bypass the
	// guard by avoiding POST.
	e, _ := New(Config{MaxDepth: 3})
	deep := url.QueryEscape(`{ a { b { c { d } } } }`) // depth 4
	get := &engine.Request{Direction: engine.DirectionRequest, Method: "GET",
		Path: "/graphql?query=" + deep, ContentType: "", Headers: hdrs{}}
	if v := inspect(t, e, get); v.RuleID != "graphql.depth" {
		t.Fatalf("deep query over GET should block, got %+v", v)
	}
	// A GET without a query param passes (not a GraphQL request).
	plain := &engine.Request{Direction: engine.DirectionRequest, Method: "GET", Path: "/graphql", Headers: hdrs{}}
	if v := inspect(t, e, plain); v.Action == decision.Block {
		t.Fatal("a GET without a query param must pass through")
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
