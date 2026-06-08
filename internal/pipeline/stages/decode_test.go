package stages

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
)

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestBodyDecodeGzipExposesPayload proves a gzip'd body is decompressed so later
// inspectors see the real payload (closing the compression WAF-bypass).
func TestBodyDecodeGzipExposesPayload(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{})
	tx := &pipeline.Transaction{Policy: pol, Headers: hdrs("content-encoding", "gzip")}
	payload := []byte(`{"q":"' OR 1=1--"}`)
	tx.AppendBody(gzipBytes(t, payload), 1<<20)

	if res := BodyContentDecode().Process(bg(), tx); res.Action != pipeline.ActionContinue {
		t.Fatalf("gzip body should decode and continue, got %v", res.Action)
	}
	if !bytes.Equal(tx.Body(), payload) {
		t.Fatalf("body should be decompressed to the real payload, got %q", tx.Body())
	}
}

// TestBodyDecodeUnsupportedEncodingBlocks proves an undecodable encoding (br) is
// blocked rather than inspected as opaque bytes.
func TestBodyDecodeUnsupportedEncodingBlocks(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{})
	tx := &pipeline.Transaction{Policy: pol, Headers: hdrs("content-encoding", "br")}
	tx.AppendBody([]byte("\x00\x01\x02opaque"), 1<<20)
	if res := BodyContentDecode().Process(bg(), tx); res.Action != pipeline.ActionDeny {
		t.Fatalf("undecodable encoding must be blocked, got %v", res.Action)
	}
}

// TestBodyDecodeCorruptGzipBlocks proves a corrupt gzip stream fails closed.
func TestBodyDecodeCorruptGzipBlocks(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{})
	tx := &pipeline.Transaction{Policy: pol, Headers: hdrs("content-encoding", "gzip")}
	tx.AppendBody([]byte("not actually gzip"), 1<<20)
	if res := BodyContentDecode().Process(bg(), tx); res.Action != pipeline.ActionDeny {
		t.Fatalf("corrupt gzip must be blocked, got %v", res.Action)
	}
}

// TestBodyDecodeBombBlocks proves a decompression bomb (expands past the cap) is
// blocked instead of exhausting memory.
func TestBodyDecodeBombBlocks(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{})
	// A highly compressible payload larger than maxDecodedBodyBytes when inflated.
	bomb := gzipBytes(t, bytes.Repeat([]byte("A"), maxDecodedBodyBytes+1024))
	tx := &pipeline.Transaction{Policy: pol, Headers: hdrs("content-encoding", "gzip")}
	tx.AppendBody(bomb, int64(len(bomb))+1)
	if res := BodyContentDecode().Process(bg(), tx); res.Action != pipeline.ActionDeny {
		t.Fatalf("decompression bomb must be blocked, got %v", res.Action)
	}
}

// tinyBudget is a BodyBudget that grants at most `cap` total bytes.
type tinyBudget struct{ remaining int64 }

func (b *tinyBudget) Acquire(n int64) int64 {
	if n > b.remaining {
		n = b.remaining
	}
	if n < 0 {
		n = 0
	}
	b.remaining -= n
	return n
}
func (b *tinyBudget) Release(n int64) { b.remaining += n }

// TestBodyDecodeChargesBudget proves the decompression expansion is charged to
// the shared budget, and an exhausted budget fails closed (closing the gzip-bomb
// memory-amplification gap that a tiny compressed body would otherwise dodge).
func TestBodyDecodeChargesBudget(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{})
	payload := bytes.Repeat([]byte("A"), 4096) // compresses small, expands to 4 KiB
	tx := &pipeline.Transaction{Policy: pol, Headers: hdrs("content-encoding", "gzip")}
	tx.AppendBody(gzipBytes(t, payload), 1<<20)
	// Budget far smaller than the decoded expansion → must block.
	tx.SetBudget(&tinyBudget{remaining: 100})
	if res := BodyContentDecode().Process(bg(), tx); res.Action != pipeline.ActionDeny {
		t.Fatalf("decode exceeding the budget must be blocked, got %v", res.Action)
	}
}

// TestBodyDecodeIdentityNoop proves an identity/absent encoding leaves the body
// untouched.
func TestBodyDecodeIdentityNoop(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{})
	tx := &pipeline.Transaction{Policy: pol, Headers: hdrs("content-encoding", "identity")}
	tx.AppendBody([]byte("plain"), 1<<20)
	if res := BodyContentDecode().Process(bg(), tx); res.Action != pipeline.ActionContinue {
		t.Fatalf("identity encoding should continue, got %v", res.Action)
	}
	if string(tx.Body()) != "plain" {
		t.Fatalf("identity body must be untouched, got %q", tx.Body())
	}
}

// TestRequireJSONRejectsNonJSONContentType proves the content-type-juggling
// bypass is closed: a body under a non-JSON content-type on a require_json route
// is blocked, not waved through.
func TestRequireJSONRejectsNonJSONContentType(t *testing.T) {
	pol := compiled(config.ModeBlock, config.Checks{Body: &config.BodyChecks{RequireJSON: true}})

	// JSON-shaped body but text/plain content-type → blocked.
	tx := &pipeline.Transaction{Policy: pol, ContentType: "text/plain"}
	tx.AppendBody([]byte(`{"ok":true}`), 1<<20)
	if res := BodyChecks(nil).Process(bg(), tx); res.Action != pipeline.ActionDeny {
		t.Fatalf("non-JSON content-type on JSON-only endpoint must deny, got %v", res.Action)
	}

	// Proper JSON content-type + valid JSON → continue.
	tx2 := &pipeline.Transaction{Policy: pol, ContentType: "application/json"}
	tx2.AppendBody([]byte(`{"ok":true}`), 1<<20)
	if res := BodyChecks(nil).Process(bg(), tx2); res.Action != pipeline.ActionContinue {
		t.Fatalf("valid JSON should continue, got %v", res.Action)
	}

	// JSON content-type but invalid JSON → deny.
	tx3 := &pipeline.Transaction{Policy: pol, ContentType: "application/json"}
	tx3.AppendBody([]byte(`{bad`), 1<<20)
	if res := BodyChecks(nil).Process(bg(), tx3); res.Action != pipeline.ActionDeny {
		t.Fatalf("invalid JSON should deny, got %v", res.Action)
	}

	// Empty body on a require_json route → continue (e.g. GET).
	tx4 := &pipeline.Transaction{Policy: pol, ContentType: ""}
	if res := BodyChecks(nil).Process(bg(), tx4); res.Action != pipeline.ActionContinue {
		t.Fatalf("empty body should continue, got %v", res.Action)
	}
}

// BenchmarkBodyDecodeGzip measures the gzip decompression cost of the structural
// content-decode stage (an attacker-controlled, body-inspecting path).
func BenchmarkBodyDecodeGzip(b *testing.B) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(bytes.Repeat([]byte("A"), 8192))
	_ = zw.Close()
	body := buf.Bytes()
	pol := compiled(config.ModeBlock, config.Checks{})
	b.ReportAllocs()
	for b.Loop() {
		tx := &pipeline.Transaction{Policy: pol, Headers: hdrs("content-encoding", "gzip")}
		tx.AppendBody(body, 1<<20)
		_ = BodyContentDecode().Process(bg(), tx)
	}
}
