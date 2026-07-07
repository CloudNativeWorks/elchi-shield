package stages

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"io"
	"strings"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
)

// maxDecodedBodyBytes bounds the decompressed body size so a compression bomb
// (a tiny gzip that expands to gigabytes) cannot exhaust memory. A body whose
// decoded form exceeds this is treated like a truncated body: it cannot be fully
// inspected, so an enforcing policy blocks it. 8 MiB comfortably exceeds the
// default 1 MiB raw body cap while staying bounded.
const maxDecodedBodyBytes = 8 << 20

// bodyContentDecode is a STRUCTURAL body-phase stage (always prepended, right
// after the truncation guard, and non-skippable) that decodes a Content-Encoded
// request/response body so the WAF and body checks inspect the actual payload
// rather than opaque compressed bytes — closing a classic WAF bypass where a
// gzip'd attack payload sails through unmatched.
//
// gzip and deflate (zlib- or raw-flate-wrapped) are decompressed, bounded by
// maxDecodedBodyBytes. Any other non-identity encoding (br, compress, multiple
// stacked encodings) cannot be decoded here, so — like the truncation guard — it
// blocks under an enforcing policy rather than letting an un-inspectable body
// through as "clean". Operators may also place an Envoy decompressor filter
// ahead of ext_proc, in which case the body arrives already decoded with no
// Content-Encoding and this stage is a no-op.
type bodyContentDecode struct{}

// BodyContentDecode returns the structural content-decoding stage.
func BodyContentDecode() pipeline.Stage { return bodyContentDecode{} }

func (bodyContentDecode) Name() string          { return "body_content_decode" }
func (bodyContentDecode) Phase() pipeline.Phase { return pipeline.PhaseBody }

func (bodyContentDecode) Process(_ context.Context, tx *pipeline.Transaction) pipeline.StageResult {
	p := tx.Policy
	if p == nil || !p.Enforcing() {
		return pipeline.Continue()
	}
	enc, ok := tx.Header("content-encoding")
	if !ok {
		return pipeline.Continue()
	}
	// Multiple Content-Encoding header lines are a stacked encoding (e.g. an outer
	// gzip over an inner br), just split across headers instead of comma-joined.
	// tx.Header returns only the first, so decoding it would hand the still-encoded
	// inner layer to the WAF as "clean" — block fail-closed like any stacked encoding.
	if tx.HeaderCount("content-encoding") > 1 {
		return denyEngine(tx, engineBodyDecode, "body.undecodable_encoding",
			"body uses stacked content-encodings that cannot be inspected", decision.SeverityMedium)
	}
	enc = strings.ToLower(strings.TrimSpace(enc))
	if enc == "" || enc == "identity" {
		return pipeline.Continue()
	}
	body := tx.Body()
	if len(body) == 0 {
		return pipeline.Continue()
	}

	decoded, err := decodeBody(enc, body)
	if err != nil {
		// Unsupported/stacked encoding or corrupt stream → cannot inspect the real
		// payload. Fail closed: block rather than inspect opaque bytes.
		return denyEngine(tx, engineBodyDecode, "body.undecodable_encoding",
			"body uses an encoding that cannot be inspected: "+enc, decision.SeverityMedium)
	}
	// Charge the decompression expansion against the shared in-flight body budget,
	// so a flood of small gzip bombs (each expanding to MiBs) can't exhaust memory
	// across streams even though their compressed bytes were tiny. On exhaustion,
	// fail closed rather than hold the decoded body.
	if extra := int64(len(decoded)) - int64(len(body)); extra > 0 && !tx.ReserveBody(extra) {
		return denyEngine(tx, engineBodyDecode, "body.decode_budget",
			"decoded body exceeds the in-flight inspection budget", decision.SeverityMedium)
	}
	tx.ReplaceBody(decoded)
	return pipeline.Continue()
}

// decodeBody decompresses a single supported Content-Encoding, bounded by
// maxDecodedBodyBytes. It rejects unknown or stacked encodings.
func decodeBody(enc string, body []byte) ([]byte, error) {
	switch enc {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer func() { _ = zr.Close() }()
		return readBounded(zr)
	case "deflate":
		// HTTP "deflate" is officially zlib-wrapped, but some clients send raw
		// DEFLATE. If the bytes ARE a valid zlib stream, decode them as zlib and
		// return that result verbatim — including a bounded-size (bomb) or corrupt
		// error, which must block. Only fall back to raw flate when the bytes are not
		// a zlib stream at all. (Previously a zlib bomb's size error fell through and
		// triggered a second full raw-flate decompression, doubling the work and
		// risking a clean-but-wrong inspected body while the real payload passed on.)
		if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			defer func() { _ = zr.Close() }()
			return readBounded(zr)
		}
		fr := flate.NewReader(bytes.NewReader(body))
		defer func() { _ = fr.Close() }()
		return readBounded(fr)
	default:
		// br (brotli), compress (LZW), and any comma-separated stack are not
		// decoded here.
		return nil, errUnsupportedEncoding
	}
}

// errUnsupportedEncoding marks a Content-Encoding this stage cannot decode.
var errUnsupportedEncoding = encodingError("unsupported content-encoding")

type encodingError string

func (e encodingError) Error() string { return string(e) }

// readBounded reads from r up to maxDecodedBodyBytes. If the stream produces
// more (a decompression bomb), it returns an error so the caller fails closed.
func readBounded(r io.Reader) ([]byte, error) {
	// Read one extra byte to detect overflow past the cap.
	limited := io.LimitReader(r, maxDecodedBodyBytes+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(out) > maxDecodedBodyBytes {
		return nil, encodingError("decoded body exceeds inspection limit")
	}
	return out, nil
}
