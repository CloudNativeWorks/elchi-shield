package stages

import (
	"bytes"
	"compress/gzip"
	"testing"
)

// FuzzDecodeBody fuzzes the Content-Encoding decoder, which decompresses
// attacker-controlled gzip/deflate bytes — the prime body-inspection DoS surface.
// It must never panic and must stay bounded (decompression bombs are rejected by
// readBounded). Seeded with a valid gzip stream and malformed inputs.
func FuzzDecodeBody(f *testing.F) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"q":"hello"}`))
	_ = zw.Close()
	f.Add("gzip", buf.Bytes())
	f.Add("deflate", []byte("\x78\x9c\x03\x00\x00\x00\x00\x01"))
	f.Add("gzip", []byte("not gzip at all"))
	f.Add("br", []byte{0, 1, 2})
	f.Add("", []byte(""))

	f.Fuzz(func(t *testing.T, enc string, body []byte) {
		out, err := decodeBody(enc, body)
		if err == nil && len(out) > maxDecodedBodyBytes {
			t.Fatalf("decoded body %d exceeds the bomb cap %d", len(out), maxDecodedBodyBytes)
		}
	})
}
