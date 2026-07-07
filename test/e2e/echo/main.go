// Configurable upstream for the e2e harness. The response is shaped by query so
// the test can exercise response inspection:
//   ?resp=json   → application/json {"ok":true}
//   ?resp=badjson→ application/json {bad
//   ?resp=pii    → text/plain with a (Luhn-valid) test credit-card number
//   ?resp=email  → text/plain with an email (redaction changes body length)
//   ?resp=coraza → text/plain leaking a marker a Coraza phase:4 rule blocks
//   (default)    → text/plain "echo <method> <path>"
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("ECHO_ADDR")
	if addr == "" {
		addr = "127.0.0.1:18080"
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "echo")
		switch r.URL.Query().Get("resp") {
		case "json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"ok":true}`)
		case "badjson":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{bad json`)
		case "pii":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "card 4111 1111 1111 1111 here")
		case "email":
			// A PII value whose redaction CHANGES the body length (unlike a
			// same-length card mask) — exercises Content-Length recompute.
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "contact user@example.com for support")
		case "coraza":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "internal leak: CORAZA_RESP_HIT in payload")
		case "privkey":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, "oops -----BEGIN PRIVATE KEY-----\nMIIEvQ...\n leaked")
		default:
			_, _ = fmt.Fprintf(w, "echo %s %s\n", r.Method, r.URL.Path)
		}
	})
	_ = http.ListenAndServe(addr, nil)
}
