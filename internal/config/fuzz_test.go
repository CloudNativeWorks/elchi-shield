package config

import "testing"

// FuzzParse fuzzes the config parser with arbitrary bytes. Config files arrive
// from elchi-client (attacker-adjacent), so the parser must never panic — it
// must only ever return a value or an error. Seeded from the example configs and
// a few malformed shapes.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`apiVersion: sentinel.elchi.io/v1
kind: SecurityPolicy
metadata: {name: t}
spec:
  domains:
    - host: a.com
      routes:
        - match: {path_prefix: /}
          policy: {mode: block}
`))
	f.Add([]byte(`{"apiVersion":"sentinel.elchi.io/v1","kind":"SecurityPolicy"}`))
	f.Add([]byte(`{`))
	f.Add([]byte(""))
	f.Add([]byte("apiVersion: x\n\x00\x01"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic on any input; the result/err is irrelevant to the fuzzer.
		_, _ = Parse("fuzz.yaml", data)
	})
}
