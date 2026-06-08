package matcher

import "testing"

// FuzzHostMatch fuzzes host pattern compilation and matching against arbitrary
// authority strings (attacker-controlled headers run through these every
// request). Neither must ever panic.
func FuzzHostMatch(f *testing.F) {
	f.Add("*.example.com", "api.example.com")
	f.Add("api.example.com", "evil@api.example.com:443")
	f.Add("*.例え.jp", "a.例え.jp.")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, pattern, host string) {
		h, err := CompileHost(pattern)
		if err != nil {
			return
		}
		_ = h.Match(host)
		_ = NormalizeHost(host)
		_ = h.Specificity()
	})
}

// FuzzPathMatch fuzzes path matcher compilation/matching with arbitrary inputs.
func FuzzPathMatch(f *testing.F) {
	f.Add("/exact", "/v1/", "^/admin/.*$", "/v1/users/42")
	f.Add("", "", "(bad[regex", "/%2e%2e/")
	f.Fuzz(func(t *testing.T, exact, prefix, regex, path string) {
		p, err := CompilePath(exact, prefix, regex)
		if err != nil {
			return
		}
		_ = p.Match(path)
		_ = p.Specificity()
	})
}

// FuzzContentType fuzzes content-type compilation/matching.
func FuzzContentType(f *testing.F) {
	f.Add("application/json", "application/json; charset=utf-8")
	f.Add("*/*", "")
	f.Fuzz(func(t *testing.T, pattern, value string) {
		ct := CompileContentTypes([]string{pattern})
		_ = ct.Match(value)
	})
}
