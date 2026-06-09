package matcher

import "testing"

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"/healthz":      "/healthz",
		"/healthz?x=1":  "/healthz", // query stripped
		"/healthz#frag": "/healthz", // fragment stripped
		"/a/../admin":   "/admin",   // dot-segments collapsed
		"//v1//x":       "/v1/x",    // duplicate slashes collapsed
		"/%61dmin":      "/admin",   // percent-decoded once
		"/v1/":          "/v1/",     // trailing slash preserved
		"/":             "/",
	}
	for in, want := range cases {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}
