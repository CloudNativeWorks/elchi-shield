package redaction

import "testing"

func TestSensitiveHeaders(t *testing.T) {
	r := Default()
	for _, name := range []string{"Authorization", "authorization", "Cookie", "Set-Cookie", "X-Api-Key", "Proxy-Authorization"} {
		if !r.IsSensitiveHeader(name) {
			t.Errorf("%q should be sensitive", name)
		}
		if got := r.HeaderValue(name, "secret"); got != Mask {
			t.Errorf("HeaderValue(%q) = %q, want mask", name, got)
		}
	}
	if r.IsSensitiveHeader("X-Request-Id") {
		t.Error("X-Request-Id should not be sensitive")
	}
	if got := r.HeaderValue("X-Request-Id", "abc"); got != "abc" {
		t.Errorf("non-sensitive header changed: %q", got)
	}
}

func TestExtraSensitiveHeaders(t *testing.T) {
	r := New("X-Internal-Token")
	if !r.IsSensitiveHeader("x-internal-token") {
		t.Error("configured extra header should be sensitive")
	}
}

func TestValueRedaction(t *testing.T) {
	r := Default()
	cases := map[string]bool{
		"Bearer abc.def.ghi":            true,
		"basic dXNlcjpwYXNz":            true,
		"eyJhbGciOi.eyJzdWIiOiI.sig123": true, // JWT-shaped
		"just a normal value":           false,
		"hello":                         false,
	}
	for in, wantMasked := range cases {
		got := r.Value(in)
		if wantMasked && got != Mask {
			t.Errorf("Value(%q) = %q, want mask", in, got)
		}
		if !wantMasked && got == Mask {
			t.Errorf("Value(%q) unexpectedly masked", in)
		}
	}
}
