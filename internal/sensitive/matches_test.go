package sensitive

import "testing"

func TestMatchesOffsetsAndKinds(t *testing.T) {
	d := New()
	body := []byte("card 4111 1111 1111 1111 and email a@b.com plus ssn 123-45-6789")
	ms := d.Matches(body)

	got := map[string]bool{}
	for _, m := range ms {
		got[m.Kind] = true
		// offsets must be within bounds and non-empty
		if m.Start < 0 || m.End > len(body) || m.Start >= m.End {
			t.Fatalf("bad offsets for %s: %d-%d", m.Kind, m.Start, m.End)
		}
		if string(body[m.Start:m.End]) == "" {
			t.Fatalf("empty match span for %s", m.Kind)
		}
	}
	for _, want := range []string{"credit_card", "email", "ssn"} {
		if !got[want] {
			t.Errorf("expected a %s match, got %v", want, got)
		}
	}
}

func TestMatchesSortedNonOverlapping(t *testing.T) {
	d := New()
	body := []byte("a@b.com x@y.org 4111111111111111")
	ms := d.Matches(body)
	for i := 1; i < len(ms); i++ {
		if ms[i].Start < ms[i-1].End {
			t.Fatalf("matches overlap or unsorted: %+v", ms)
		}
	}
}

func TestMatchesEmpty(t *testing.T) {
	d := New()
	if ms := d.Matches([]byte("nothing sensitive here")); len(ms) != 0 {
		t.Fatalf("expected no matches, got %+v", ms)
	}
	if ms := d.Matches(nil); ms != nil {
		t.Fatal("nil body should yield nil")
	}
}
