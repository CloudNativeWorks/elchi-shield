package feed

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadCIDRLines(t *testing.T) {
	p := write(t, "f.txt", "# comment\n192.0.2.0/24\n198.51.100.7\n\n; another comment\n10.0.0.0/8  # inline\n")
	got, err := Load(p, FormatCIDRLines)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 prefixes, got %d: %v", len(got), got)
	}
	if got[1].String() != "198.51.100.7/32" {
		t.Errorf("bare IP should become /32, got %s", got[1])
	}
}

func TestLoadFireholNetset(t *testing.T) {
	p := write(t, "f.netset", "# FireHOL level1\n203.0.113.0/24\n2001:db8::/32\n")
	got, err := Load(p, FormatFireholNetset)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
}

func TestLoadSpamhausJSON(t *testing.T) {
	body := `; Spamhaus DROP metadata line
{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":"arin"}
{"cidr":"198.51.100.0/24","sblid":"SBL2","rir":"ripe"}
`
	p := write(t, "drop.json", body)
	got, err := Load(p, FormatSpamhausJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2, got %d: %v", len(got), got)
	}
	if got[0].String() != "192.0.2.0/24" {
		t.Errorf("got %s", got[0])
	}
}

func TestLoadRejectsMalformed(t *testing.T) {
	p := write(t, "bad.txt", "not-an-ip\n")
	if _, err := Load(p, FormatCIDRLines); err == nil {
		t.Fatal("expected error on malformed entry")
	}
}

func TestLoadRejectsBadSpamhausRecord(t *testing.T) {
	p := write(t, "bad.json", `{"nope":"x"}`+"\n")
	if _, err := Load(p, FormatSpamhausJSON); err == nil {
		t.Fatal("expected error on missing cidr field")
	}
}

func TestUnknownFormat(t *testing.T) {
	if _, err := Load("/nonexistent", "bogus"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestKnownFormat(t *testing.T) {
	for _, f := range []string{FormatCIDRLines, FormatFireholNetset, FormatSpamhausJSON} {
		if !KnownFormat(f) {
			t.Errorf("%q should be known", f)
		}
	}
	if KnownFormat("nope") {
		t.Error("nope should be unknown")
	}
}

func TestLoadNormalizesIPv4MappedIPv6(t *testing.T) {
	// A feed written in IPv4-mapped-IPv6 notation must normalize to native IPv4, or it
	// never matches the unmapped client IP the reputation engine looks up.
	p := write(t, "f.txt", "::ffff:192.0.2.0/120\n::ffff:198.51.100.7\n")
	got, err := Load(p, FormatCIDRLines)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].String() != "192.0.2.0/24" {
		t.Errorf("mapped CIDR should normalize to native IPv4 /24, got %s", got[0])
	}
	if got[1].String() != "198.51.100.7/32" {
		t.Errorf("mapped bare IP should normalize to native IPv4 /32, got %s", got[1])
	}
}
