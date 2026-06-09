package geoip

import (
	"net/netip"
	"testing"
)

const (
	countryDB = "testdata/GeoLite2-Country-Test.mmdb"
	asnDB     = "testdata/GeoLite2-ASN-Test.mmdb"
)

func TestLookupCountry(t *testing.T) {
	r, err := Open(countryDB, "")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck

	for _, tc := range []struct {
		ip   string
		want string
	}{
		{"81.2.69.142", "GB"},
		{"89.160.20.128", "SE"},
		{"67.43.156.1", "BT"},
		{"202.196.224.1", "PH"},
		{"8.8.8.8", ""}, // not in the test DB
	} {
		rec, err := r.Lookup(netip.MustParseAddr(tc.ip))
		if err != nil {
			t.Fatalf("lookup %s: %v", tc.ip, err)
		}
		if rec.Country != tc.want {
			t.Errorf("country(%s) = %q, want %q", tc.ip, rec.Country, tc.want)
		}
	}
}

func TestLookupASN(t *testing.T) {
	r, err := Open("", asnDB)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck

	for _, tc := range []struct {
		ip   string
		want uint
	}{
		{"1.128.0.1", 1221},  // Telstra
		{"12.81.92.1", 7018}, // AT&T
		{"8.8.8.8", 0},       // not in the test DB
	} {
		rec, err := r.Lookup(netip.MustParseAddr(tc.ip))
		if err != nil {
			t.Fatalf("lookup %s: %v", tc.ip, err)
		}
		if rec.ASN != tc.want {
			t.Errorf("asn(%s) = %d, want %d", tc.ip, rec.ASN, tc.want)
		}
	}
}

func TestBothDatabases(t *testing.T) {
	r, err := Open(countryDB, asnDB)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() //nolint:errcheck
	rec, err := r.Lookup(netip.MustParseAddr("1.128.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.ASN != 1221 {
		t.Errorf("asn = %d, want 1221", rec.ASN)
	}
}

func TestOpenMissingFile(t *testing.T) {
	if _, err := Open("testdata/nonexistent.mmdb", ""); err == nil {
		t.Fatal("expected error opening missing database")
	}
}
