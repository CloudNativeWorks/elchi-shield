// Package geoip provides a thin, snapshot-friendly reader over MaxMind
// GeoLite2/GeoIP2 databases (country + ASN), used by the IP-reputation engine to
// block by geography or autonomous system. It decodes only the few fields the WAF
// needs (country ISO code, ASN) rather than whole records.
//
// Databases are loaded into memory by copying the file bytes (OpenBytes), not
// mmap, so an in-place replace of the .mmdb by the management plane can never
// invalidate an in-flight lookup on the live snapshot — the old snapshot keeps
// its byte copy until it is retired and GC'd.
package geoip

import (
	"net/netip"
	"os"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// Record is the decoded subset of a GeoIP lookup the WAF uses.
type Record struct {
	// Country is the ISO 3166-1 alpha-2 code (e.g. "GB"); empty if not found.
	Country string
	// ASN is the autonomous system number; 0 if not found.
	ASN uint
}

// Reader resolves an IP to a Record using an optional country database and an
// optional ASN database. At least one must be configured. It is safe for
// concurrent use.
type Reader struct {
	country *maxminddb.Reader
	asn     *maxminddb.Reader
}

// Open loads the given database files (either path may be empty to skip that
// dimension). The caller must Close the returned Reader.
func Open(countryPath, asnPath string) (*Reader, error) {
	r := &Reader{}
	if countryPath != "" {
		db, err := openCopy(countryPath)
		if err != nil {
			return nil, err
		}
		r.country = db
	}
	if asnPath != "" {
		db, err := openCopy(asnPath)
		if err != nil {
			_ = r.Close()
			return nil, err
		}
		r.asn = db
	}
	return r, nil
}

// openCopy reads the whole file and hands an owned byte copy to maxminddb, so the
// reader is decoupled from the on-disk file lifetime.
func openCopy(path string) (*maxminddb.Reader, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is validated, operator-controlled config
	if err != nil {
		return nil, err
	}
	return maxminddb.OpenBytes(data)
}

// Lookup resolves ip against the configured databases. A miss in either database
// leaves the corresponding field at its zero value; it is not an error.
func (r *Reader) Lookup(ip netip.Addr) (Record, error) {
	var rec Record
	if r.country != nil {
		var c struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		res := r.country.Lookup(ip)
		if err := res.Err(); err != nil {
			return rec, err
		}
		if res.Found() {
			if err := res.Decode(&c); err != nil {
				return rec, err
			}
			rec.Country = c.Country.ISOCode
		}
	}
	if r.asn != nil {
		var a struct {
			ASN uint `maxminddb:"autonomous_system_number"`
		}
		res := r.asn.Lookup(ip)
		if err := res.Err(); err != nil {
			return rec, err
		}
		if res.Found() {
			if err := res.Decode(&a); err != nil {
				return rec, err
			}
			rec.ASN = a.ASN
		}
	}
	return rec, nil
}

// Close releases the underlying database readers.
func (r *Reader) Close() error {
	var err error
	if r.country != nil {
		if e := r.country.Close(); e != nil {
			err = e
		}
	}
	if r.asn != nil {
		if e := r.asn.Close(); e != nil {
			err = e
		}
	}
	return err
}
