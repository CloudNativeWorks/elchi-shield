// Package xfcc implements a header-phase engine that authenticates a request by
// the client TLS certificate identity Envoy forwards in the
// x-forwarded-client-cert (XFCC) header. It performs no network I/O — the
// identity is read from the header (which a correctly-configured Envoy sets from
// the verified peer cert) and matched against a configured allow-list.
package xfcc

import "strings"

// Element is one parsed XFCC entry (one hop's client certificate identity).
// Envoy emits the keys By, Hash, Cert, Chain, Subject, URI, DNS; URI and DNS may
// repeat. We keep the fields used for identity matching.
type Element struct {
	Hash    string   // SHA-256 fingerprint of the cert (hex)
	Subject string   // RFC 2253 distinguished name
	URIs    []string // SAN URIs (e.g. SPIFFE IDs)
	DNSs    []string // SAN DNS names
}

// parse decodes an XFCC header value into its elements. The grammar is a
// comma-separated list of certs, each a ';'-separated list of key=value pairs;
// values may be double-quoted (and then contain ',' or ';'). Parsing is
// quote-aware so a quoted Subject DN does not split the entry.
func parse(header string) []Element {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	var (
		elems   []Element
		cur     Element
		started bool
	)
	flush := func() {
		if started {
			elems = append(elems, cur)
		}
		cur = Element{}
		started = false
	}

	for _, kv := range splitTop(header, ',') {
		flush()
		started = true
		for _, pair := range splitTop(kv, ';') {
			key, val, ok := strings.Cut(pair, "=")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			val = unquote(strings.TrimSpace(val))
			switch strings.ToLower(key) {
			case "hash":
				cur.Hash = val
			case "subject":
				cur.Subject = val
			case "uri":
				cur.URIs = append(cur.URIs, val)
			case "dns":
				cur.DNSs = append(cur.DNSs, val)
			}
		}
	}
	flush()
	return elems
}

// splitTop splits s on sep at the top level only (not inside double quotes).
func splitTop(s string, sep byte) []string {
	var (
		out     []string
		start   int
		inQuote bool
	)
	for i := range len(s) {
		switch s[i] {
		case '"':
			inQuote = !inQuote
		case sep:
			if !inQuote {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// unquote strips surrounding double quotes if present.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
