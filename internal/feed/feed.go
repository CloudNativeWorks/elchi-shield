// Package feed loads CIDR/IP threat-intelligence feed files from disk into
// normalized prefix lists. It performs NO network I/O — the management plane
// (elchi-client) writes feed files into the watched config directory and the
// atomic reload recompiles them. Parsing happens on the cold path only.
//
// Supported formats (selected per feed in config):
//   - "cidr_lines"     one CIDR or bare IP per line; '#' and ';' start comments
//   - "firehol_netset" FireHOL .netset: identical line grammar to cidr_lines
//   - "spamhaus_json"  Spamhaus DROP JSON-lines: {"cidr":"1.2.3.0/24",...} per
//     line, with ';'-prefixed metadata lines ignored
package feed

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// Supported feed format identifiers.
const (
	FormatCIDRLines     = "cidr_lines"
	FormatFireholNetset = "firehol_netset"
	FormatSpamhausJSON  = "spamhaus_json"
)

// maxFeedEntries bounds the prefixes a single feed may contribute, so a runaway or
// corrupt multi-GB feed can't OOM the process on reload. 5M prefixes (~120 MB of
// netip.Prefix) is far above any real threat feed.
const maxFeedEntries = 5_000_000

// KnownFormat reports whether format is a recognized feed format.
func KnownFormat(format string) bool {
	switch format {
	case FormatCIDRLines, FormatFireholNetset, FormatSpamhausJSON:
		return true
	default:
		return false
	}
}

// Load reads and parses the feed file at path in the given format, returning its
// normalized (masked) prefixes. A bare IP is widened to a host prefix (/32 or
// /128). Blank lines and comments are skipped. A malformed entry is an error
// (fail loud on the cold path) so a corrupt feed aborts the reload rather than
// silently shrinking the blocklist.
func Load(path, format string) ([]netip.Prefix, error) {
	if !KnownFormat(format) {
		return nil, fmt.Errorf("unknown feed format %q", format)
	}
	f, err := os.Open(path) //nolint:gosec // path comes from validated, operator-controlled config
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file

	var out []netip.Prefix
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || raw[0] == '#' || raw[0] == ';' {
			continue
		}
		token := raw
		if format == FormatSpamhausJSON {
			if raw[0] != '{' {
				continue // metadata / non-record line
			}
			var rec struct {
				CIDR string `json:"cidr"`
			}
			if err := json.Unmarshal([]byte(raw), &rec); err != nil || rec.CIDR == "" {
				return nil, fmt.Errorf("%s:%d: malformed spamhaus record", path, line)
			}
			token = rec.CIDR
		} else {
			// FireHOL/cidr_lines may carry a trailing inline comment.
			if i := strings.IndexAny(token, " \t#;"); i >= 0 {
				token = token[:i]
			}
		}
		p, err := parsePrefix(token)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		out = append(out, p)
		if len(out) > maxFeedEntries {
			return nil, fmt.Errorf("%s: feed exceeds the %d-entry limit", path, maxFeedEntries)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parsePrefix accepts a CIDR ("1.2.3.0/24") or a bare IP ("1.2.3.4"), returning
// the masked prefix (a bare IP becomes a host route).
func parsePrefix(token string) (netip.Prefix, error) {
	if strings.ContainsRune(token, '/') {
		p, err := netip.ParsePrefix(token)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", token, err)
		}
		return unmapPrefix(p).Masked(), nil
	}
	addr, err := netip.ParseAddr(token)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP %q: %w", token, err)
	}
	// The reputation engine Unmap()s the client IP before lookup, so store feed
	// entries in native IPv4 form too — otherwise an IPv4-mapped-IPv6 feed line never
	// matches.
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// unmapPrefix normalizes an IPv4-in-IPv6 prefix (e.g. ::ffff:1.2.3.0/120) to its
// native IPv4 form (1.2.3.0/24) so it matches the unmapped client IP. A native IPv4
// or IPv6 prefix is returned unchanged.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		if np, err := p.Addr().Unmap().Prefix(p.Bits() - 96); err == nil {
			return np
		}
	}
	return p
}
