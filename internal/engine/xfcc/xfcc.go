package xfcc

import (
	"context"
	"strings"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
	"github.com/cloudnativeworks/elchi-shield/internal/engine"
)

const engineName = "xfcc"

// Config configures the XFCC engine. The allow-list dimensions are OR'd: a
// request is authenticated if the presented client cert matches ANY configured
// URI, DNS name, subject, or hash. Empty dimensions are ignored.
type Config struct {
	// HeaderName is the XFCC header (default "x-forwarded-client-cert").
	HeaderName string
	// RequirePresent blocks a request that carries no XFCC header.
	RequirePresent bool
	// Allow-list match values.
	URIs     []string // SAN URIs / SPIFFE IDs (exact)
	DNSNames []string // SAN DNS names (exact)
	Subjects []string // full subject DNs (exact)
	Hashes   []string // cert SHA-256 fingerprints (hex, case-insensitive)
}

// Engine matches the forwarded client-cert identity against the allow-list.
type Engine struct {
	header         string
	requirePresent bool
	uris           map[string]struct{}
	dns            map[string]struct{}
	subjects       map[string]struct{}
	hashes         map[string]struct{}
	hasAllow       bool
}

// New compiles the configuration into an Engine.
func New(cfg Config) (*Engine, error) {
	header := cfg.HeaderName
	if header == "" {
		header = "x-forwarded-client-cert"
	}
	e := &Engine{
		header:         header,
		requirePresent: cfg.RequirePresent,
		uris:           toSet(cfg.URIs, false),
		dns:            toSet(cfg.DNSNames, false),
		subjects:       toSet(cfg.Subjects, false),
		hashes:         toSet(cfg.Hashes, true), // fingerprints compared case-insensitively
	}
	e.hasAllow = len(e.uris)+len(e.dns)+len(e.subjects)+len(e.hashes) > 0
	return e, nil
}

// Name implements engine.SecurityEngine.
func (*Engine) Name() string { return engineName }

// RequiresBody implements engine.SecurityEngine.
func (*Engine) RequiresBody() bool { return false }

// Close implements engine.SecurityEngine.
func (*Engine) Close() error { return nil }

// Inspect authenticates the request by its forwarded client certificate.
// Responses pass through.
func (e *Engine) Inspect(_ context.Context, req *engine.Request) (decision.Verdict, error) {
	if req.Direction != engine.DirectionRequest {
		return decision.Verdict{}, nil
	}
	hdr, ok := req.Headers.Header(e.header)
	if !ok || strings.TrimSpace(hdr) == "" {
		if e.requirePresent {
			return block("xfcc.missing", "client certificate (XFCC) required but not present"), nil
		}
		return decision.Verdict{}, nil
	}
	if !e.hasAllow {
		return decision.Verdict{}, nil // presence-only mode
	}
	elems := parse(hdr)
	for i := range elems {
		if e.matches(&elems[i]) {
			return decision.Verdict{}, nil
		}
	}
	return block("xfcc.no_match", "client certificate identity not in the allow-list"), nil
}

// matches reports whether an XFCC element satisfies any allow-list dimension.
func (e *Engine) matches(el *Element) bool {
	if _, ok := e.subjects[el.Subject]; ok && el.Subject != "" {
		return true
	}
	if _, ok := e.hashes[strings.ToLower(el.Hash)]; ok && el.Hash != "" {
		return true
	}
	for _, u := range el.URIs {
		if _, ok := e.uris[u]; ok {
			return true
		}
	}
	for _, d := range el.DNSs {
		if _, ok := e.dns[d]; ok {
			return true
		}
	}
	return false
}

func toSet(items []string, lower bool) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(items))
	for _, s := range items {
		if lower {
			s = strings.ToLower(s)
		}
		m[s] = struct{}{}
	}
	return m
}

func block(ruleID, reason string) decision.Verdict {
	return decision.Verdict{
		Action:     decision.Block,
		Reason:     reason,
		RuleID:     ruleID,
		Engine:     engineName,
		Severity:   decision.SeverityHigh,
		StatusCode: decision.DefaultBlockStatus,
	}
}
