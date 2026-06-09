package stages

import (
	"strings"
	"testing"

	"github.com/cloudnativeworks/elchi-shield/internal/config"
	"github.com/cloudnativeworks/elchi-shield/internal/pipeline"
	"github.com/cloudnativeworks/elchi-shield/internal/sensitive"
)

func dlpPolicy(t *testing.T, block, redact []string) *pipeline.Transaction {
	t.Helper()
	pol := compiled(config.ModeBlock, config.Checks{Body: &config.BodyChecks{
		DLP: &config.DLPSpec{Direction: "response", Block: block, Redact: redact},
	}})
	tx := &pipeline.Transaction{Policy: pol, Direction: pipeline.DirectionResponse}
	return tx
}

func TestDLPRedactsCreditCard(t *testing.T) {
	tx := dlpPolicy(t, nil, []string{"credit_card"})
	tx.AppendBody([]byte(`{"card":"4111 1111 1111 1111"}`), 1<<20)
	res := BodyChecks(sensitive.New()).Process(bg(), tx)
	if res.Action != pipeline.ActionContinue {
		t.Fatalf("redaction should continue, got %+v", res)
	}
	if !tx.BodyMutated() {
		t.Fatal("body should be marked mutated")
	}
	out := string(tx.Body())
	if !strings.Contains(out, "1111") {
		t.Fatalf("last 4 should be preserved: %q", out)
	}
	if strings.Contains(out, "4111 1111 1111 1111") {
		t.Fatalf("full card should be masked: %q", out)
	}
	if !strings.Contains(out, "*") {
		t.Fatalf("masked digits expected: %q", out)
	}
}

func TestDLPRedactsEmailTag(t *testing.T) {
	tx := dlpPolicy(t, nil, []string{"email"})
	tx.AppendBody([]byte(`contact alice@example.com today`), 1<<20)
	BodyChecks(sensitive.New()).Process(bg(), tx)
	if !tx.BodyMutated() {
		t.Fatal("email should be redacted")
	}
	if got := string(tx.Body()); !strings.Contains(got, "[REDACTED:email]") || strings.Contains(got, "alice@example.com") {
		t.Fatalf("email not redacted: %q", got)
	}
}

func TestDLPBlocksPrivateKey(t *testing.T) {
	tx := dlpPolicy(t, []string{"private_key"}, []string{"credit_card"})
	tx.AppendBody([]byte("-----BEGIN PRIVATE KEY-----\nMIIE...\n"), 1<<20)
	res := BodyChecks(sensitive.New()).Process(bg(), tx)
	if res.Action != pipeline.ActionDeny {
		t.Fatalf("private key should block, got %+v", res)
	}
	if res.Decision.RuleID != "body.dlp_block:private_key" {
		t.Fatalf("rule id = %q", res.Decision.RuleID)
	}
	if tx.BodyMutated() {
		t.Fatal("a blocked body must not be mutated/forwarded")
	}
}

func TestDLPDirectionGating(t *testing.T) {
	// Configured for response only → does not run on the request direction.
	pol := compiled(config.ModeBlock, config.Checks{Body: &config.BodyChecks{
		DLP: &config.DLPSpec{Direction: "response", Redact: []string{"email"}},
	}})
	tx := &pipeline.Transaction{Policy: pol, Direction: pipeline.DirectionRequest}
	tx.AppendBody([]byte("alice@example.com"), 1<<20)
	BodyChecks(sensitive.New()).Process(bg(), tx)
	if tx.BodyMutated() {
		t.Fatal("response-only DLP must not redact the request body")
	}
}

func TestDLPNoMatchNoMutation(t *testing.T) {
	tx := dlpPolicy(t, nil, []string{"email"})
	tx.AppendBody([]byte("nothing sensitive here"), 1<<20)
	BodyChecks(sensitive.New()).Process(bg(), tx)
	if tx.BodyMutated() {
		t.Fatal("no matches → no mutation")
	}
}

func TestDLPBlockNotHiddenByOverlappingRedact(t *testing.T) {
	// A redact-kind match overlaps a block-kind match (built-in patterns won't
	// produce this, so use a fake detector). Block must still win — the hard
	// secret must NOT be redacted-and-forwarded.
	tx := dlpPolicy(t, []string{"private_key"}, []string{"email"})
	tx.AppendBody([]byte("0123456789012345"), 1<<20)
	det := fakeDetector{ms: []sensitive.Match{
		{Start: 0, End: 12, Kind: "email"},       // redact, longer, sorts first
		{Start: 4, End: 16, Kind: "private_key"}, // block, overlaps
	}}
	res := BodyChecks(det).Process(bg(), tx)
	if res.Action != pipeline.ActionDeny {
		t.Fatalf("an overlapping block-kind match must still block, got %+v", res)
	}
	if tx.BodyMutated() {
		t.Fatal("a blocked body must not be mutated/forwarded")
	}
}

func TestRedactBodySinglePass(t *testing.T) {
	body := []byte("a@b.com mid c@d.com end")
	ms := sensitive.New().Matches(body)
	out, changed := redactBody(body, ms, map[string]struct{}{"email": {}})
	if !changed {
		t.Fatal("expected redaction")
	}
	got := string(out)
	if strings.Contains(got, "@") {
		t.Fatalf("all emails should be masked: %q", got)
	}
	if !strings.Contains(got, "mid") || !strings.Contains(got, "end") {
		t.Fatalf("non-matched spans must be preserved: %q", got)
	}
}
