package sensitive

import (
	"context"
	"testing"
)

func TestDetectorFindsSecrets(t *testing.T) {
	d := New()
	ctx := context.Background()
	cases := map[string]string{
		"aws":         `{"key":"AKIAIOSFODNN7EXAMPLE"}`,
		"private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
		"google":      "key=AIza01234567890123456789012345678901234",
		"github":      "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD",
		"stripe":      `{"key":"sk_live_0123456789abcdefABCDEFGH"}`,
		"credit_card": "card 4111 1111 1111 1111 here", // valid Luhn Visa test number
	}
	for name, body := range cases {
		if found, _ := d.Scan(ctx, "text/plain", []byte(body)); !found {
			t.Errorf("%s: expected sensitive data to be detected in %q", name, body)
		}
	}
}

func TestDetectorIgnoresBenign(t *testing.T) {
	d := New()
	ctx := context.Background()
	benign := []string{
		`{"name":"alice","age":30}`,
		"just some normal text without secrets",
		"1234 5678 9012 3456",             // fails Luhn → not a credit card
		"order id 1234567890123456789012", // long digits but not Luhn-valid
		"",
	}
	for _, body := range benign {
		if found, kind := d.Scan(ctx, "application/json", []byte(body)); found {
			t.Errorf("benign body %q falsely flagged as %q", body, kind)
		}
	}
}

func TestLuhn(t *testing.T) {
	if !luhnValid([]byte("4111111111111111")) {
		t.Error("valid Visa test number should pass Luhn")
	}
	if luhnValid([]byte("4111111111111112")) {
		t.Error("invalid checksum should fail Luhn")
	}
	if luhnValid([]byte("411111")) {
		t.Error("too-short number should fail (not a card length)")
	}
	// IIN guard: cards start with 2–6, so Luhn-passing IDs with a 0/1 lead are not cards.
	if luhnValid([]byte("0000000000000000")) {
		t.Error("all-zeros (Luhn-valid but IIN 0) must not be treated as a card")
	}
	if luhnValid([]byte("1234567890123452")) {
		t.Error("Luhn-valid sequential ID (IIN 1) must not be treated as a card")
	}
}

func TestDetectorCatchesHardSecretVariants(t *testing.T) {
	d := New()
	ctx := context.Background()
	// Regression for previously-missed hard secrets.
	for name, body := range map[string]string{
		"encrypted_pkcs8_key": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF...",
		"pgp_private_key":     "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQd...",
		"github_fine_grained": "github_pat_11ABCDE0aZ_0123456789abcdefghij0123456789",
	} {
		if found, _ := d.Scan(ctx, "text/plain", []byte(body)); !found {
			t.Errorf("%s: hard secret must be detected in %q", name, body)
		}
	}
}
