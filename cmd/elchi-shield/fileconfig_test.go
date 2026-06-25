package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "shield.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFileConfig(t *testing.T) {
	p := writeTmp(t, `
audit:
  clickhouse_dsn: clickhouse://u:p@ch:9000/elchi
  clickhouse_ttl_days: 14
  max_per_sec: 50
metrics:
  otlp_endpoint: otel:4317
  otlp_insecure: true
`)
	fc, err := loadFileConfig(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if fc.Audit.ClickHouseDSN != "clickhouse://u:p@ch:9000/elchi" {
		t.Errorf("dsn = %q", fc.Audit.ClickHouseDSN)
	}
	if fc.Audit.ClickHouseTTLDays != 14 || fc.Audit.MaxPerSec != 50 {
		t.Errorf("ttl/max = %d/%v", fc.Audit.ClickHouseTTLDays, fc.Audit.MaxPerSec)
	}
	if fc.Metrics.OTLPEndpoint != "otel:4317" || !fc.Metrics.OTLPInsecure {
		t.Errorf("metrics = %q/%v", fc.Metrics.OTLPEndpoint, fc.Metrics.OTLPInsecure)
	}
}

func TestLoadFileConfigRejectsUnknownKey(t *testing.T) {
	p := writeTmp(t, "audit:\n  bogus_key: 1\n")
	if _, err := loadFileConfig(p); err == nil {
		t.Fatal("expected an error for an unknown key (strict decode)")
	}
}

// TestMergeFileConfigPrecedence proves an explicit flag/env value wins and the
// file only fills settings left at their zero value.
func TestMergeFileConfigPrecedence(t *testing.T) {
	var fc fileConfig
	fc.Audit.ClickHouseDSN = "clickhouse://conf/elchi"
	fc.Audit.OTELEndpoint = "conf-otel:4317"
	fc.Metrics.OTLPEndpoint = "conf-metrics:4317"
	fc.Audit.ClickHouseTTLDays = 14

	cfg := appConfig{
		auditDSN:       "clickhouse://flag/elchi", // explicitly set → must win
		auditCHTTLDays: 0,                         // unset → take conf
	}
	mergeFileConfig(&cfg, fc)

	if cfg.auditDSN != "clickhouse://flag/elchi" {
		t.Errorf("explicit flag DSN must win, got %q", cfg.auditDSN)
	}
	if cfg.auditEndpoint != "conf-otel:4317" {
		t.Errorf("empty otel endpoint should take conf, got %q", cfg.auditEndpoint)
	}
	if cfg.metricsOTLPEndpoint != "conf-metrics:4317" {
		t.Errorf("empty metrics endpoint should take conf, got %q", cfg.metricsOTLPEndpoint)
	}
	if cfg.auditCHTTLDays != 14 {
		t.Errorf("zero ttl should take conf, got %d", cfg.auditCHTTLDays)
	}
}
