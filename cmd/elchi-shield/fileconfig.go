package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// fileConfig is shield's optional process-level config file (--config-file /
// ELCHI_SHIELD_CONFIG_FILE). It carries the audit + metrics SINK settings so they
// can be delivered as a file (e.g. written by elchi-client) instead of only via
// flags/env — the central-distribution path for the ClickHouse DSN + OTLP endpoint.
// It is SEPARATE from the watched policy dir (--config-dir): it is read once at
// startup and is process-level, not hot-reloaded per-policy.
//
// Precedence: an explicitly-set flag/env value always wins; the file fills any
// setting still at its zero value. The two intervals (flush / otlp) are flag/env
// only (their defaults are non-zero, so "unset" can't be told from the default).
type fileConfig struct {
	Audit struct {
		Exporter            string  `yaml:"exporter"`              // none|clickhouse|otel
		ClickHouseDSN       string  `yaml:"clickhouse_dsn"`        // the default audit sink when set
		ClickHouseTable     string  `yaml:"clickhouse_table"`      // default elchi_shield_audit
		ClickHouseBatchSize int     `yaml:"clickhouse_batch_size"` // default 500
		ClickHouseTTLDays   int     `yaml:"clickhouse_ttl_days"`   // default 7
		OTELEndpoint        string  `yaml:"otel_endpoint"`         // OTLP audit endpoint
		OTELInsecure        bool    `yaml:"otel_insecure"`
		// MaxPerSec is the allow-stream rate cap. NOTE: under the merge rule a file
		// value of 0 means "inherit" (not "force unlimited") — the default already
		// is unlimited, so this only matters if you wanted the file to override a
		// flag-set limit back to unlimited, which it cannot. Set a positive cap.
		MaxPerSec float64 `yaml:"max_per_sec"`
	} `yaml:"audit"`
	Metrics struct {
		OTLPEndpoint string `yaml:"otlp_endpoint"` // push metrics to this OTel Collector
		OTLPInsecure bool   `yaml:"otlp_insecure"`
	} `yaml:"metrics"`
}

// loadFileConfig reads and strictly parses the process config file at path. The
// file may carry the ClickHouse DSN (with a password), so it warns when the file
// is group/world-readable — keep it `chmod 0600`, owner-only.
func loadFileConfig(path string) (fileConfig, error) {
	var fc fileConfig
	if info, statErr := os.Stat(path); statErr == nil && info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "warning: config file %q is mode %#o (group/world-accessible); it may hold the ClickHouse DSN — chmod 0600\n", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fc, fmt.Errorf("read config file %q: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // reject unknown keys so a typo'd setting is caught at boot
	if err := dec.Decode(&fc); err != nil && err != io.EOF {
		return fc, fmt.Errorf("parse config file %q: %w", path, err)
	}
	return fc, nil
}

// mergeFileConfig fills any sink setting still at its zero value from fc, so an
// explicitly-set flag/env value always takes precedence over the file.
func mergeFileConfig(cfg *appConfig, fc fileConfig) {
	if cfg.auditExporter == "" {
		cfg.auditExporter = fc.Audit.Exporter
	}
	if cfg.auditDSN == "" {
		cfg.auditDSN = fc.Audit.ClickHouseDSN
	}
	if cfg.auditCHTable == "" {
		cfg.auditCHTable = fc.Audit.ClickHouseTable
	}
	if cfg.auditCHBatchSize == 0 {
		cfg.auditCHBatchSize = fc.Audit.ClickHouseBatchSize
	}
	if cfg.auditCHTTLDays == 0 {
		cfg.auditCHTTLDays = fc.Audit.ClickHouseTTLDays
	}
	if cfg.auditEndpoint == "" {
		cfg.auditEndpoint = fc.Audit.OTELEndpoint
	}
	if !cfg.auditInsecure {
		cfg.auditInsecure = fc.Audit.OTELInsecure
	}
	if cfg.auditMaxPerSec == 0 {
		cfg.auditMaxPerSec = fc.Audit.MaxPerSec
	}
	if cfg.metricsOTLPEndpoint == "" {
		cfg.metricsOTLPEndpoint = fc.Metrics.OTLPEndpoint
	}
	if !cfg.metricsOTLPInsecure {
		cfg.metricsOTLPInsecure = fc.Metrics.OTLPInsecure
	}
}
