//go:build clickhouse

package main

// Side-effect import: registers the ClickHouse audit exporter. Built only with
// the `clickhouse` build tag.
import _ "github.com/cloudnativeworks/elchi-shield/internal/audit/clickhouse"
