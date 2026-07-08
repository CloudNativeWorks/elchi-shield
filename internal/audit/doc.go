// Package audit defines audit events, sampling, and pluggable exporters. There is
// NO local-file sink: events go to ClickHouse or OTLP, or are dropped when neither is
// configured — so audit never grows local disk. The bounded queue drops on overflow
// and never blocks the request path.
package audit
