package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cloudnativeworks/elchi-shield/internal/decision"
)

// TestEventMarshalsRedactedJSON proves the audit Event serializes to JSON with
// the decision enums as readable strings and without leaking sensitive header
// names — the same contract every sink (ClickHouse/OTLP) relies on.
func TestEventMarshalsRedactedJSON(t *testing.T) {
	ev := &Event{
		Timestamp: time.Unix(0, 0).UTC(),
		RequestID: "r1",
		Phase:     "request_headers",
		Decision:  decision.Decision{Action: decision.Block, Reason: "forbidden", Severity: decision.SeverityHigh},
		Host:      "api.example.com",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if got["request_id"] != "r1" {
		t.Fatalf("request_id wrong: %v", got)
	}
	// Decision action/severity must marshal as readable strings.
	dec := got["decision"].(map[string]any)
	if dec["Action"] != "block" || dec["Severity"] != "high" {
		t.Fatalf("decision enums should be strings: %v", dec)
	}
	if strings.Contains(strings.ToLower(string(b)), "authorization") {
		t.Fatal("audit JSON unexpectedly contains a sensitive header name")
	}
}

func TestAuditorEmitSwallowsErrors(t *testing.T) {
	a := NewAuditor(errExporter{}, nil)
	// Must not panic or propagate.
	a.Emit(context.Background(), &Event{RequestID: "x"})
}

type errExporter struct{}

func (errExporter) Export(context.Context, *Event) error { return errors.New("boom") }
func (errExporter) Flush(context.Context) error          { return nil }
func (errExporter) Close() error                         { return nil }

func TestSample(t *testing.T) {
	if !Sample(1) || !Sample(2) {
		t.Error("rate >= 1 should always sample")
	}
	if Sample(0) || Sample(-1) {
		t.Error("rate <= 0 should never sample")
	}
	// Probabilistic rate: just ensure it returns without panic across calls.
	for range 100 {
		_ = Sample(0.5)
	}
}

func TestRemoteExporterStubs(t *testing.T) {
	if _, err := NewClickHouseExporter(ClickHouseConfig{}); !errors.Is(err, ErrNotImplemented) {
		t.Error("clickhouse stub")
	}
	if _, err := NewKafkaExporter(KafkaConfig{}); !errors.Is(err, ErrNotImplemented) {
		t.Error("kafka stub")
	}
	if _, err := NewOTELExporter(OTELConfig{}); !errors.Is(err, ErrNotImplemented) {
		t.Error("otel stub")
	}
}
