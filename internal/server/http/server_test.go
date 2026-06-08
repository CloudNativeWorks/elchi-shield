package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestEndpoints(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewCounter(prometheus.CounterOpts{Name: "test_counter", Help: "h"}))

	ready := true
	configInfo := func() ConfigInfo { return ConfigInfo{Version: "v1", Domains: 2} }
	explain := func(q PolicyQuery) PolicyExplanation {
		return PolicyExplanation{Matched: true, PolicyID: "p|" + q.Host, Mode: "block"}
	}
	s := NewServer("127.0.0.1:0", reg, func() bool { return ready }, configInfo, explain, true, nil)
	h := s.srv.Handler

	do := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	if rec := do("/healthz"); rec.Code != http.StatusOK {
		t.Errorf("healthz = %d", rec.Code)
	}
	if rec := do("/readyz"); rec.Code != http.StatusOK {
		t.Errorf("readyz (ready) = %d", rec.Code)
	}

	ready = false
	if rec := do("/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz (not ready) = %d, want 503", rec.Code)
	}

	if rec := do("/metrics"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "test_counter") {
		t.Errorf("metrics endpoint missing data: code=%d", rec.Code)
	}

	if rec := do("/configz"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"version": "v1"`) {
		t.Errorf("configz endpoint missing data: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := do("/debug/pprof/"); rec.Code != http.StatusOK {
		t.Errorf("pprof index should be served on the loopback mux: code=%d", rec.Code)
	}
	if rec := do("/policyz?host=api.example.com"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"policy_id": "p|api.example.com"`) {
		t.Errorf("policyz endpoint missing data: code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPprofDisabled(t *testing.T) {
	s := NewServer("127.0.0.1:0", nil, nil, nil, nil, false, nil)
	rec := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("pprof must be absent when disabled, got %d", rec.Code)
	}
}
