package httpserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ConfigInfo is the read-only view of the active configuration exposed by
// /configz, so an operator can ask the running process which config it is
// enforcing (and from which files) without reading YAML off disk.
type ConfigInfo struct {
	Version   string   `json:"version"`
	Hash      string   `json:"hash"`
	Sources   []string `json:"sources"`
	Domains   int      `json:"domains"`
	Empty     bool     `json:"empty"`
	BuiltAt   string   `json:"built_at"`
	AgeSec    float64  `json:"config_age_seconds"`
	Instance  string   `json:"instance"`
	Build     string   `json:"build"`
	Revision  string   `json:"revision"`
	GoVersion string   `json:"go_version"`
}

// Server hosts the operational HTTP endpoints: /healthz (liveness), /readyz
// (readiness), and /metrics (Prometheus). It binds loopback by default and is
// independent of the data-plane ext_proc server.
type Server struct {
	srv *http.Server
	log *slog.Logger
}

// PolicyQuery is a request to explain which policy and inspection a given
// request shape resolves to (the /policyz endpoint).
type PolicyQuery struct {
	Host        string
	Path        string
	Method      string
	ContentType string
	Listener    string
}

// PolicyExplanation is the redaction-safe answer: it describes policy *structure*
// (id, mode, the effective stage order, engine names) — never secrets, rules, or
// request payloads — so an operator can answer "why was this allowed/blocked?".
type PolicyExplanation struct {
	Matched              bool     `json:"matched"`
	PolicyID             string   `json:"policy_id"`
	Mode                 string   `json:"mode"`
	FailMode             string   `json:"fail_mode"`
	TimeoutMs            int64    `json:"timeout_ms"`
	InspectRequestBody   bool     `json:"inspect_request_body"`
	InspectResponseBody  bool     `json:"inspect_response_body"`
	Engines              []string `json:"engines"`
	RequestHeaderStages  []string `json:"request_header_stages"`
	RequestBodyStages    []string `json:"request_body_stages"`
	ResponseHeaderStages []string `json:"response_header_stages"`
	ResponseBodyStages   []string `json:"response_body_stages"`
	Note                 string   `json:"note,omitempty"`
}

// PolicyExplainer resolves a PolicyQuery to a PolicyExplanation. It is provided by
// main (which holds the snapshot store + stage catalog).
type PolicyExplainer func(PolicyQuery) PolicyExplanation

// NewServer builds the HTTP server. reg backs /metrics; ready reports readiness
// for /readyz (nil → always ready); configInfo backs /configz (nil → endpoint
// omitted); explain backs /policyz (nil → endpoint omitted); enablePprof exposes
// the net/http/pprof handlers under /debug/pprof/ (safe here because this server
// is loopback-only).
func NewServer(addr string, reg *prometheus.Registry, ready func() bool, configInfo func() ConfigInfo, explain PolicyExplainer, enablePprof bool, log *slog.Logger) *Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready == nil || ready() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready\n"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready\n"))
	})

	if reg != nil {
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	}

	if configInfo != nil {
		mux.HandleFunc("/configz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(configInfo())
		})
	}

	if explain != nil {
		mux.HandleFunc("/policyz", func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			exp := explain(PolicyQuery{
				Host:        q.Get("host"),
				Path:        q.Get("path"),
				Method:      q.Get("method"),
				ContentType: q.Get("content_type"),
				Listener:    q.Get("listener"),
			})
			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(exp)
		})
	}

	if enablePprof {
		// Registered on this private mux only (never DefaultServeMux). pprof.Index
		// serves the named profiles (heap, goroutine, allocs, block, mutex, ...);
		// block/mutex read empty until their sampling rate is enabled at startup.
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	return &Server{
		srv: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
		log: log,
	}
}

// Serve listens and blocks until the server is shut down. A clean shutdown
// returns nil.
func (s *Server) Serve() error {
	if s.log != nil {
		s.log.Info("http server listening", "addr", s.srv.Addr)
	}
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) {
	_ = s.srv.Shutdown(ctx)
}
