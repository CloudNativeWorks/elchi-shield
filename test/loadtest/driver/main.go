// Command driver is a self-contained closed-loop HTTP load generator for the
// elchi-shield real-traffic load test. It drives a fixed concurrency of
// persistent (keep-alive) connections against a target URL for a duration and
// reports sustained throughput (req/s) plus latency percentiles (p50/p90/p99/
// p999/max), the status-code distribution, and the error count.
//
// It is dependency-free (stdlib only) so the load test needs no external tool
// (hey/vegeta/wrk); the topology under test is a REAL Envoy proxying to
// elchi-shield, so this measures end-to-end data-plane behaviour, not a mock.
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ",") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func main() {
	var (
		target   = flag.String("target", "http://127.0.0.1:10010/bench", "target URL")
		host     = flag.String("host", "api.example.com", "Host header")
		method   = flag.String("method", "GET", "HTTP method")
		body     = flag.String("body", "", "request body (string)")
		conns    = flag.Int("conns", 64, "concurrent connections (closed-loop workers)")
		dur      = flag.Duration("duration", 10*time.Second, "load duration")
		warmup   = flag.Duration("warmup", 1*time.Second, "warm-up duration (not measured)")
		name     = flag.String("name", "", "scenario label for the report")
		randByte = flag.Int("rand-bytes", 0, "append N random bytes to the body (defeats any caching; sized payload)")
		headers  headerList
	)
	flag.Var(&headers, "H", "extra request header 'Key: Value' (repeatable)")
	flag.Parse()

	payload := []byte(*body)
	if *randByte > 0 {
		extra := make([]byte, *randByte)
		_, _ = rand.Read(extra)
		payload = append(payload, extra...)
	}

	// One transport shared by all workers, tuned to keep connections hot so we
	// measure the proxy path, not TCP/TLS handshakes.
	tr := &http.Transport{
		MaxIdleConns:        *conns * 2,
		MaxIdleConnsPerHost: *conns * 2,
		MaxConnsPerHost:     *conns * 2,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	doOne := func() (time.Duration, int, error) {
		var rdr io.Reader
		if len(payload) > 0 {
			rdr = strings.NewReader(string(payload))
		}
		req, err := http.NewRequest(*method, *target, rdr)
		if err != nil {
			return 0, 0, err
		}
		req.Host = *host
		for _, h := range headers {
			if k, v, ok := strings.Cut(h, ":"); ok {
				req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
			}
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return time.Since(start), 0, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return time.Since(start), resp.StatusCode, nil
	}

	// Warm-up: open connections and prime the path; results discarded.
	if *warmup > 0 {
		warmCtx, cancel := context.WithTimeout(context.Background(), *warmup)
		var wg sync.WaitGroup
		for range *conns {
			wg.Go(func() {
				for warmCtx.Err() == nil {
					_, _, _ = doOne()
				}
			})
		}
		wg.Wait()
		cancel()
	}

	// Measured run.
	ctx, cancel := context.WithTimeout(context.Background(), *dur)
	var (
		wg       sync.WaitGroup
		errCount int64
		perWork  = make([][]time.Duration, *conns)
		statuses = make([]map[int]int, *conns)
	)
	measureStart := time.Now()
	for i := range *conns {
		wg.Go(func() {
			lat := make([]time.Duration, 0, 4096)
			st := make(map[int]int, 4)
			for ctx.Err() == nil {
				d, code, err := doOne()
				if err != nil {
					atomic.AddInt64(&errCount, 1)
					continue
				}
				lat = append(lat, d)
				st[code]++
			}
			perWork[i] = lat
			statuses[i] = st
		})
	}
	wg.Wait()
	cancel()
	elapsed := time.Since(measureStart)

	// Merge latencies and statuses.
	var all []time.Duration
	status := map[int]int{}
	for i := range *conns {
		all = append(all, perWork[i]...)
		for c, n := range statuses[i] {
			status[c] += n
		}
	}
	slices.Sort(all)

	total := len(all)
	rps := float64(total) / elapsed.Seconds()
	label := *name
	if label == "" {
		label = *target
	}

	fmt.Printf("\n── %s ──\n", label)
	fmt.Printf("  target       : %s  (Host: %s, %s)\n", *target, *host, *method)
	fmt.Printf("  concurrency  : %d   duration: %s\n", *conns, elapsed.Round(time.Millisecond))
	fmt.Printf("  requests     : %d\n", total)
	fmt.Printf("  throughput   : %.0f req/s\n", rps)
	if total > 0 {
		fmt.Printf("  latency      : p50=%s  p90=%s  p99=%s  p999=%s  max=%s\n",
			rd(pct(all, 0.50)), rd(pct(all, 0.90)), rd(pct(all, 0.99)), rd(pct(all, 0.999)), rd(all[total-1]))
		fmt.Printf("  mean         : %s\n", rd(mean(all)))
	}
	fmt.Printf("  status codes : %s\n", fmtStatus(status))
	if errCount > 0 {
		fmt.Printf("  errors       : %d\n", errCount)
	}

	// Exit non-zero if any request errored or returned an unexpected 5xx, so the
	// load test fails loudly on a broken data plane.
	if errCount > 0 || status[502] > 0 || status[503] > 0 || status[504] > 0 {
		os.Exit(1)
	}
}

func pct(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(p * float64(len(sorted)))
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func mean(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	return sum / time.Duration(len(ds))
}

func rd(d time.Duration) time.Duration { return d.Round(10 * time.Microsecond) }

func fmtStatus(m map[int]int) string {
	codes := make([]int, 0, len(m))
	for c := range m {
		codes = append(codes, c)
	}
	slices.Sort(codes)
	parts := make([]string, 0, len(codes))
	for _, c := range codes {
		parts = append(parts, fmt.Sprintf("%d=%d", c, m[c]))
	}
	return strings.Join(parts, " ")
}
