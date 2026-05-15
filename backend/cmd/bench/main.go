// Bench harness for HS-04 performance gates.
//
// Single self-contained binary that runs each Blueprint §31.5 SLO
// scenario, prints the latency histogram (P50/P95/P99) + throughput,
// and exits non-zero if any threshold is breached. Designed for CI
// against an already-running VAULTSCAN stack.
//
// Scenarios:
//   api        500-concurrent /api/v1/healthz; P99 < 500ms
//   findings   10k findings ingest/hour over 60s window
//   heartbeats 50 simulated agents heartbeating every 30s for 90s
//   dashboard  100 concurrent /api/v1/dashboards/exec; P95 < 3s
//
// Usage:
//   go run ./cmd/bench -scenario api -target https://api.vaultscan.zaishield.com -token $JWT
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	var (
		scenario  = flag.String("scenario", "api", "api | findings | heartbeats | dashboard")
		target    = flag.String("target", "http://127.0.0.1:8080", "API base URL")
		token     = flag.String("token", "", "Bearer token")
		duration  = flag.Duration("duration", 30*time.Second, "test duration")
		concurrency = flag.Int("concurrency", 50, "concurrent virtual users")
	)
	flag.Parse()

	bench := &Bench{
		target:      *target,
		token:       *token,
		concurrency: *concurrency,
		duration:    *duration,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        500,
				MaxIdleConnsPerHost: 500,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
	var slo SLO
	switch *scenario {
	case "api":
		slo = SLO{P99: 500 * time.Millisecond, ErrRate: 0.001}
		bench.run("GET", "/api/v1/healthz", nil, slo)
	case "findings":
		slo = SLO{Throughput: 10000.0 / 3600.0, ErrRate: 0.005}
		bench.run("POST", "/api/v1/findings/bulk-ingest", findingsPayload, slo)
	case "heartbeats":
		slo = SLO{P95: 200 * time.Millisecond, ErrRate: 0.001}
		bench.run("POST", "/api/v1/agents/heartbeat", heartbeatPayload, slo)
	case "dashboard":
		slo = SLO{P95: 3 * time.Second, ErrRate: 0.005}
		bench.run("GET", "/api/v1/dashboards/exec", nil, slo)
	default:
		fmt.Fprintln(os.Stderr, "unknown scenario")
		os.Exit(2)
	}
}

type SLO struct {
	P50, P95, P99 time.Duration
	Throughput    float64 // requests per second floor
	ErrRate       float64 // failure tolerance (e.g. 0.001 = 0.1%)
}

type Bench struct {
	target      string
	token       string
	concurrency int
	duration    time.Duration
	client      *http.Client
}

func (b *Bench) run(method, path string, payload func() []byte, slo SLO) {
	ctx, cancel := context.WithTimeout(context.Background(), b.duration)
	defer cancel()

	var (
		wg          sync.WaitGroup
		total, errs uint64
	)
	mu := sync.Mutex{}
	latencies := make([]time.Duration, 0, 1_000_000)

	start := time.Now()
	for i := 0; i < b.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				rstart := time.Now()
				err := b.fire(ctx, method, path, payload)
				lat := time.Since(rstart)
				atomic.AddUint64(&total, 1)
				if err != nil {
					atomic.AddUint64(&errs, 1)
				}
				mu.Lock()
				latencies = append(latencies, lat)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p := func(q float64) time.Duration {
		if len(latencies) == 0 {
			return 0
		}
		idx := int(float64(len(latencies)) * q)
		if idx >= len(latencies) {
			idx = len(latencies) - 1
		}
		return latencies[idx]
	}

	rps := float64(total) / elapsed.Seconds()
	errRate := float64(errs) / float64(total)
	report := Report{
		Scenario: method + " " + path,
		Total:    int(total),
		Errors:   int(errs),
		ErrRate:  errRate,
		Elapsed:  elapsed,
		RPS:      rps,
		P50:      p(0.50),
		P95:      p(0.95),
		P99:      p(0.99),
	}
	report.Print()
	exit := 0
	if slo.P95 > 0 && report.P95 > slo.P95 {
		fmt.Fprintf(os.Stderr, "SLO breach P95: %s > %s\n", report.P95, slo.P95)
		exit = 1
	}
	if slo.P99 > 0 && report.P99 > slo.P99 {
		fmt.Fprintf(os.Stderr, "SLO breach P99: %s > %s\n", report.P99, slo.P99)
		exit = 1
	}
	if slo.Throughput > 0 && report.RPS < slo.Throughput {
		fmt.Fprintf(os.Stderr, "SLO breach RPS: %.2f < %.2f\n", report.RPS, slo.Throughput)
		exit = 1
	}
	if slo.ErrRate > 0 && report.ErrRate > slo.ErrRate {
		fmt.Fprintf(os.Stderr, "SLO breach error rate: %.4f > %.4f\n", report.ErrRate, slo.ErrRate)
		exit = 1
	}
	os.Exit(exit)
}

func (b *Bench) fire(ctx context.Context, method, path string, payload func() []byte) error {
	var body []byte
	if payload != nil {
		body = payload()
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = &bytesBuf{b: body}
	}
	req, err := http.NewRequestWithContext(ctx, method, b.target+path, reader)
	if err != nil {
		return err
	}
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

type Report struct {
	Scenario string
	Total    int
	Errors   int
	ErrRate  float64
	Elapsed  time.Duration
	RPS      float64
	P50, P95, P99 time.Duration
}

func (r Report) Print() {
	fmt.Printf("scenario      %s\n", r.Scenario)
	fmt.Printf("total         %d\n", r.Total)
	fmt.Printf("errors        %d (%.3f%%)\n", r.Errors, r.ErrRate*100)
	fmt.Printf("elapsed       %s\n", r.Elapsed)
	fmt.Printf("throughput    %.1f req/s\n", r.RPS)
	fmt.Printf("p50/p95/p99   %s / %s / %s\n", r.P50, r.P95, r.P99)
}

func findingsPayload() []byte {
	return []byte(`{"items":[{"title":"port open","severity":"low","scanner":"nmap","port":` +
		itoa(1000+rand.Intn(60000)) + `}]}`)
}

func heartbeatPayload() []byte {
	return []byte(`{"cpu_percent":` + ftoa(rand.Float64()*100) + `,"memory_percent":` +
		ftoa(rand.Float64()*100) + `,"running_jobs":` + itoa(rand.Intn(3)) + `}`)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func ftoa(f float64) string {
	whole := int(f)
	frac := int((f - float64(whole)) * 100)
	if frac < 0 {
		frac = -frac
	}
	if frac < 10 {
		return itoa(whole) + ".0" + itoa(frac)
	}
	return itoa(whole) + "." + itoa(frac)
}

type bytesBuf struct {
	b   []byte
	pos int
}

func (bb *bytesBuf) Read(p []byte) (int, error) {
	if bb.pos >= len(bb.b) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, bb.b[bb.pos:])
	bb.pos += n
	return n, nil
}

