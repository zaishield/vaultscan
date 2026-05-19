// cmd/loadtest is a minimal Go-native load generator for the
// VaultScan API. It is intentionally NOT a comprehensive load suite
// (use k6 / vegeta against a staging environment for that) — its
// job is to give engineers a single binary that can:
//
//   * fire N concurrent workers against a target URL
//   * report per-status latency percentiles
//   * exit non-zero if the failure rate or p99 exceeds operator-
//     supplied thresholds, so CI can gate releases on a regression
//
// Usage:
//   loadtest -target http://localhost:8080/healthz \
//            -workers 50 -duration 30s \
//            -max-fail-pct 0.5 -max-p99-ms 250
//
// Sample output:
//   target=http://localhost:8080/healthz workers=50 duration=30s
//   total=14823 ok=14820 fail=3 fail_pct=0.020%
//   latency_ms p50=1.8 p90=3.4 p99=12.7 max=204.0
//   verdict: PASS (limits: fail_pct<=0.500% p99<=250.0ms)
//
// This binary is excluded from production container images by
// default (it has no use there).

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	target := flag.String("target", "", "absolute URL OR comma-separated list of URLs (multi-target mode)")
	method := flag.String("method", "GET", "HTTP method (applies to every target)")
	workers := flag.Int("workers", 25, "concurrent workers per phase")
	duration := flag.Duration("duration", 10*time.Second, "wall-clock test duration")
	header := flag.String("header", "", "optional 'Name: value' header (repeatable via comma-split)")
	maxFailPct := flag.Float64("max-fail-pct", 1.0, "exit non-zero if failure% exceeds this")
	maxP99Ms := flag.Float64("max-p99-ms", 500.0, "exit non-zero if p99 latency (ms) exceeds this")
	mode := flag.String("mode", "steady", "load shape: steady | burst | soak")
	burstMul := flag.Int("burst-mul", 10, "burst-mode multiplier (workers ×N during burst windows)")
	burstEvery := flag.Duration("burst-every", 5*time.Second, "burst-mode burst interval")
	burstFor := flag.Duration("burst-for", 1*time.Second, "burst-mode burst duration each cycle")
	soakProgress := flag.Duration("soak-progress", 30*time.Second, "soak-mode periodic stats interval")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "loadtest: -target is required")
		os.Exit(2)
	}
	targets := splitTopLevel(*target, ',')
	for i, t := range targets {
		targets[i] = trim(t)
	}
	if len(targets) == 0 || targets[0] == "" {
		fmt.Fprintln(os.Stderr, "loadtest: -target is required")
		os.Exit(2)
	}
	if *mode != "steady" && *mode != "burst" && *mode != "soak" {
		fmt.Fprintf(os.Stderr, "loadtest: -mode must be steady|burst|soak (got %q)\n", *mode)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	// Graceful SIGINT — stop the test, still print the summary.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; cancel() }()

	headerKV := parseHeaders(*header)

	stats := make(map[string]*targetStats, len(targets))
	for _, t := range targets {
		stats[t] = &targetStats{latencyCh: make(chan time.Duration, *workers*64)}
	}

	client := &http.Client{Timeout: 30 * time.Second}

	// runWorker fires one request at a time for the lifetime of its
	// ctx, rotating through every target. Used in every mode.
	runWorker := func(ctx context.Context) {
		i := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			target := targets[i%len(targets)]
			i++
			req, err := http.NewRequestWithContext(ctx, *method, target, nil)
			if err != nil {
				stats[target].fail.Add(1)
				continue
			}
			for k, v := range headerKV {
				req.Header.Set(k, v)
			}
			t0 := time.Now()
			resp, err := client.Do(req)
			dur := time.Since(t0)
			if err != nil {
				stats[target].fail.Add(1)
				continue
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				stats[target].fail.Add(1)
			} else {
				stats[target].ok.Add(1)
			}
			select {
			case stats[target].latencyCh <- dur:
			default:
			}
		}
	}

	// Steady-state worker pool — always running.
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() { defer wg.Done(); runWorker(ctx) }()
	}

	// Mode-specific overlays.
	switch *mode {
	case "burst":
		// Every burst-every interval, spawn an EXTRA pool of
		// workers × burst-mul for burst-for duration. Simulates
		// thundering-herd patterns (cron firing across N pods,
		// a marketing email blast, etc.).
		extraStop := make(chan struct{})
		go func() {
			ticker := time.NewTicker(*burstEvery)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					close(extraStop)
					return
				case <-ticker.C:
					burstCtx, burstCancel := context.WithTimeout(ctx, *burstFor)
					var burstWG sync.WaitGroup
					for b := 0; b < *workers*(*burstMul); b++ {
						burstWG.Add(1)
						go func() { defer burstWG.Done(); runWorker(burstCtx) }()
					}
					burstWG.Wait()
					burstCancel()
				}
			}
		}()
		<-extraStop

	case "soak":
		// Long-running pattern: periodic progress dumps so the
		// operator can watch a multi-hour soak unfold.
		go func() {
			ticker := time.NewTicker(*soakProgress)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					printProgress(targets, stats, start)
				}
			}
		}()
	}

	wg.Wait()
	for _, t := range targets {
		close(stats[t].latencyCh)
	}
	elapsed := time.Since(start)

	// Aggregate per-target + global metrics.
	overallFailed := false
	for _, target := range targets {
		s := stats[target]
		latencies := drainLatencies(s.latencyCh)
		okN := s.ok.Load()
		failN := s.fail.Load()
		total := okN + failN
		failPct := 0.0
		if total > 0 {
			failPct = 100.0 * float64(failN) / float64(total)
		}
		p50 := percentile(latencies, 0.50)
		p90 := percentile(latencies, 0.90)
		p99 := percentile(latencies, 0.99)
		maxL := time.Duration(0)
		if len(latencies) > 0 {
			maxL = latencies[len(latencies)-1]
		}

		fmt.Printf("target=%s mode=%s workers=%d duration=%s\n",
			target, *mode, *workers, elapsed)
		fmt.Printf("  total=%d ok=%d fail=%d fail_pct=%.3f%%\n", total, okN, failN, failPct)
		fmt.Printf("  latency_ms p50=%.1f p90=%.1f p99=%.1f max=%.1f\n",
			ms(p50), ms(p90), ms(p99), ms(maxL))

		if failPct > *maxFailPct {
			fmt.Printf("  FAIL: %s failure rate %.3f%% exceeds limit %.3f%%\n",
				target, failPct, *maxFailPct)
			overallFailed = true
		}
		if ms(p99) > *maxP99Ms {
			fmt.Printf("  FAIL: %s p99 %.1fms exceeds limit %.1fms\n",
				target, ms(p99), *maxP99Ms)
			overallFailed = true
		}
	}
	if overallFailed {
		os.Exit(1)
	}
	fmt.Printf("verdict: PASS (mode=%s, %d target(s); limits: fail_pct<=%.3f%% p99<=%.1fms)\n",
		*mode, len(targets), *maxFailPct, *maxP99Ms)
}

// drainLatencies collects and sorts.
func drainLatencies(ch chan time.Duration) []time.Duration {
	out := make([]time.Duration, 0, 1024)
	for d := range ch {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// targetStats is per-target counters + a latency channel that
// workers append to. Aggregated at end-of-run; sampled live by
// printProgress during soak.
type targetStats struct {
	ok, fail  atomic.Int64
	latencyCh chan time.Duration
}

// printProgress emits a one-line-per-target snapshot during soak.
// Atomically reads counters and prints — doesn't drain the channel.
func printProgress(targets []string, stats map[string]*targetStats, start time.Time) {
	elapsed := time.Since(start).Round(time.Second)
	for _, t := range targets {
		s := stats[t]
		ok := s.ok.Load()
		fl := s.fail.Load()
		fmt.Printf("[soak-progress %s] %s ok=%d fail=%d rps=%.1f\n",
			elapsed, t, ok, fl, float64(ok+fl)/elapsed.Seconds())
	}
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000.0 }

// parseHeaders splits "Name: value, Name2: value2" into a map.
// Permissive — operators can omit it for unauthenticated probes.
func parseHeaders(s string) map[string]string {
	out := map[string]string{}
	if s == "" {
		return out
	}
	for _, pair := range splitTopLevel(s, ',') {
		colon := -1
		for i, b := range pair {
			if b == ':' {
				colon = i
				break
			}
		}
		if colon < 0 {
			continue
		}
		k := trim(pair[:colon])
		v := trim(pair[colon+1:])
		if k != "" {
			out[k] = v
		}
	}
	return out
}

func splitTopLevel(s string, sep byte) []string {
	var parts []string
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[last:i])
			last = i + 1
		}
	}
	parts = append(parts, s[last:])
	return parts
}

func trim(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}
