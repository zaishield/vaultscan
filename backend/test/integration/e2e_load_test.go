//go:build integration

// e2e_load_test.go — real load test against the in-process API,
// exercises the full middleware chain (auth, tenant scope, RLS,
// security headers) under concurrent load. This is the test that
// proves the system stays HEALTHY under sustained traffic, not
// just functionally correct on single-request smoke.
//
// Two test bodies:
//   1. SteadyLoad — N workers × T seconds, asserts sustained
//      throughput + p99 < threshold + 0 server-error rate.
//   2. BurstLoad — periodic concurrency spikes (5× normal); the
//      system must absorb them without 5xx blooms.
//
// Skipped under -short. Wall-clock budget tuned to ~10s; CI runs
// at this scale, longer soaks run against staging.

package integration

import (
	"context"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestE2ELoad_SteadyHealthz hammers /healthz with 50 concurrent
// workers for 5 seconds. Asserts:
//   * server-error rate (5xx) is zero
//   * p99 latency under 100ms (the route is in-memory + writeJSON)
//   * sustained throughput > 100 RPS (the test container is modest;
//     a real prod host would do 10k+ but the floor catches a
//     pathologically-slow regression)
func TestE2ELoad_SteadyHealthz(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	h := newHarness(t)
	srv := mountFullAPI(t, h)

	const (
		workers  = 50
		duration = 5 * time.Second
	)
	stats := hammer(t, srv.URL+"/healthz", workers, duration, nil)
	stats.report(t, "steady")

	if stats.fail5xx > 0 {
		t.Errorf("steady load: %d 5xx responses on /healthz", stats.fail5xx)
	}
	if ms := stats.p99().Milliseconds(); ms > 100 {
		t.Errorf("steady load: p99 %dms exceeds 100ms threshold", ms)
	}
	rps := float64(stats.total) / duration.Seconds()
	if rps < 100 {
		t.Errorf("steady load: %.0f RPS is below the 100-RPS sanity floor", rps)
	}
}

// TestE2ELoad_AuthenticatedEndpointSteady — same shape as the
// healthz test but for /api/v1/auth/me, which goes through the
// full middleware stack (auth, tenant scope, RLS GUC, security
// headers). Catches regressions in the per-request overhead.
func TestE2ELoad_AuthenticatedEndpointSteady(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	h := newHarness(t)
	srv := mountFullAPI(t, h)
	tenantID, _ := h.makeTenant(t, "load-auth-"+uuid.NewString()[:6])
	tok := mintToken(t, tenantID)

	headers := map[string]string{
		"Authorization": "Bearer " + tok,
		"X-Tenant-Id":   tenantID.String(),
	}
	const (
		workers  = 25
		duration = 5 * time.Second
	)
	stats := hammer(t, srv.URL+"/api/v1/auth/me", workers, duration, headers)
	stats.report(t, "authed steady")

	if stats.fail5xx > 0 {
		t.Errorf("authed steady: %d 5xx responses on /auth/me", stats.fail5xx)
	}
	if ms := stats.p99().Milliseconds(); ms > 200 {
		t.Errorf("authed steady: p99 %dms exceeds 200ms threshold (full middleware chain)", ms)
	}
}

// TestE2ELoad_BurstAbsorbed — fires concurrent bursts every 1
// second for 5 seconds. The API must absorb the burst without
// 5xxs. Catches:
//   * connection-pool saturation that returns 500 instead of
//     queuing
//   * panic-class crashes that take a worker down under
//     concurrent middleware execution
func TestE2ELoad_BurstAbsorbed(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	h := newHarness(t)
	srv := mountFullAPI(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		ok, fail5xx atomic.Int64
		mu          sync.Mutex
		latencies   []time.Duration
	)
	client := &http.Client{Timeout: 5 * time.Second}

	fire := func(burstSize int) {
		var wg sync.WaitGroup
		for i := 0; i < burstSize; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				t0 := time.Now()
				req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/healthz", nil)
				resp, err := client.Do(req)
				dur := time.Since(t0)
				if err != nil {
					fail5xx.Add(1)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode >= 500 {
					fail5xx.Add(1)
				} else {
					ok.Add(1)
				}
				mu.Lock()
				latencies = append(latencies, dur)
				mu.Unlock()
			}()
		}
		wg.Wait()
	}

	// Burst every 1s with 100 concurrent requests.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			goto done
		case <-ticker.C:
			fire(100)
		}
	}
done:

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p99 := time.Duration(0)
	if len(latencies) > 0 {
		p99 = latencies[len(latencies)-1*len(latencies)/100]
		if idx := int(0.99 * float64(len(latencies))); idx < len(latencies) {
			p99 = latencies[idx]
		}
	}
	t.Logf("burst-load: ok=%d fail5xx=%d p99=%dms", ok.Load(), fail5xx.Load(), p99.Milliseconds())
	if fail5xx.Load() > 0 {
		t.Errorf("burst load produced %d 5xx responses", fail5xx.Load())
	}
}

// ----- shared helpers --------------------------------------------

type loadStats struct {
	total     int64
	fail5xx   int64
	failOther int64
	latencies []time.Duration
}

func (s *loadStats) p99() time.Duration {
	if len(s.latencies) == 0 {
		return 0
	}
	idx := int(0.99 * float64(len(s.latencies)))
	if idx >= len(s.latencies) {
		idx = len(s.latencies) - 1
	}
	return s.latencies[idx]
}

func (s *loadStats) p50() time.Duration {
	if len(s.latencies) == 0 {
		return 0
	}
	return s.latencies[len(s.latencies)/2]
}

func (s *loadStats) report(t *testing.T, label string) {
	t.Helper()
	t.Logf("%s: total=%d ok=%d fail5xx=%d failOther=%d p50=%dms p99=%dms",
		label, s.total, s.total-s.fail5xx-s.failOther,
		s.fail5xx, s.failOther,
		s.p50().Milliseconds(), s.p99().Milliseconds())
}

// hammer fires concurrent requests at `url` for `duration` and
// returns aggregated stats.
func hammer(t *testing.T, url string, workers int, duration time.Duration, headers map[string]string) *loadStats {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	client := &http.Client{Timeout: 5 * time.Second}
	var (
		ok, fail5xx, failOther atomic.Int64
		mu                     sync.Mutex
		latencies              []time.Duration
		wg                     sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				t0 := time.Now()
				req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
				for k, v := range headers {
					req.Header.Set(k, v)
				}
				resp, err := client.Do(req)
				dur := time.Since(t0)
				if err != nil {
					failOther.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode >= 500 {
					fail5xx.Add(1)
				} else {
					ok.Add(1)
				}
				mu.Lock()
				latencies = append(latencies, dur)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return &loadStats{
		total:     ok.Load() + fail5xx.Load() + failOther.Load(),
		fail5xx:   fail5xx.Load(),
		failOther: failOther.Load(),
		latencies: latencies,
	}
}
