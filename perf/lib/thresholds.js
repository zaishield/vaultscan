// thresholds.js — shared SLO targets every scenario imports.
//
// k6 thresholds language:
//   http_req_duration{...}: ['p(50)<250', 'p(95)<1000', 'p(99)<2500']
//   http_req_failed:         ['rate<0.005']
//   <custom_metric>:         ['p(95)<30000']
//
// One source of truth — change here, every scenario inherits.

export const apiThresholds = {
  // Median ≤ 250ms, P95 ≤ 1s, P99 ≤ 2.5s.
  http_req_duration: ['p(50)<250', 'p(95)<1000', 'p(99)<2500'],
  // Below 0.5% of requests should fail.
  http_req_failed: ['rate<0.005'],
};

export const writeThresholds = {
  http_req_duration: ['p(50)<500', 'p(95)<2000', 'p(99)<5000'],
  http_req_failed: ['rate<0.01'],
};

// Emergency stop must complete end-to-end within 30 s (Blueprint §11.6).
// We measure with a custom Trend metric per scenario.
export const emergencyStopThresholds = {
  emergency_stop_e2e_ms: ['p(95)<30000', 'max<60000'],
  http_req_failed: ['rate<0.01'],
};

// Findings ingest target: ≥ 50/s sustained, P95 ingest latency ≤ 1s.
export const ingestThresholds = {
  http_req_duration: ['p(50)<300', 'p(95)<1000'],
  http_req_failed: ['rate<0.01'],
  // iterations_per_second is computed from the run duration; a 5-min
  // soak with 50 RPS target means we expect at least 14 500 iterations.
  iterations: ['rate>50'],
};
