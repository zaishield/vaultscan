// baseline.js — k6 load test matching the "500 tenants, 10 users each"
// scenario documented in docs/operations/capacity-planning.md.
//
// Drives a realistic-looking mix of read + light-write traffic:
//
//   - 80% dashboard polls (replica-routed)
//   - 10% finding list / drill-down
//   -  5% asset list
//   -  5% scan submission
//
// SLO targets baked in via thresholds: a regressed build fails the
// run (exit code != 0) so CI can gate releases on it.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

const baseURL = __ENV.VAULTSCAN_API_URL || 'http://localhost:8080';
const token   = __ENV.VAULTSCAN_TEST_TOKEN || '';

if (!token) {
  throw new Error('VAULTSCAN_TEST_TOKEN required');
}

const errors = new Rate('vaultscan_request_errors');

export const options = {
  scenarios: {
    baseline_500_tenants: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '2m',  target: 100 },   // ramp
        { duration: '15m', target: 100 },   // steady-state
        { duration: '1m',  target: 0 },     // cool-down
      ],
      gracefulRampDown: '30s',
    },
  },
  thresholds: {
    // Matches the capacity-planning targets.
    http_req_duration: ['p(95)<500', 'p(99)<1500'],
    'vaultscan_request_errors': ['rate<0.001'],   // <0.1% errors
  },
};

const headers = { 'Authorization': `Bearer ${token}` };

export default function () {
  const r = Math.random();
  let resp;
  if (r < 0.80) {
    resp = http.get(`${baseURL}/api/v1/dashboards/executive`, { headers });
  } else if (r < 0.90) {
    resp = http.get(`${baseURL}/api/v1/findings?limit=50`, { headers });
  } else if (r < 0.95) {
    resp = http.get(`${baseURL}/api/v1/assets?limit=50`, { headers });
  } else {
    resp = http.post(`${baseURL}/api/v1/scans`, JSON.stringify({
      profile_code: 'baseline_quick',
      plane: 'external',
      targets: [`load.test/${Math.floor(Math.random()*1000)}`],
    }), { headers: { ...headers, 'Content-Type': 'application/json' } });
  }
  const ok = check(resp, {
    'status<400': (r) => r.status < 400,
  });
  errors.add(!ok);
  sleep(0.5 + Math.random());  // 0.5-1.5s think time per VU
}
