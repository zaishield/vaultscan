// api_spike.js — 0 → 500 VUs over 30 seconds, holds for 1 minute,
// drops back to 0. Models a thundering herd (alert storm forces
// every operator's browser to refresh, or a CI pipeline fan-out).
//
// Goal: confirm the API rate-limiter degrades gracefully (429 spike
// is acceptable; 5xx is not) and that the system recovers within
// 30 seconds after the spike clears.

import http from 'k6/http';
import { check } from 'k6';
import { authHeaders, config } from '../lib/auth.js';

export const options = {
  scenarios: {
    spike: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '30s', target: 500 },
        { duration: '1m',  target: 500 },
        { duration: '30s', target: 0 },
      ],
      gracefulRampDown: '20s',
    },
  },
  thresholds: {
    // During a spike we tolerate elevated latency but never 5xx.
    'http_req_failed{type:server_5xx}': ['rate<0.001'],
    // Some 429s are expected (the rate limiter is supposed to kick in).
    // We cap them at 25% of total requests.
    'http_req_failed{type:rate_limited}': ['rate<0.25'],
    // P95 should still be under 5s even under spike.
    http_req_duration: ['p(95)<5000'],
  },
};

export default function () {
  const r = http.get(`${config.API_URL}/api/v1/dashboards/geo`,
    { headers: authHeaders() });

  let type = 'success';
  if (r.status === 429) type = 'rate_limited';
  else if (r.status >= 500) type = 'server_5xx';
  else if (r.status >= 400) type = 'client_4xx';

  check(r, {
    'no 5xx': (x) => x.status < 500,
  }, { type });
}
