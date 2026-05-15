// api_steady.js — sustained 100-VU mixed read load for 5 minutes.
//
// Models the operational baseline: half the calls hit dashboards
// (~30 RPS in steady state), a third hit findings/listing endpoints,
// the rest hit marketplace + integrations.
//
// Goal: prove API median ≤ 250ms / P95 ≤ 1s / P99 ≤ 2.5s with
// error rate < 0.5% under sustained 100-concurrent load.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { apiThresholds } from '../lib/thresholds.js';
import { authHeaders, config } from '../lib/auth.js';

export const options = {
  scenarios: {
    sustained: {
      executor: 'ramping-vus',
      startVUs: 10,
      stages: [
        { duration: '30s', target: 100 }, // ramp up
        { duration: '4m',  target: 100 }, // soak
        { duration: '30s', target: 0 },   // ramp down
      ],
      gracefulRampDown: '30s',
    },
  },
  thresholds: apiThresholds,
};

const ENDPOINTS = [
  // 50% — dashboards and metrics most ops view
  { path: '/api/v1/dashboards/geo',           weight: 25 },
  { path: '/api/v1/audit/retention-policies', weight: 5 },
  { path: '/api/v1/audit/timeline?since=2024-01-01T00:00:00Z&until=2025-01-01T00:00:00Z',
    weight: 20 },
  // 30% — findings + assets list
  { path: '/api/v1/findings',                 weight: 15 },
  { path: '/api/v1/assets',                   weight: 15 },
  // 20% — meta + marketplace/integrations
  { path: '/api/v1/marketplace/listings',     weight: 10 },
  { path: '/api/v1/marketplace/installs',     weight: 5 },
  { path: '/api/v1/integrations',             weight: 5 },
];

// Build a weighted lookup table once.
const TABLE = (() => {
  const t = [];
  for (const e of ENDPOINTS) {
    for (let i = 0; i < e.weight; i++) t.push(e.path);
  }
  return t;
})();

export default function () {
  const headers = authHeaders();
  const path = TABLE[Math.floor(Math.random() * TABLE.length)];
  const url = path.includes('?') ? `${config.API_URL}${path}` : `${config.API_URL}${path}?tenant_id=${config.TENANT_ID}`;
  const r = http.get(url, { headers, tags: { endpoint: path } });
  check(r, { 'status < 500': (x) => x.status < 500 });
  sleep(0.1 + Math.random() * 0.5);
}
