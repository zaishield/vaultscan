// api_smoke.js — quick correctness check before launching a real
// load test. 10 VUs × 30s, exercises every read endpoint a
// dashboard typically polls. Asserts SLO thresholds plus a few
// per-request response shape checks.

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { apiThresholds } from '../lib/thresholds.js';
import { authHeaders, config } from '../lib/auth.js';

export const options = {
  vus: 10,
  duration: '30s',
  thresholds: apiThresholds,
};

export default function () {
  const headers = authHeaders();

  group('healthz', () => {
    const r = http.get(`${config.API_URL}/healthz`, { headers });
    check(r, { 'healthz 200': (x) => x.status === 200 });
  });

  group('dashboard', () => {
    const r = http.get(`${config.API_URL}/api/v1/dashboards/geo`, { headers });
    check(r, { 'geo nodes 200': (x) => x.status === 200 });
  });

  group('integrations.list', () => {
    const r = http.get(
      `${config.API_URL}/api/v1/integrations?tenant_id=${config.TENANT_ID}`,
      { headers });
    check(r, { 'integrations 200': (x) => x.status === 200 });
  });

  group('marketplace.list', () => {
    const r = http.get(`${config.API_URL}/api/v1/marketplace/listings`, { headers });
    check(r, {
      'marketplace 200': (x) => x.status === 200,
      'has listings':    (x) => {
        try { return (JSON.parse(x.body).listings || []).length > 0; }
        catch { return false; }
      },
    });
  });

  group('audit.policies', () => {
    const r = http.get(`${config.API_URL}/api/v1/audit/retention-policies`, { headers });
    check(r, { 'audit policies 200': (x) => x.status === 200 });
  });

  group('jwks', () => {
    const r = http.get(`${config.API_URL}/api/v1/.well-known/jwks.json`);
    check(r, {
      'jwks 200': (x) => x.status === 200,
      'has keys': (x) => {
        try { return (JSON.parse(x.body).keys || []).length > 0; }
        catch { return false; }
      },
    });
  });

  sleep(1);
}
