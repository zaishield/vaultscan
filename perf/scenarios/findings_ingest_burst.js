// findings_ingest_burst.js — drives ≥50 findings/sec into the
// findings.Service.Upsert path for 5 minutes via the synthetic
// scanner-results ingest endpoint.
//
// Verifies the dedup + audit-chain + bus-publish hot path under
// sustained ingest load. With 50/s for 300s we expect ≥15 000
// successful upserts.

import http from 'k6/http';
import { check } from 'k6';
import { ingestThresholds } from '../lib/thresholds.js';
import { authHeaders, config } from '../lib/auth.js';

export const options = {
  scenarios: {
    ingest: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 100,
      maxVUs: 300,
    },
  },
  thresholds: ingestThresholds,
};

const ENGAGEMENT_ID = __ENV.VAULTSCAN_LOAD_ENGAGEMENT_ID || '00000000-0000-0000-0000-000000000010';
const PARTNER_ID    = __ENV.VAULTSCAN_LOAD_PARTNER_ID    || '00000000-0000-0000-0000-000000000020';

const SEVERITIES = ['low', 'medium', 'high', 'critical'];

export default function () {
  const headers = authHeaders();
  // Most of the load should be NEW findings (unique title + endpoint)
  // to hit the INSERT path; ~10% repeats hit the dedup path.
  const isDup = Math.random() < 0.1;
  const idx = isDup ? Math.floor(Math.random() * 100) : Math.floor(Math.random() * 1e9);
  const sev = SEVERITIES[Math.floor(Math.random() * SEVERITIES.length)];
  const body = JSON.stringify({
    platform_id:  '00000000-0000-0000-0000-000000000001',
    partner_id:   PARTNER_ID,
    tenant_id:    config.TENANT_ID,
    engagement_id: ENGAGEMENT_ID,
    title: `loadtest-finding-${idx}`,
    severity: sev,
    scanner: 'loadtest',
    affected_endpoint: `target-${idx % 1000}.example`,
  });
  const r = http.post(`${config.API_URL}/api/v1/findings/ingest`, body, { headers });
  check(r, {
    'ingest 2xx': (x) => x.status >= 200 && x.status < 300,
  });
}
