// scan_submit_burst.js — submits ~1000 scan jobs in 60 seconds via
// /api/v1/scans/external. Verifies the orchestrator + scope-guard +
// scan_jobs INSERT path can sustain the §11 1000-concurrent-scans
// requirement.

import http from 'k6/http';
import { check } from 'k6';
import { writeThresholds } from '../lib/thresholds.js';
import { authHeaders, config } from '../lib/auth.js';

export const options = {
  scenarios: {
    burst: {
      executor: 'constant-arrival-rate',
      rate: 17,                  // 17 RPS × 60 s ≈ 1020 scans submitted
      timeUnit: '1s',
      duration: '1m',
      preAllocatedVUs: 50,
      maxVUs: 200,
    },
  },
  thresholds: writeThresholds,
};

const ENGAGEMENT_ID = __ENV.VAULTSCAN_LOAD_ENGAGEMENT_ID || '00000000-0000-0000-0000-000000000010';
const PARTNER_ID    = __ENV.VAULTSCAN_LOAD_PARTNER_ID    || '00000000-0000-0000-0000-000000000020';

export default function () {
  const headers = authHeaders();
  // Vary the target so dedup at the scope-guard layer doesn't
  // collapse every submission into a single job.
  const target = `203.0.113.${Math.floor(Math.random() * 254) + 1}`;
  const body = JSON.stringify({
    partner_id: PARTNER_ID,
    tenant_id:  config.TENANT_ID,
    engagement_id: ENGAGEMENT_ID,
    profile_code: 'ext_recon_quick',
    region: 'us-east-1',
    targets: [target],
  });
  const r = http.post(`${config.API_URL}/api/v1/scans/external`, body, { headers });
  check(r, {
    'submit < 500': (x) => x.status < 500,
    'submit 2xx':   (x) => x.status >= 200 && x.status < 300,
  });
}
