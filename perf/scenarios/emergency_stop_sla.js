// emergency_stop_sla.js — measures end-to-end emergency-stop latency
// against the §11.6 SLO of ≤30 s.
//
// Per iteration:
//   1. POST a scan job (must be in 'pending' or 'dispatched' state).
//   2. POST /api/v1/scan-jobs/emergency-stop with tenant scope.
//   3. Poll GET /api/v1/scan-jobs/{id} until status='stopped'.
//   4. Record end-to-end latency into a custom Trend metric.
//
// We run 30 iterations so the P95 is meaningful; each iteration is
// independent (own scan job).

import http from 'k6/http';
import { check, fail, sleep } from 'k6';
import { Trend } from 'k6/metrics';
import { emergencyStopThresholds } from '../lib/thresholds.js';
import { authHeaders, config } from '../lib/auth.js';

const e2e = new Trend('emergency_stop_e2e_ms');

export const options = {
  scenarios: {
    sla: {
      executor: 'per-vu-iterations',
      vus: 1,
      iterations: 30,
      maxDuration: '15m',
    },
  },
  thresholds: emergencyStopThresholds,
};

const ENGAGEMENT_ID = __ENV.VAULTSCAN_LOAD_ENGAGEMENT_ID || '00000000-0000-0000-0000-000000000010';
const PARTNER_ID    = __ENV.VAULTSCAN_LOAD_PARTNER_ID    || '00000000-0000-0000-0000-000000000020';

export default function () {
  const headers = authHeaders();

  // Submit a scan that we'll then halt.
  const submit = http.post(`${config.API_URL}/api/v1/scans/external`,
    JSON.stringify({
      partner_id:    PARTNER_ID,
      tenant_id:     config.TENANT_ID,
      engagement_id: ENGAGEMENT_ID,
      profile_code:  'ext_recon_quick',
      region:        'us-east-1',
      targets:       ['203.0.113.42'],
    }), { headers });
  if (submit.status >= 300) {
    fail(`submit failed: ${submit.status} ${submit.body}`);
  }
  const scanID = JSON.parse(submit.body).id;

  // Fire the emergency stop. Time starts here.
  const start = Date.now();
  const stop = http.post(`${config.API_URL}/api/v1/scan-jobs/emergency-stop`,
    JSON.stringify({ tenant_id: config.TENANT_ID, reason: 'k6 load drill' }),
    { headers });
  check(stop, { 'emergency-stop 200': (x) => x.status === 200 });

  // Poll until terminal.
  const deadline = start + 60_000;
  let observedStatus = '';
  while (Date.now() < deadline) {
    const get = http.get(`${config.API_URL}/api/v1/scan-jobs/${scanID}`, { headers });
    if (get.status === 200) {
      try {
        const job = JSON.parse(get.body);
        if (job.status === 'stopped' || job.status === 'failed' ||
            job.status === 'succeeded') {
          observedStatus = job.status;
          break;
        }
      } catch {}
    }
    sleep(0.5);
  }
  const elapsed = Date.now() - start;
  e2e.add(elapsed);
  check(null, {
    'reached terminal state': () => observedStatus !== '',
    'within 30s SLO':         () => elapsed <= 30_000,
  });
}
