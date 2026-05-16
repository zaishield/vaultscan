// integrations_test_burst.js — drives concurrent integration
// "test connection" calls. This is the path customers hit when
// configuring a Slack/webhook/Jira destination; in a 100-tenant
// trial it can spike to ~50 concurrent calls.
//
// Goal: confirm Test() stays under 500ms p95 even at 50 VUs and that
// success rate stays above 99% when the receiver is healthy.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { apiThresholds } from '../lib/thresholds.js';
import { authHeaders, config } from '../lib/auth.js';

export const options = {
  scenarios: {
    integrations_test_burst: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '20s', target: 10 },
        { duration: '40s', target: 50 },
        { duration: '20s', target: 0 },
      ],
      gracefulRampDown: '10s',
    },
  },
  thresholds: {
    ...apiThresholds,
    http_req_failed: ['rate<0.01'],          // <1% failures
    http_req_duration: ['p(95)<500'],        // p95 under 500ms
  },
};

export default function () {
  const headers = authHeaders();
  // List integrations is the read path on the same page.
  const list = http.get(
    `${config.API_URL}/api/v1/integrations?tenant_id=${config.TENANT_ID}`,
    { headers });
  check(list, { 'list 200': (x) => x.status === 200 });

  // Health rollup feeds the integration health dashboard.
  const health = http.get(
    `${config.API_URL}/api/v1/integrations/health?tenant_id=${config.TENANT_ID}`,
    { headers });
  check(health, { 'health 200': (x) => x.status === 200 });

  sleep(0.3);
}
