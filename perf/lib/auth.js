// auth.js — bearer token + tenant header builder.
//
// Production flow uses /api/v1/auth/login + MFA (POST /api/v1/auth/mfa/verify).
// Load tests use either:
//   1. A pre-minted token in env VAULTSCAN_LOAD_TOKEN
//   2. The /api/v1/auth/dev-token endpoint (only available in
//      VAULTSCAN_ENV=development; the production guard refuses to
//      mount the route otherwise)

import http from 'k6/http';
import { check, fail } from 'k6';

const API_URL = __ENV.VAULTSCAN_API_URL || 'http://localhost:8080';
const TENANT_ID = __ENV.VAULTSCAN_TENANT_ID || '00000000-0000-0000-0000-000000000001';

// authHeaders returns the headers map every authenticated request needs.
// Memoizes the token across iterations.
let _token = null;
export function authHeaders() {
  if (!_token) {
    _token = mintToken();
  }
  return {
    Authorization: `Bearer ${_token}`,
    'X-Tenant-Id': TENANT_ID,
    'Content-Type': 'application/json',
  };
}

function mintToken() {
  if (__ENV.VAULTSCAN_LOAD_TOKEN) {
    return __ENV.VAULTSCAN_LOAD_TOKEN;
  }
  // Fall back to the dev-token endpoint.
  const resp = http.post(
    `${API_URL}/api/v1/auth/dev-token`,
    JSON.stringify({
      email: 'loadtest@vaultscan.test',
      full_name: 'Load Test',
      tenant_id: TENANT_ID,
      roles: ['zaishield_super_admin'],
      ttl_seconds: 7200,
      mfa: true,
    }),
    { headers: { 'Content-Type': 'application/json' } },
  );
  check(resp, { 'dev-token 200': (r) => r.status === 200 });
  if (resp.status !== 200) {
    fail(`mint dev token: ${resp.status} ${resp.body}`);
  }
  const body = JSON.parse(resp.body);
  return body.token;
}

export const config = { API_URL, TENANT_ID };
