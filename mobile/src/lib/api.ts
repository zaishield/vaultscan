// api.ts — typed fetch wrapper bound to the stored session.
import { loadSession } from './session';

async function authedFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const session = await loadSession();
  if (!session) throw new Error('not authenticated');
  const res = await fetch(`${session.apiBase}${path}`, {
    ...init,
    headers: {
      'Authorization': `Bearer ${session.token}`,
      'X-Tenant-Id':   session.tenantId,
      'Content-Type':  'application/json',
      ...(init.headers ?? {}),
    },
  });
  const text = await res.text();
  let body: unknown;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (!res.ok) {
    const msg = (body as { error?: { message?: string } } | null)?.error?.message
              ?? (typeof body === 'string' ? body : `HTTP ${res.status}`);
    throw new Error(msg);
  }
  return body as T;
}

export interface MobileDashboard {
  open_critical_count: number;
  agents_online:       number;
  agents_offline:      number;
  jobs_running:        number;
  alerts_pending:      number;
  pending_approvals: Array<{
    id: string; title: string; severity: string; requested_at: string;
  }>;
}

export const api = {
  dashboard:       () => authedFetch<MobileDashboard>('/api/v1/mobile/dashboard'),
  ackAlert:        (alertID: string) =>
    authedFetch<{ status: string }>('/api/v1/mobile/alerts/ack', {
      method: 'POST',
      body:   JSON.stringify({ alert_id: alertID }),
    }),
  emergencyStop:   (tenantID: string, reason: string) =>
    authedFetch<{ stopped: number; reason: string }>('/api/v1/mobile/emergency-stop', {
      method: 'POST',
      body:   JSON.stringify({ tenant_id: tenantID, reason }),
    }),
};
