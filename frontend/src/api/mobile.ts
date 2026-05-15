// API client for §24 mobile portal endpoints.

import { api } from './client';

export interface MobileDevice {
  id: string;
  user_id: string;
  device_label: string;
  platform: 'ios' | 'android';
  push_token: string;
  enrolled_at: string;
  last_seen_at?: string;
  revoked_at?: string;
}

export interface MobileDashboard {
  open_critical_count: number;
  agents_online: number;
  agents_offline: number;
  jobs_running: number;
  alerts_pending: number;
  pending_approvals: Array<{
    id: string;
    title: string;
    severity: string;
    requested_at: string;
  }>;
}

export const mobile = {
  enrollDevice: (input: {
    tenant_id: string;
    device_label: string;
    platform: 'ios' | 'android';
    push_token: string;
  }) => api.post<{ device_id: string }>(`/api/v1/mobile/devices`, input),

  revokeDevice: (deviceID: string) =>
    api.delete<{ status: string }>(`/api/v1/mobile/devices/${deviceID}`),

  dashboard: () =>
    api.get<MobileDashboard>(`/api/v1/mobile/dashboard`),

  ackAlert: (alertID: string) =>
    api.post<{ status: string }>(`/api/v1/mobile/alerts/ack`, {
      alert_id: alertID,
    }),

  emergencyStop: (tenantID: string, reason: string) =>
    api.post<{ stopped: number; reason: string }>(
      `/api/v1/mobile/emergency-stop`, { tenant_id: tenantID, reason }),
};
