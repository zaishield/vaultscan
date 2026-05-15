// Typed client functions for the deepened VS-05..VS-12 + HS endpoints.
// Mirrors backend/internal/api/handlers_ops.go.

import { api } from './client';

// ---------- VS-05 Scanner ops ----------

export interface RegionQuota {
  region: string;
  at_quota: boolean;
  inflight: number;
  max: number;
  reserved_for_platform: number;
}

export const scannerOps = {
  getRegionQuota: (region: string) =>
    api.get<RegionQuota>(`/api/v1/scanner/regions/${region}/quota`),
  setRegionQuota: (region: string, max: number, reserved: number) =>
    api.put<{ status: string }>(`/api/v1/scanner/regions/${region}/quota`, {
      max_concurrent_jobs: max, reserved_for_platform: reserved,
    }),
  upsertPullCredential: (region: string, registry: string, user: string, pw: string) =>
    api.post<{ status: string }>(`/api/v1/scanner/regions/${region}/pull-credentials`, {
      registry_host: registry, username: user, password: pw,
    }),
  networkPolicyYAML: (region: string) =>
    api.raw<string>(`/api/v1/scanner/regions/${region}/network-policy.yaml`),
  sweepStalled: () =>
    api.post<{ degraded_nodes: string[]; count: number }>(`/api/v1/scanner/nodes/failover-sweep`),
};

// ---------- VS-06 Agent ops ----------

export interface AgentTelemetryBucket {
  bucket_start: string;
  samples: number;
  cpu_avg: number; cpu_peak: number;
  memory_avg: number; memory_peak: number;
  queue_peak: number;
}

export interface EmergencyStopSLA {
  count: number; avg_ms: number; p95_ms: number; breach_count: number;
}

export interface UpdateBundleOffer {
  id: string;
  manifest: {
    target_version: string;
    download_url: string;
    bundle_sha256: string;
    min_from_version?: string;
    issued_at: string;
  };
  signature_b64: string;
  signing_key_id: string;
}

export const agentOps = {
  submitCSR: (agentID: string, csrPEM: string) =>
    api.post<{ certificate_pem: string; fingerprint: string }>(
      `/api/v1/agents/${agentID}/csr`, { csr_pem: csrPEM }),
  listTelemetry: (agentID: string, since?: string) => {
    const qs = since ? `?since=${encodeURIComponent(since)}` : '';
    return api.get<{ buckets: AgentTelemetryBucket[] }>(
      `/api/v1/agents/${agentID}/telemetry${qs}`);
  },
  rollupTelemetry: (agentID: string) =>
    api.post<{ buckets_written: number }>(`/api/v1/agents/${agentID}/telemetry/rollup`),
  publishBundle: (manifest: UpdateBundleOffer['manifest'], sig: string, keyID: string, notes = '') =>
    api.post<{ id: string }>(`/api/v1/agent-updates`, {
      manifest, signature_b64: sig, signing_key_id: keyID, notes,
    }),
  offerUpdate: (agentID: string, currentVersion: string) =>
    api.get<UpdateBundleOffer | null>(
      `/api/v1/agents/${agentID}/update-offer?current_version=${encodeURIComponent(currentVersion)}`),
  requestEmergencyStop: (agentID: string, reason: string, scope: 'agent' | 'tenant' | 'engagement' = 'agent') =>
    api.post<{ emergency_stop_id: string }>(
      `/api/v1/agents/${agentID}/emergency-stop`, { reason, scope }),
  emergencyStopSLA: (agentID: string, since?: string) => {
    const qs = since ? `?since=${encodeURIComponent(since)}` : '';
    return api.get<EmergencyStopSLA>(`/api/v1/agents/${agentID}/emergency-stop-sla${qs}`);
  },
};

// ---------- VS-07 Findings ops ----------

export interface FindingCluster {
  id: string; cluster_key: string;
  representative_title: string; scanner: string;
  severity_max: string; member_count: number;
  first_seen: string; last_seen: string;
}

export const findingsOps = {
  listClusters: (tenantID: string) =>
    api.get<{ clusters: FindingCluster[] }>(
      `/api/v1/findings/clusters?tenant_id=${tenantID}`),
  addSeverityOverride: (tenantID: string, input: {
    name: string; title_regex?: string; cve_pattern?: string;
    scanner_filter?: string; new_severity: string; reason: string;
  }) => api.post<{ id: string }>(
    `/api/v1/findings/severity-overrides?tenant_id=${tenantID}`, input),
  addSuppressionRule: (tenantID: string, input: {
    name: string; title_regex?: string; cve_pattern?: string;
    scanner_filter?: string; asset_filter?: string; reason: string;
  }) => api.post<{ id: string }>(
    `/api/v1/findings/suppression-rules?tenant_id=${tenantID}`, input),
  sarifURL: (tenantID: string, opts?: { severity?: string; scanner?: string }) => {
    const qs = new URLSearchParams({ tenant_id: tenantID });
    if (opts?.severity) qs.set('severity', opts.severity);
    if (opts?.scanner) qs.set('scanner', opts.scanner);
    return `/api/v1/findings/export.sarif?${qs}`;
  },
};

// ---------- VS-08 Evidence ops ----------

export interface CustodyEvent {
  id: string; event: string;
  actor_id?: string; actor_type: string;
  ip?: string; user_agent?: string;
  details?: Record<string, unknown>;
  occurred_at: string;
}

export const evidenceOps = {
  verifyIntegrity: (evidenceID: string) =>
    api.post<{ integrity_ok: boolean }>(`/api/v1/evidence/${evidenceID}/integrity`),
  enableWORM: (evidenceID: string, until?: string) =>
    api.post<{ status: string; until: string }>(`/api/v1/evidence/${evidenceID}/worm`,
      until ? { until } : {}),
  chainOfCustody: (evidenceID: string) =>
    api.get<{ events: CustodyEvent[] }>(`/api/v1/evidence/${evidenceID}/chain-of-custody`),
  chainOfCustodyMarkdownURL: (evidenceID: string) =>
    `/api/v1/evidence/${evidenceID}/chain-of-custody.md`,
  rotateTenantKey: (tenantID: string) =>
    api.post<{ new_key_version: number }>(`/api/v1/tenants/${tenantID}/data-key/rotate`),
};

// ---------- VS-09 Retesting ops ----------

export interface RetestBatch {
  id: string; tenant_id: string; requested_by?: string;
  reason: string; status: 'open' | 'in_progress' | 'completed' | 'cancelled';
  total_items: number; completed_items: number; failed_items: number;
  created_at: string; completed_at?: string;
}

export interface RetestDiff {
  verdict: 'resolved' | 'regressed' | 'unchanged' | 'severity_dropped' | 'severity_raised';
  severity_from?: string; severity_to?: string;
  original?: Record<string, unknown>;
  post?: Record<string, unknown>;
}

export const retestOps = {
  createBatch: (tenantID: string, reason: string, findingIDs: string[]) =>
    api.post<{ batch_id: string; queued: number }>(`/api/v1/retest-batches`, {
      tenant_id: tenantID, reason, finding_ids: findingIDs,
    }),
  getBatch: (batchID: string) =>
    api.get<RetestBatch>(`/api/v1/retest-batches/${batchID}`),
  getDiff: (retestID: string) =>
    api.get<RetestDiff>(`/api/v1/retests/${retestID}/diff`),
  setAutoRetest: (tenantID: string, enabled: boolean) =>
    api.put<{ enabled: boolean }>(`/api/v1/settings/auto-retest`, {
      tenant_id: tenantID, enabled,
    }),
};

// ---------- VS-10 Reporting ops ----------

export interface ControlCoverage {
  control: {
    id: string; framework: string; framework_version: string;
    control_code: string; title: string; description?: string;
  };
  finding_matches: number;
  severity_mix?: Record<string, number>;
}

export const reportingOps = {
  createSchedule: (input: {
    tenant_id: string; engagement_id?: string;
    name: string; report_type: string; cadence: string;
    formats?: string[];
  }) => api.post<{ id: string }>(`/api/v1/report-schedules`, input),
  runDue: () => api.post<{ ran: string[]; count: number }>(`/api/v1/report-schedules/run-due`),
  complianceMatrix: (framework: string, engagementID: string) =>
    api.get<{ framework: string; controls: ControlCoverage[] }>(
      `/api/v1/compliance/${framework}/engagements/${engagementID}`),
};

// ---------- VS-11 Integration DLQ ----------

export interface DeadLetter {
  id: string; integration_id: string; event_id: string;
  event_type: string; attempts: number;
  last_error?: string; last_status_code?: number;
  enqueued_at: string; resolved_at?: string;
  resolution?: 'replayed' | 'dropped' | 'quarantined';
}

export const integrationOps = {
  listDeadLetters: (integrationID: string) =>
    api.get<{ dead_letters: DeadLetter[] }>(
      `/api/v1/integrations/${integrationID}/dead-letters`),
  replay: (dlqID: string) =>
    api.post<{ status: string }>(`/api/v1/integrations/dead-letters/${dlqID}/replay`),
  resolve: (dlqID: string, resolution: 'replayed' | 'dropped' | 'quarantined') =>
    api.post<{ resolution: string }>(`/api/v1/integrations/dead-letters/${dlqID}/resolve`,
      { resolution }),
};

// ---------- VS-12 Dashboard ops ----------

export interface GeoNode {
  node_id: string; region: string; hostname: string;
  latitude: number; longitude: number;
  city: string; country: string;
  status: string; inflight: number;
  last_heartbeat?: string;
}

export interface ComplianceSnapshot {
  framework: string; framework_version: string;
  controls_total: number; controls_at_risk: number;
  by_severity: Record<string, number>;
  updated_at: string;
}

export interface DashboardLayout {
  id: string; user_id: string; tenant_id?: string;
  name: string; role: string; is_default: boolean;
  widgets: Array<{
    id: string; type: string; title: string;
    x: number; y: number; w: number; h: number;
    config?: Record<string, unknown>;
  }>;
  updated_at: string;
}

export const dashboardOps = {
  listLayouts: () =>
    api.get<{ layouts: DashboardLayout[] }>(`/api/v1/dashboards/layouts`),
  saveLayout: (input: Partial<DashboardLayout> & { name: string; role: string }) =>
    api.post<{ id: string }>(`/api/v1/dashboards/layouts`, input),
  geoNodes: () =>
    api.get<{ nodes: GeoNode[] }>(`/api/v1/dashboards/geo`),
  complianceSnapshot: (tenantID: string) =>
    api.get<{ snapshots: ComplianceSnapshot[] }>(
      `/api/v1/dashboards/compliance?tenant_id=${tenantID}`),
  streamURL: (tenantID: string, channel = 'executive') =>
    `/api/v1/dashboards/stream?tenant_id=${tenantID}&channel=${channel}`,
};

// ---------- HS-01 Auth ops ----------

export interface IPLockout {
  ip: string; locked_until: string; reason: string; locked_at: string;
}

export const authOps = {
  listIPLockouts: () =>
    api.get<{ lockouts: IPLockout[] }>(`/api/v1/auth/ip-lockouts`),
  unlockIP: (ip: string) =>
    api.post<{ status: string }>(`/api/v1/auth/ip-lockouts/${encodeURIComponent(ip)}/unlock`),
};

// ---------- HS-02 Audit ops ----------

export interface AuditTimelineEvent {
  id: number; time: string; event: string;
  actor_id?: string; actor_type: string;
  target_type?: string; target_id?: string;
  payload?: Record<string, unknown>;
}

export interface RetentionPolicy {
  event_prefix: string; retention_days: number; archive_target?: string;
}

export interface ChainVerifyDeep {
  total_rows: number;
  first_bad_id: number;
  last_good_id: number;
  detected_at: string;
  expected_hash?: string;
  stored_hash?: string;
  detail?: string;
}

export const auditOps = {
  verifyDeep: () =>
    api.get<ChainVerifyDeep>(`/api/v1/audit/verify-deep`),
  timeline: (tenantID: string, since: string, until: string) =>
    api.get<{ events: AuditTimelineEvent[] }>(
      `/api/v1/audit/timeline?tenant_id=${tenantID}&since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}`),
  retentionPolicies: () =>
    api.get<{ policies: RetentionPolicy[] }>(`/api/v1/audit/retention-policies`),
};

// ---------- HS-05 Guardrails ----------

export interface MaintenanceState {
  enabled: boolean; reason?: string;
  started_at?: string; expected_end_at?: string;
  last_changed_by?: string; last_changed_at: string;
}

export interface PolicyRule {
  id: string; name: string; description: string;
  rule_class: 'never_allow' | 'always_require';
  subject: string;
  condition: Record<string, unknown>;
  verdict: string;
}

export const guardrailsOps = {
  maintenanceStatus: () =>
    api.get<MaintenanceState>(`/api/v1/platform/maintenance`),
  setMaintenance: (enabled: boolean, reason: string, expectedEnd?: string) =>
    api.put<{ enabled: boolean }>(`/api/v1/platform/maintenance`, {
      enabled, reason, expected_end_at: expectedEnd,
    }),
  issueBreakGlass: (permission: string, reason: string, ttlMinutes = 15) =>
    api.post<{ id: string; permission: string; expires_at: string; token: string }>(
      `/api/v1/platform/break-glass`, {
        permission, reason, ttl_minutes: ttlMinutes,
      }),
  redeemBreakGlass: (token: string) =>
    api.post<{ permission: string; issuer_id: string }>(
      `/api/v1/platform/break-glass/redeem`, { token }),
  policyRules: (subject?: string) => {
    const qs = subject ? `?subject=${subject}` : '';
    return api.get<{ rules: PolicyRule[] }>(`/api/v1/platform/policy-rules${qs}`);
  },
};
