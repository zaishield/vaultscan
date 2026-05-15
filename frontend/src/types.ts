// Mirrors backend models. Kept narrow on purpose - extend as the UI needs.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Status =
  | 'open' | 'triaged' | 'assigned' | 'in_progress'
  | 'risk_accepted' | 'false_positive' | 'remediated'
  | 'retest_requested' | 'retest_passed' | 'retest_failed' | 'closed';

export interface Branding {
  partner: { id: string; name: string; slug: string; type: string };
  branding: {
    product_name: string;
    logo_url: string;
    primary_color: string;
    secondary_color: string;
    accent_color?: string;
    legal_footer?: string;
    confidentiality_tag?: string;
    watermark_text?: string;
    support_email?: string;
  };
  feature_flags: Record<string, boolean>;
  support: { url?: string; email?: string; phone?: string; sla_response_minutes: number };
}

export interface Tenant {
  id: string; partner_id: string; name: string; slug: string; status: string;
  isolation_mode: string; created_at: string;
}
export interface Partner {
  id: string; platform_id: string; parent_id?: string;
  type: string; name: string; slug: string; status: string; created_at: string;
}
export interface Engagement {
  id: string; tenant_id: string; partner_id: string;
  code: string; name: string; description: string; status: string;
  starts_at: string; ends_at: string; intensity: string;
}
export interface ScopeTarget {
  id: string; engagement_id: string; target_type: string; target_value: string;
  plane: 'external' | 'internal'; status: 'pending' | 'approved' | 'rejected';
  notes?: string; created_at: string;
}
export interface Asset {
  id: string; tenant_id: string; engagement_id?: string;
  asset_type: string; name: string; value: string;
  plane: 'external' | 'internal';
  criticality: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  owner?: string; environment?: string; cloud_provider?: string;
  tags: string[]; first_seen: string; last_seen: string;
}
export interface ScanProfile {
  id: string; code: string; name: string; plane: string;
  intensity: string; description: string; tools: string[];
  requires_approval: boolean;
}
export interface ScanJob {
  id: string; tenant_id: string; engagement_id: string;
  profile_code: string; plane: string; region?: string; agent_id?: string;
  status: string; target_summary: string; targets: string[];
  requires_approval: boolean; created_at: string;
}
export interface Agent {
  id: string; tenant_id: string; name: string; location?: string;
  form_factor: string; version?: string; status: string;
  last_heartbeat?: string; cpu_percent?: number; memory_percent?: number;
  cert_status: string; cert_expires_at?: string; emergency_stop_armed: boolean;
  created_at: string;
}
export interface Finding {
  id: string; tenant_id: string; engagement_id: string; asset_id?: string;
  title: string; description?: string; severity: Severity; status: Status;
  cvss_score?: number; cve?: string; cwe?: string; scanner: string; scan_type: string;
  affected_endpoint?: string; port?: number; protocol?: string;
  remediation?: string; first_seen: string; last_seen: string;
}
export interface Evidence {
  id: string; tenant_id: string; finding_id?: string; engagement_id?: string;
  evidence_type: string; storage_url: string; sha256: string;
  size_bytes: number; content_type: string; uploaded_at: string;
}
export interface Report {
  id: string; report_type: string; title: string; status: string;
  exports: { format: string; storage_url: string; sha256: string; size_bytes: number }[];
  generated_at: string;
}
export interface ExecDashboard {
  overall_risk_score: number;
  total_assets: number;
  publicly_exposed_assets: number;
  internal_assets_scanned: number;
  critical_findings: number;
  high_findings: number;
  sla_breaches: number;
  retest_status: { pending: number; passed: number; failed: number };
  compliance_status: Record<string, number>;
  agent_health: { online: number; offline: number; pending: number; quarantined: number };
  scan_trend: { date: string; scans: number }[];
}
export interface TechDashboard {
  findings_by_severity: Record<string, number>;
  findings_by_asset: { key: string; count: number }[];
  findings_by_scanner: Record<string, number>;
  open_ports: number; exposed_services: number; tls_issues: number;
  ad_risks: number; cloud_posture_risks: number; container_risks: number;
  k8s_risks: number; web_api_vulnerabilities: number;
}
export interface PartnerDashboard {
  customers_managed: number;
  active_tenants: number;
  active_agents: number;
  scan_usage_30d: number;
  license_usage: { assets_used: number; scans_used: number; agents_used: number };
  open_critical_across_tenants: number;
  expiring_engagements: number;
  billing_counters: Record<string, number>;
}
