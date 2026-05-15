import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { StatCard } from '../components/ui/StatCard';
import { StatusDot } from '../components/ui/Sev';
import type { ExecDashboard, TechDashboard, PartnerDashboard } from '../types';

export function Dashboard() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const partnerId = useAuthStore((s) => s.partnerId);
  const [exec, setExec] = useState<ExecDashboard | null>(null);
  const [tech, setTech] = useState<TechDashboard | null>(null);
  const [partner, setPartner] = useState<PartnerDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    async function tick() {
      try {
        if (tenantId) {
          const e = await api.get<ExecDashboard>(`/api/v1/dashboards/executive?tenant_id=${tenantId}`);
          const t = await api.get<TechDashboard>(`/api/v1/dashboards/technical?tenant_id=${tenantId}`);
          if (alive) { setExec(e); setTech(t); }
        }
        if (partnerId) {
          const p = await api.get<PartnerDashboard>(`/api/v1/dashboards/partner?partner_id=${partnerId}`);
          if (alive) setPartner(p);
        }
      } catch (e) {
        if (alive) setError((e as Error).message);
      }
    }
    tick();
    const t = setInterval(tick, 30000);  // refresh every 30s (Blueprint §22.2 live update)
    return () => { alive = false; clearInterval(t); };
  }, [tenantId, partnerId]);

  return (
    <div className="space-y-6">
      <div>
        <div className="label-accent mb-1">01 OVERVIEW</div>
        <h1 className="h-section">Platform Overview</h1>
        <div className="accent-line mt-2" />
      </div>
      {error && <div className="text-status-critical text-xs font-mono">{error}</div>}

      <Panel accent="EXECUTIVE" title="Risk Posture">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard label="Overall Risk Score" value={exec?.overall_risk_score?.toFixed(0) ?? '—'} tone="high" />
          <StatCard label="Critical Findings" value={exec?.critical_findings ?? '—'} tone="critical" />
          <StatCard label="High Findings" value={exec?.high_findings ?? '—'} tone="high" />
          <StatCard label="SLA Breaches" value={exec?.sla_breaches ?? '—'} tone="critical" />
          <StatCard label="Total Assets" value={exec?.total_assets ?? '—'} />
          <StatCard label="Externally Exposed" value={exec?.publicly_exposed_assets ?? '—'} />
          <StatCard label="Internal Scanned (30d)" value={exec?.internal_assets_scanned ?? '—'} />
          <StatCard label="Retests Pending" value={exec?.retest_status?.pending ?? '—'} />
        </div>
      </Panel>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Panel accent="AGENT FLEET" title="Agent Health">
          <div className="space-y-2">
            <StatusDot label={`ONLINE · ${exec?.agent_health?.online ?? 0}`}     color="#00FF88" />
            <StatusDot label={`OFFLINE · ${exec?.agent_health?.offline ?? 0}`}    color="#8A8A8A" />
            <StatusDot label={`PENDING · ${exec?.agent_health?.pending ?? 0}`}    color="#FFB800" />
            <StatusDot label={`QUARANTINED · ${exec?.agent_health?.quarantined ?? 0}`} color="#FF2D2D" />
          </div>
        </Panel>
        <Panel accent="14-DAY TREND" title="Scans Per Day">
          <div className="flex items-end gap-1 h-32">
            {(exec?.scan_trend ?? []).map((b) => (
              <div key={b.date} className="flex-1 flex flex-col items-center gap-1">
                <div className="bg-orange-primary/60 hover:bg-orange-primary transition-colors w-full"
                     style={{ height: `${Math.min(100, b.scans * 10)}%` }} />
                <div className="text-[8px] font-mono text-text-muted">{b.date.slice(5)}</div>
              </div>
            ))}
            {(!exec?.scan_trend || exec.scan_trend.length === 0) && (
              <div className="text-text-muted text-xs font-mono">No scans yet.</div>
            )}
          </div>
        </Panel>
      </div>

      <Panel accent="TECHNICAL" title="Findings Distribution">
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          <StatCard label="Critical" value={tech?.findings_by_severity?.critical ?? 0} tone="critical" />
          <StatCard label="High"     value={tech?.findings_by_severity?.high ?? 0}     tone="high" />
          <StatCard label="Medium"   value={tech?.findings_by_severity?.medium ?? 0} />
          <StatCard label="Low"      value={tech?.findings_by_severity?.low ?? 0}     tone="low" />
          <StatCard label="Info"     value={tech?.findings_by_severity?.info ?? 0} />
          <StatCard label="TLS Issues" value={tech?.tls_issues ?? 0} />
          <StatCard label="AD Risks" value={tech?.ad_risks ?? 0} />
          <StatCard label="Cloud Posture" value={tech?.cloud_posture_risks ?? 0} />
          <StatCard label="K8s Risks" value={tech?.k8s_risks ?? 0} />
          <StatCard label="Container Risks" value={tech?.container_risks ?? 0} />
          <StatCard label="Open Ports" value={tech?.open_ports ?? 0} />
          <StatCard label="Web/API" value={tech?.web_api_vulnerabilities ?? 0} />
        </div>
      </Panel>

      {partner && (
        <Panel accent="PARTNER" title="Network Roll-up">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard label="Customers Managed" value={partner.customers_managed} />
            <StatCard label="Active Tenants" value={partner.active_tenants} />
            <StatCard label="Active Agents" value={partner.active_agents} />
            <StatCard label="Scans (30d)" value={partner.scan_usage_30d} />
            <StatCard label="Open Critical (rollup)" value={partner.open_critical_across_tenants} tone="critical" />
            <StatCard label="Expiring Engagements" value={partner.expiring_engagements} />
            <StatCard label="Assets Used" value={partner.license_usage.assets_used} />
            <StatCard label="Agents Used" value={partner.license_usage.agents_used} />
          </div>
        </Panel>
      )}
    </div>
  );
}
