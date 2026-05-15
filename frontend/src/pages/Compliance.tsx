import { useEffect, useState } from 'react';
import { dashboardOps, ComplianceSnapshot, reportingOps, ControlCoverage } from '../api/ops';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';
import { useAuthStore } from '../store/auth';

const FRAMEWORKS = ['iso27001', 'pci_dss', 'nist_csf', 'soc2'];

export function Compliance() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const [snapshots, setSnapshots] = useState<ComplianceSnapshot[]>([]);
  const [framework, setFramework] = useState('pci_dss');
  const [engagementID, setEngagementID] = useState('');
  const [matrix, setMatrix] = useState<ControlCoverage[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!tenantId) return;
    dashboardOps.complianceSnapshot(tenantId)
      .then(r => setSnapshots(r.snapshots ?? []))
      .catch(e => setError((e as Error).message));
  }, [tenantId]);

  async function loadMatrix() {
    if (!engagementID) return;
    try {
      const r = await reportingOps.complianceMatrix(framework, engagementID);
      setMatrix(r.controls ?? []);
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="06 OUTPUT" title="Compliance Dashboard" />
      <ErrorBanner error={error} />

      <Panel accent={`OVERVIEW · ${snapshots.length} FRAMEWORKS`} title="Tenant Snapshot">
        <DataTable<ComplianceSnapshot>
          rows={snapshots}
          columns={[
            { key: 'framework', header: 'Framework',
              render: r => <span className="text-orange-primary uppercase">{r.framework}</span> },
            { key: 'framework_version', header: 'Version' },
            { key: 'controls_total', header: 'Controls' },
            { key: 'controls_at_risk', header: 'At Risk',
              render: r => <span className={r.controls_at_risk > 0 ? 'text-status-critical' : 'text-status-low'}>
                {r.controls_at_risk}</span> },
            { key: 'by_severity', header: 'Severity Mix',
              render: r => Object.entries(r.by_severity || {})
                .map(([k, v]) => `${k}:${v}`).join(' · ') || '—' },
          ]}
        />
      </Panel>

      <Panel accent="MATRIX" title="Per-Engagement Control Coverage">
        <div className="flex gap-2 mb-3">
          <select className="input" value={framework} onChange={(e) => setFramework(e.target.value)}>
            {FRAMEWORKS.map(f => <option key={f} value={f}>{f}</option>)}
          </select>
          <input className="input flex-1" placeholder="engagement UUID"
                 value={engagementID} onChange={(e) => setEngagementID(e.target.value)} />
          <button className="btn-primary" onClick={loadMatrix}>LOAD</button>
        </div>
        {matrix.length > 0 && (
          <DataTable<ControlCoverage>
            rows={matrix}
            columns={[
              { key: 'control', header: 'Code',
                render: r => <span className="font-mono">{r.control.control_code}</span> },
              { key: 'control', header: 'Title', render: r => r.control.title },
              { key: 'finding_matches', header: 'Matches',
                render: r => <span className={r.finding_matches > 0 ? 'text-status-high' : 'text-text-muted'}>
                  {r.finding_matches}</span> },
              { key: 'severity_mix', header: 'Severity Mix',
                render: r => Object.entries(r.severity_mix || {})
                  .map(([k, v]) => `${k}:${v}`).join(' · ') || '—' },
            ]}
          />
        )}
      </Panel>
    </div>
  );
}
