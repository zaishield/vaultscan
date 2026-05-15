import { useEffect, useState } from 'react';
import { findingsOps, FindingCluster } from '../api/ops';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';

export function FindingClusters() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const [clusters, setClusters] = useState<FindingCluster[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [overrideForm, setOverrideForm] = useState({ name: '', title_regex: '', new_severity: 'high', reason: '' });
  const [suppressForm, setSuppressForm] = useState({ name: '', title_regex: '', scanner_filter: '', reason: '' });

  async function load() {
    if (!tenantId) return;
    try {
      const r = await findingsOps.listClusters(tenantId);
      setClusters(r.clusters ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, [tenantId]);

  async function addOverride(e: React.FormEvent) {
    e.preventDefault();
    if (!tenantId) return;
    try {
      await findingsOps.addSeverityOverride(tenantId, overrideForm);
      setOverrideForm({ name: '', title_regex: '', new_severity: 'high', reason: '' });
      alert('Override added');
    } catch (err) { setError((err as Error).message); }
  }

  async function addSuppress(e: React.FormEvent) {
    e.preventDefault();
    if (!tenantId) return;
    try {
      await findingsOps.addSuppressionRule(tenantId, suppressForm);
      setSuppressForm({ name: '', title_regex: '', scanner_filter: '', reason: '' });
      alert('Suppression rule added');
    } catch (err) { setError((err as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="05 FINDINGS" title="Clusters · Overrides · Suppression" right={
        tenantId && (
          <a className="btn-muted" download="vaultscan-findings.sarif"
             href={findingsOps.sarifURL(tenantId)}>EXPORT SARIF</a>
        )
      } />
      <ErrorBanner error={error} />

      <Panel accent={`CLUSTERS · ${clusters.length}`} title="Similar Findings Grouped" dense>
        <DataTable<FindingCluster>
          rows={clusters}
          columns={[
            { key: 'representative_title', header: 'Family',
              render: r => <span className="text-orange-primary">{r.representative_title}</span> },
            { key: 'scanner', header: 'Scanner' },
            { key: 'member_count', header: 'Members' },
            { key: 'severity_max', header: 'Max Severity',
              render: r => <span className="uppercase">{r.severity_max}</span> },
            { key: 'last_seen', header: 'Last Seen',
              render: r => new Date(r.last_seen).toLocaleString() },
          ]}
        />
      </Panel>

      <Panel accent="SEVERITY OVERRIDE" title="Title pattern → forced severity">
        <form onSubmit={addOverride} className="grid grid-cols-2 md:grid-cols-5 gap-2">
          <input className="input" placeholder="rule name" required
                 value={overrideForm.name} onChange={e => setOverrideForm({ ...overrideForm, name: e.target.value })} />
          <input className="input" placeholder="title regex (case-insensitive)"
                 value={overrideForm.title_regex} onChange={e => setOverrideForm({ ...overrideForm, title_regex: e.target.value })} />
          <select className="input" value={overrideForm.new_severity}
                  onChange={e => setOverrideForm({ ...overrideForm, new_severity: e.target.value })}>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
          <input className="input" placeholder="reason"
                 value={overrideForm.reason} onChange={e => setOverrideForm({ ...overrideForm, reason: e.target.value })} />
          <button className="btn-primary" type="submit">ADD</button>
        </form>
      </Panel>

      <Panel accent="SUPPRESSION RULE" title="Auto-mark matching findings as false_positive">
        <form onSubmit={addSuppress} className="grid grid-cols-2 md:grid-cols-5 gap-2">
          <input className="input" placeholder="rule name" required
                 value={suppressForm.name} onChange={e => setSuppressForm({ ...suppressForm, name: e.target.value })} />
          <input className="input" placeholder="title regex"
                 value={suppressForm.title_regex} onChange={e => setSuppressForm({ ...suppressForm, title_regex: e.target.value })} />
          <input className="input" placeholder="scanner (optional)"
                 value={suppressForm.scanner_filter} onChange={e => setSuppressForm({ ...suppressForm, scanner_filter: e.target.value })} />
          <input className="input" placeholder="reason (required)" required
                 value={suppressForm.reason} onChange={e => setSuppressForm({ ...suppressForm, reason: e.target.value })} />
          <button className="btn-primary" type="submit">ADD</button>
        </form>
      </Panel>
    </div>
  );
}
