import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { SevBadge } from '../components/ui/Sev';
import { PageHeader, ErrorBanner } from './_helpers';
import type { Finding, Severity, Status } from '../types';

const SEVS: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES: Status[] = ['open','triaged','assigned','in_progress','risk_accepted','false_positive','remediated','retest_requested','retest_passed','retest_failed','closed'];

export function Findings() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const [items, setItems] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [sev, setSev] = useState<Severity | ''>('');
  const [status, setStatus] = useState<Status | ''>('');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<Finding | null>(null);

  async function load() {
    if (!tenantId) return;
    const qs = new URLSearchParams({ tenant_id: tenantId });
    if (sev) qs.set('severity', sev);
    if (status) qs.set('status', status);
    if (search) qs.set('q', search);
    try {
      const r = await api.get<{ items: Finding[] }>(`/api/v1/findings?${qs}`);
      setItems(r.items ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, [tenantId, sev, status, search]);

  async function transition(id: string, to: Status) {
    try { await api.patch(`/api/v1/findings/${id}`, { status: to }); load(); }
    catch (e) { setError((e as Error).message); }
  }
  async function requestRetest(id: string) {
    try { await api.post('/api/v1/retests', { finding_id: id, note: 'Retest queued from findings page' }); load(); }
    catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="05 FINDINGS" title="Vulnerability Findings" />
      <ErrorBanner error={error} />
      <Panel accent="FILTER" title="Search">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <select className="input" value={sev} onChange={(e) => setSev(e.target.value as Severity | '')}>
            <option value="">— all severities —</option>
            {SEVS.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="input" value={status} onChange={(e) => setStatus(e.target.value as Status | '')}>
            <option value="">— all statuses —</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input className="input md:col-span-2" placeholder="search title / description" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
      </Panel>
      <Panel accent={`FINDINGS · ${items.length}`} title="List" dense>
        <DataTable<Finding>
          rows={items}
          columns={[
            { key: 'severity', header: 'Severity', render: (r) => <SevBadge severity={r.severity} /> },
            { key: 'title', header: 'Title', render: (r) => <button className="text-orange-primary hover:underline text-left" onClick={() => setSelected(r)}>{r.title}</button> },
            { key: 'affected_endpoint', header: 'Endpoint' },
            { key: 'scanner', header: 'Scanner' },
            { key: 'cve', header: 'CVE' },
            { key: 'status', header: 'Status' },
            { key: 'last_seen', header: 'Last Seen', render: (r) => r.last_seen.slice(0, 10) },
          ]}
        />
      </Panel>

      {selected && (
        <Panel accent="DETAIL" title={selected.title} right={<button className="btn-muted" onClick={() => setSelected(null)}>CLOSE</button>}>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <Section title="Summary"><SevBadge severity={selected.severity} />
              <div className="mt-2 text-text-primary whitespace-pre-line">{selected.description}</div></Section>
            <Section title="Affected Asset">{selected.affected_endpoint}{selected.port ? ':' + selected.port : ''} ({selected.protocol || '-'})</Section>
            <Section title="Business Impact">{selected.severity === 'critical' || selected.severity === 'high' ? 'Direct exposure to compromise' : 'Limited business impact'}</Section>
            <Section title="Technical Details">CVSS: {selected.cvss_score} · CVE: {selected.cve} · CWE: {selected.cwe} · Scanner: {selected.scanner}</Section>
            <Section title="Evidence">See Evidence Vault for raw output</Section>
            <Section title="Remediation">{selected.remediation || 'See vendor advisory'}</Section>
            <Section title="References">none</Section>
            <Section title="Status History">{selected.status} (last seen {selected.last_seen.slice(0, 10)})</Section>
            <Section title="Comments">none</Section>
            <Section title="Retest History">use button below</Section>
            <Section title="Audit Trail">recorded in audit_logs</Section>
          </div>
          <div className="mt-4 flex gap-2 flex-wrap">
            {STATUSES.map((s) => (
              <button key={s} className="btn-muted" disabled={s === selected.status}
                onClick={() => { transition(selected.id, s); setSelected({ ...selected, status: s }); }}>
                → {s}
              </button>
            ))}
            <button className="btn-primary" onClick={() => requestRetest(selected.id)}>REQUEST RETEST</button>
          </div>
        </Panel>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="panel-elevated p-3">
      <div className="label-accent mb-1">{title}</div>
      <div className="text-text-primary text-xs font-mono">{children}</div>
    </div>
  );
}
