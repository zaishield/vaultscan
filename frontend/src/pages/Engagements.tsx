import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';
import type { Engagement } from '../types';

export function Engagements() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const partnerId = useAuthStore((s) => s.partnerId);
  const [items, setItems] = useState<Engagement[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [name, setName] = useState('');
  const [start, setStart] = useState(new Date().toISOString().slice(0, 10));
  const [end, setEnd] = useState(new Date(Date.now() + 30 * 86400_000).toISOString().slice(0, 10));
  const [intensity, setIntensity] = useState('standard');

  async function load() {
    if (!tenantId) return;
    try {
      const r = await api.get<{ items: Engagement[] }>(`/api/v1/engagements?tenant_id=${tenantId}`);
      setItems(r.items ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, [tenantId]);

  async function create() {
    if (!tenantId || !partnerId) { setError('tenant_id + partner_id required in session'); return; }
    try {
      await api.post('/api/v1/engagements', {
        tenant_id: tenantId, partner_id: partnerId,
        code, name, intensity,
        starts_at: new Date(start).toISOString(),
        ends_at: new Date(end).toISOString(),
      });
      setCode(''); setName(''); load();
    } catch (e) { setError((e as Error).message); }
  }
  async function activate(id: string) {
    try { await api.post(`/api/v1/engagements/${id}/activate`); load(); }
    catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="03 OPERATIONS" title="Engagements" />
      <ErrorBanner error={error} />
      <Panel accent="NEW ENGAGEMENT" title="Create">
        <div className="grid grid-cols-1 md:grid-cols-6 gap-3">
          <input className="input" placeholder="Code (e.g. ENG-2026-0001)" value={code} onChange={(e) => setCode(e.target.value)} />
          <input className="input md:col-span-2" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <input className="input" type="date" value={start} onChange={(e) => setStart(e.target.value)} />
          <input className="input" type="date" value={end} onChange={(e) => setEnd(e.target.value)} />
          <select className="input" value={intensity} onChange={(e) => setIntensity(e.target.value)}>
            <option value="light">Light</option>
            <option value="standard">Standard</option>
            <option value="aggressive">Aggressive</option>
          </select>
        </div>
        <div className="mt-3"><button className="btn-primary" onClick={create} disabled={!code || !name}>CREATE</button></div>
      </Panel>
      <Panel accent="ROSTER" title="All Engagements" dense>
        <DataTable<Engagement>
          rows={items}
          columns={[
            { key: 'code', header: 'Code', render: (r) => <span className="text-orange-primary">{r.code}</span> },
            { key: 'name', header: 'Name' },
            { key: 'status', header: 'Status', render: (r) => <span className={r.status === 'active' ? 'text-status-low' : 'text-text-muted'}>{r.status}</span> },
            { key: 'intensity', header: 'Intensity' },
            { key: 'starts_at', header: 'Starts', render: (r) => r.starts_at.slice(0, 10) },
            { key: 'ends_at',   header: 'Ends',   render: (r) => r.ends_at.slice(0, 10) },
            { key: '__actions', header: 'Actions',
              render: (r) => r.status === 'draft'
                ? <button className="btn-muted" onClick={() => activate(r.id)}>ACTIVATE</button>
                : <span className="text-text-muted">—</span> },
          ]}
        />
      </Panel>
    </div>
  );
}
