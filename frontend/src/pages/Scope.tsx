import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';
import type { Engagement, ScopeTarget } from '../types';

export function Scope() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [engId, setEngId] = useState('');
  const [scope, setScope] = useState<ScopeTarget[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [type, setType] = useState('domain');
  const [value, setValue] = useState('');
  const [plane, setPlane] = useState<'external' | 'internal'>('external');

  useEffect(() => {
    if (!tenantId) return;
    api.get<{ items: Engagement[] }>(`/api/v1/engagements?tenant_id=${tenantId}`)
       .then((r) => setEngagements(r.items ?? [])).catch((e) => setError((e as Error).message));
  }, [tenantId]);

  async function loadScope(id: string) {
    setEngId(id);
    if (!id) return setScope([]);
    try {
      const r = await api.get<{ items: ScopeTarget[] }>(`/api/v1/scope/${id}`);
      setScope(r.items ?? []);
    } catch (e) { setError((e as Error).message); }
  }

  async function add() {
    try {
      await api.post('/api/v1/scope', { engagement_id: engId, target_type: type, target_value: value, plane });
      setValue(''); loadScope(engId);
    } catch (e) { setError((e as Error).message); }
  }
  async function approve(id: string) {
    try { await api.post(`/api/v1/scope/${id}/approve`); loadScope(engId); }
    catch (e) { setError((e as Error).message); }
  }
  async function uploadAuth(file: File) {
    try {
      const text = await file.text();
      const r = await fetch(`/api/v1/authorization/${engId}?title=${encodeURIComponent(file.name)}&type=letter`, {
        method: 'POST',
        headers: { 'Content-Type': file.type || 'application/octet-stream',
                   'Authorization': `Bearer ${useAuthStore.getState().token}`,
                   ...(tenantId ? { 'X-Tenant-Id': tenantId } : {}) },
        body: text,
      });
      if (!r.ok) throw new Error(`upload failed: ${r.status}`);
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="03 OPERATIONS" title="Scope & Authorization" />
      <ErrorBanner error={error} />
      <Panel accent="ENGAGEMENT" title="Select Engagement">
        <select className="input" value={engId} onChange={(e) => loadScope(e.target.value)}>
          <option value="">— select —</option>
          {engagements.map((e) => <option key={e.id} value={e.id}>{e.code} · {e.name}</option>)}
        </select>
      </Panel>
      {engId && (
        <>
          <Panel accent="AUTHORIZATION" title="Upload Signed Letter / RoE">
            <input type="file" className="text-text-muted file:btn-muted file:mr-2"
                   onChange={(e) => e.target.files && uploadAuth(e.target.files[0])} />
          </Panel>
          <Panel accent="ADD SCOPE" title="Add Target">
            <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
              <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
                {['domain','subdomain','ip','cidr','url','api'].map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
              <input className="input md:col-span-2" placeholder="value" value={value} onChange={(e) => setValue(e.target.value)} />
              <select className="input" value={plane} onChange={(e) => setPlane(e.target.value as 'external' | 'internal')}>
                <option value="external">external</option>
                <option value="internal">internal</option>
              </select>
              <button className="btn-primary" onClick={add} disabled={!value}>ADD</button>
            </div>
          </Panel>
          <Panel accent="SCOPE" title="Approved & Pending Targets" dense>
            <DataTable<ScopeTarget>
              rows={scope}
              columns={[
                { key: 'target_type', header: 'Type' },
                { key: 'target_value', header: 'Target', render: (r) => <span className="text-orange-primary">{r.target_value}</span> },
                { key: 'plane', header: 'Plane' },
                { key: 'status', header: 'Status', render: (r) => <span className={r.status === 'approved' ? 'text-status-low' : 'text-status-medium'}>{r.status}</span> },
                { key: '__actions', header: 'Actions',
                  render: (r) => r.status === 'pending'
                    ? <button className="btn-muted" onClick={() => approve(r.id)}>APPROVE</button>
                    : <span className="text-text-muted">—</span> },
              ]}
            />
          </Panel>
        </>
      )}
    </div>
  );
}
