import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';
import type { ScanJob } from '../types';

export function ScanJobs() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const [items, setItems] = useState<ScanJob[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    if (!tenantId) return;
    try {
      const r = await api.get<{ items: ScanJob[] }>(`/api/v1/scans?tenant_id=${tenantId}`);
      setItems(r.items ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, [tenantId]);

  async function approve(id: string) { try { await api.post(`/api/v1/scans/${id}/approve`); load(); } catch (e) { setError((e as Error).message); } }
  async function emergencyStop(id: string) { try { await api.post('/api/v1/scans/emergency-stop', { job_id: id }); load(); } catch (e) { setError((e as Error).message); } }

  return (
    <div className="space-y-4">
      <PageHeader accent="04 SCANNING" title="Scan Jobs" />
      <ErrorBanner error={error} />
      <Panel accent={`JOBS · ${items.length}`} title="Live Status (auto-refresh 15s)" dense>
        <DataTable<ScanJob>
          rows={items}
          columns={[
            { key: 'profile_code', header: 'Profile', render: (r) => <span className="text-orange-primary">{r.profile_code}</span> },
            { key: 'plane', header: 'Plane' },
            { key: 'region', header: 'Region/Agent', render: (r) => r.region || (r.agent_id ? r.agent_id.slice(0, 8) : '—') },
            { key: 'target_summary', header: 'Targets' },
            { key: 'status', header: 'Status', render: (r) => statusPill(r.status) },
            { key: 'requires_approval', header: 'Approval', render: (r) => r.requires_approval ? 'required' : 'auto' },
            { key: 'created_at', header: 'Created', render: (r) => new Date(r.created_at).toLocaleString() },
            { key: '__act', header: 'Actions', render: (r) => (
              <div className="flex gap-2">
                {r.status === 'pending' && <button className="btn-muted" onClick={() => approve(r.id)}>APPROVE</button>}
                {!['stopped','succeeded','failed','cancelled'].includes(r.status) && <button className="btn-muted" onClick={() => emergencyStop(r.id)}>STOP</button>}
              </div>
            )},
          ]}
        />
      </Panel>
    </div>
  );
}

function statusPill(s: string) {
  const color = s === 'succeeded' ? '#00FF88' : s === 'failed' ? '#FF2D2D'
              : s === 'running' ? '#FF6B00' : s === 'stopped' ? '#FF2D2D' : '#8A8A8A';
  return <span style={{ color }} className="font-mono uppercase">{s}</span>;
}
