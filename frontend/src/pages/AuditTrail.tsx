import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';

interface AuditRow {
  id: number; event: string; actor_type: string; actor_id?: string;
  target_type?: string; target_id?: string; tenant_id?: string;
  partner_id?: string; occurred_at: string; payload?: Record<string, unknown>;
}

export function AuditTrail() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const [items, setItems] = useState<AuditRow[]>([]);
  const [verify, setVerify] = useState<{ chain_valid: boolean; broken_at_id: number } | null>(null);
  const [eventFilter, setEventFilter] = useState('');
  const [error, setError] = useState<string | null>(null);

  async function load() {
    const qs = new URLSearchParams();
    if (tenantId) qs.set('tenant_id', tenantId);
    if (eventFilter) qs.set('event', eventFilter);
    try {
      const r = await api.get<{ items: AuditRow[] }>(`/api/v1/audit?${qs}`);
      setItems(r.items ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, [tenantId, eventFilter]);

  async function runVerify() {
    try { setVerify(await api.get('/api/v1/audit/verify')); } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="07 SYSTEM" title="Audit Trail (hash-chained, immutable)" />
      <ErrorBanner error={error} />
      <Panel accent="INTEGRITY" title="Hash-Chain Verification">
        <div className="flex gap-3 items-center">
          <button className="btn-primary" onClick={runVerify}>VERIFY CHAIN</button>
          {verify && (
            verify.chain_valid
              ? <span className="text-status-low font-mono text-xs">CHAIN INTACT</span>
              : <span className="text-status-critical font-mono text-xs">BROKEN AT id={verify.broken_at_id}</span>
          )}
        </div>
      </Panel>
      <Panel accent="FILTER" title="Search">
        <input className="input" placeholder="event name (e.g. scan.created)" value={eventFilter} onChange={(e) => setEventFilter(e.target.value)} />
      </Panel>
      <Panel accent={`EVENTS · ${items.length}`} title="Recent Events" dense>
        <DataTable<AuditRow>
          rows={items}
          columns={[
            { key: 'occurred_at', header: 'When', render: (r) => new Date(r.occurred_at).toLocaleString() },
            { key: 'event', header: 'Event', render: (r) => <span className="text-orange-primary">{r.event}</span> },
            { key: 'actor_type', header: 'Actor' },
            { key: 'target_type', header: 'Target Type' },
            { key: 'target_id', header: 'Target ID', render: (r) => r.target_id?.slice(0, 12) ?? '—' },
            { key: 'tenant_id', header: 'Tenant', render: (r) => r.tenant_id?.slice(0, 8) ?? '—' },
          ]}
        />
      </Panel>
    </div>
  );
}
