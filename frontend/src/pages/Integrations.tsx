import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';

const TYPES = ['jira', 'servicenow', 'slack', 'teams', 'webhook', 'siem',
               'gitlab', 'github', 'jenkins', 'sentinel'];

interface Integration {
  id: string; type: string; name: string; enabled: boolean;
  config: Record<string, unknown>; event_filter: string[]; last_status: string;
}

export function Integrations() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const partnerId = useAuthStore((s) => s.partnerId);
  const [items, setItems] = useState<Integration[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [type, setType] = useState('slack');
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [filter, setFilter] = useState('');

  async function load() {
    try {
      const qs = new URLSearchParams();
      if (tenantId) qs.set('tenant_id', tenantId);
      if (partnerId) qs.set('partner_id', partnerId);
      const r = await api.get<{ items: Integration[] }>(`/api/v1/integrations?${qs}`);
      setItems(r.items ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, [tenantId, partnerId]);

  async function create() {
    try {
      await api.post(`/api/v1/integrations/${type}`, {
        tenant_id: tenantId, partner_id: partnerId, name,
        config: { url }, event_filter: filter.split(',').map((s) => s.trim()).filter(Boolean),
      });
      setName(''); setUrl(''); setFilter(''); load();
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="07 SYSTEM" title="Integrations" />
      <ErrorBanner error={error} />
      <Panel accent="NEW" title="Wire an Integration">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
            {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input className="input" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <input className="input md:col-span-2" placeholder="Webhook / endpoint URL" value={url} onChange={(e) => setUrl(e.target.value)} />
          <input className="input" placeholder="Event filter (comma sep, blank=all)" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </div>
        <div className="mt-3"><button className="btn-primary" onClick={create} disabled={!name || !url}>WIRE INTEGRATION</button></div>
      </Panel>
      <Panel accent="WIRED" title="Active Integrations" dense>
        <DataTable<Integration>
          rows={items}
          columns={[
            { key: 'type', header: 'Type', render: (r) => <span className="text-orange-primary">{r.type}</span> },
            { key: 'name', header: 'Name' },
            { key: 'enabled', header: 'Enabled', render: (r) => r.enabled ? '✓' : '✕' },
            { key: 'event_filter', header: 'Events', render: (r) => (r.event_filter ?? []).join(', ') || 'all' },
            { key: 'last_status', header: 'Last Status' },
          ]}
        />
      </Panel>
    </div>
  );
}
