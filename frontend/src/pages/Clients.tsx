import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';
import type { Tenant } from '../types';

export function Clients() {
  const partnerId = useAuthStore((s) => s.partnerId);
  const [items, setItems] = useState<Tenant[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');

  async function load() {
    try {
      const r = await api.get<{ items: Tenant[] }>(`/api/v1/tenants${partnerId ? `?partner_id=${partnerId}` : ''}`);
      setItems(r.items ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, [partnerId]);

  async function create() {
    setError(null);
    try {
      await api.post('/api/v1/tenants', { partner_id: partnerId, name, slug, isolation_mode: 'shared' });
      setName(''); setSlug(''); load();
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="02 ESTATE" title="Customer Tenants" />
      <ErrorBanner error={error} />
      <Panel accent="NEW TENANT" title="Provision Customer">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input className="input" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <input className="input" placeholder="Slug" value={slug} onChange={(e) => setSlug(e.target.value)} />
          <button className="btn-primary" onClick={create} disabled={!name || !slug}>CREATE TENANT</button>
        </div>
      </Panel>
      <Panel accent="ROSTER" title="All Tenants" dense>
        <DataTable<Tenant>
          rows={items}
          columns={[
            { key: 'slug', header: 'Slug', render: (r) => <span className="text-orange-primary">{r.slug}</span> },
            { key: 'name', header: 'Name' },
            { key: 'isolation_mode', header: 'Isolation' },
            { key: 'status', header: 'Status' },
            { key: 'created_at', header: 'Created' },
          ]}
        />
      </Panel>
    </div>
  );
}
