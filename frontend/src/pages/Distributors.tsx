import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';
import type { Partner } from '../types';

export function Distributors() {
  const [items, setItems] = useState<Partner[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');

  async function load() {
    try {
      const r = await api.get<{ items: Partner[] }>('/api/v1/partners');
      setItems((r.items ?? []).filter((p) => p.type === 'distributor'));
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, []);

  async function create() {
    try {
      await api.post('/api/v1/partners', { type: 'distributor', name, slug });
      setName(''); setSlug(''); load();
    } catch (e) { setError((e as Error).message); }
  }
  return (
    <div className="space-y-4">
      <PageHeader accent="02 ESTATE" title="Distributors" />
      <ErrorBanner error={error} />
      <Panel accent="NEW DISTRIBUTOR" title="Onboard">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input className="input" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <input className="input" placeholder="Slug" value={slug} onChange={(e) => setSlug(e.target.value)} />
          <button className="btn-primary" onClick={create} disabled={!name || !slug}>CREATE DISTRIBUTOR</button>
        </div>
      </Panel>
      <Panel accent="NETWORK" title="All Distributors" dense>
        <DataTable<Partner>
          rows={items}
          columns={[
            { key: 'slug', header: 'Slug', render: (r) => <span className="text-orange-primary">{r.slug}</span> },
            { key: 'name', header: 'Name' },
            { key: 'status', header: 'Status' },
            { key: 'created_at', header: 'Created' },
          ]}
        />
      </Panel>
    </div>
  );
}
