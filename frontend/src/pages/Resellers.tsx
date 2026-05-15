import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';
import type { Partner } from '../types';

export function Resellers() {
  const [items, setItems] = useState<Partner[]>([]);
  const [distributors, setDistributors] = useState<Partner[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [parentId, setParentId] = useState('');

  async function load() {
    try {
      const r = await api.get<{ items: Partner[] }>('/api/v1/partners');
      const all = r.items ?? [];
      setItems(all.filter((p) => p.type === 'reseller' || p.type === 'mssp' || p.type === 'white_label'));
      setDistributors(all.filter((p) => p.type === 'distributor'));
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, []);

  async function create(type: string) {
    try {
      await api.post('/api/v1/partners', { type, name, slug, parent_id: parentId });
      setName(''); setSlug(''); load();
    } catch (e) { setError((e as Error).message); }
  }
  return (
    <div className="space-y-4">
      <PageHeader accent="02 ESTATE" title="Resellers / MSSPs / White-Label" />
      <ErrorBanner error={error} />
      <Panel accent="NEW PARTNER" title="Onboard">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <input className="input" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <input className="input" placeholder="Slug" value={slug} onChange={(e) => setSlug(e.target.value)} />
          <select className="input" value={parentId} onChange={(e) => setParentId(e.target.value)}>
            <option value="">— no distributor —</option>
            {distributors.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
          <div className="flex gap-2">
            <button className="btn-primary flex-1" onClick={() => create('reseller')}>RESELLER</button>
            <button className="btn-ghost flex-1"   onClick={() => create('mssp')}>MSSP</button>
            <button className="btn-muted flex-1"   onClick={() => create('white_label')}>WHITE-LABEL</button>
          </div>
        </div>
      </Panel>
      <Panel accent="NETWORK" title="All Resellers / MSSPs" dense>
        <DataTable<Partner>
          rows={items}
          columns={[
            { key: 'type', header: 'Type', render: (r) => <span className="text-orange-primary uppercase">{r.type}</span> },
            { key: 'slug', header: 'Slug' },
            { key: 'name', header: 'Name' },
            { key: 'parent_id', header: 'Distributor', render: (r) => r.parent_id ? r.parent_id.slice(0, 8) : '—' },
            { key: 'status', header: 'Status' },
          ]}
        />
      </Panel>
    </div>
  );
}
