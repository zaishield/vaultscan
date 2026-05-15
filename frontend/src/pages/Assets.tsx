import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';
import type { Asset } from '../types';

const ASSET_TYPES = ['domain','subdomain','ip','cidr','api','webapp','server','database',
                     'cloud_resource','container','k8s_cluster','mobile_app','repository','ssl_certificate'];

export function Assets() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const partnerId = useAuthStore((s) => s.partnerId);
  const [items, setItems] = useState<Asset[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [type, setType] = useState('domain');
  const [value, setValue] = useState('');
  const [crit, setCrit] = useState('medium');
  const [plane, setPlane] = useState<'external' | 'internal'>('external');
  const [filterType, setFilterType] = useState('');
  const [search, setSearch] = useState('');

  async function load() {
    if (!tenantId) return;
    const qs = new URLSearchParams({ tenant_id: tenantId });
    if (filterType) qs.set('asset_type', filterType);
    if (search)     qs.set('q', search);
    try {
      const r = await api.get<{ items: Asset[] }>(`/api/v1/assets?${qs}`);
      setItems(r.items ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, [tenantId, filterType, search]);

  async function create() {
    try {
      await api.post('/api/v1/assets', {
        tenant_id: tenantId, partner_id: partnerId,
        asset_type: type, value, name: value, criticality: crit, plane,
      });
      setValue(''); load();
    } catch (e) { setError((e as Error).message); }
  }

  async function importCSV(file: File) {
    try {
      const text = await file.text();
      const url = `/api/v1/assets/import-csv?tenant_id=${tenantId}&partner_id=${partnerId}`;
      const r = await fetch(url, {
        method: 'POST', body: text,
        headers: { 'Content-Type': 'text/csv',
                   'Authorization': `Bearer ${useAuthStore.getState().token}`,
                   ...(tenantId ? { 'X-Tenant-Id': tenantId } : {}) },
      });
      if (!r.ok) throw new Error(await r.text());
      load();
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="03 OPERATIONS" title="Asset Inventory" />
      <ErrorBanner error={error} />
      <Panel accent="ADD ASSET" title="Manual Entry / CSV">
        <div className="grid grid-cols-1 md:grid-cols-6 gap-3">
          <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
            {ASSET_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input className="input md:col-span-2" placeholder="value (FQDN, IP, ARN, etc.)" value={value} onChange={(e) => setValue(e.target.value)} />
          <select className="input" value={plane} onChange={(e) => setPlane(e.target.value as 'external' | 'internal')}>
            <option value="external">external</option>
            <option value="internal">internal</option>
          </select>
          <select className="input" value={crit} onChange={(e) => setCrit(e.target.value)}>
            {['critical','high','medium','low','unknown'].map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <button className="btn-primary" onClick={create} disabled={!value}>ADD</button>
        </div>
        <div className="mt-3 flex items-center gap-3">
          <label className="label">CSV import (asset_type,value,name,plane,criticality):</label>
          <input type="file" accept=".csv" className="text-text-muted"
                 onChange={(e) => e.target.files && importCSV(e.target.files[0])} />
        </div>
      </Panel>
      <Panel accent="FILTER" title="Search Assets">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <select className="input" value={filterType} onChange={(e) => setFilterType(e.target.value)}>
            <option value="">— all types —</option>
            {ASSET_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input className="input md:col-span-3" placeholder="search by value or name" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
      </Panel>
      <Panel accent={`INVENTORY · ${items.length} assets`} title="Asset List" dense>
        <DataTable<Asset>
          rows={items}
          columns={[
            { key: 'asset_type', header: 'Type' },
            { key: 'value', header: 'Value', render: (r) => <span className="text-orange-primary">{r.value}</span> },
            { key: 'plane', header: 'Plane' },
            { key: 'criticality', header: 'Criticality',
              render: (r) => <span className={`sev sev-${r.criticality === 'unknown' ? 'info' : r.criticality}`}>{r.criticality}</span> },
            { key: 'environment', header: 'Env' },
            { key: 'last_seen', header: 'Last Seen', render: (r) => r.last_seen.slice(0, 10) },
          ]}
        />
      </Panel>
    </div>
  );
}
