import { useEffect, useState } from 'react';
import { scannerOps, dashboardOps, GeoNode, RegionQuota } from '../api/ops';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';

const REGIONS = ['ae', 'eu', 'in', 'us', 'sg', 'sa', 'uk'];

export function ScannerFarm() {
  const [nodes, setNodes] = useState<GeoNode[]>([]);
  const [quotas, setQuotas] = useState<Record<string, RegionQuota>>({});
  const [yaml, setYaml] = useState<{ region: string; body: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      const g = await dashboardOps.geoNodes();
      setNodes(g.nodes ?? []);
      const map: Record<string, RegionQuota> = {};
      for (const r of REGIONS) {
        try {
          map[r] = await scannerOps.getRegionQuota(r);
        } catch { /* region might not have a quota row yet */ }
      }
      setQuotas(map);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, []);

  async function updateQuota(region: string, max: number, reserved: number) {
    try {
      await scannerOps.setRegionQuota(region, max, reserved);
      await load();
    } catch (e) { setError((e as Error).message); }
  }

  async function showYAML(region: string) {
    try {
      const body = await scannerOps.networkPolicyYAML(region);
      setYaml({ region, body: body as string });
    } catch (e) { setError((e as Error).message); }
  }

  async function sweep() {
    try {
      const r = await scannerOps.sweepStalled();
      alert(`Marked ${r.count} stalled nodes degraded`);
      await load();
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="04 SCANNING" title="External Scanner Farm" right={
        <button className="btn-muted" onClick={sweep}>SWEEP STALLED</button>
      } />
      <ErrorBanner error={error} />

      <Panel accent="GEO" title="Regional Nodes" dense>
        <DataTable<GeoNode>
          rows={nodes}
          columns={[
            { key: 'region', header: 'Region', render: r => <span className="text-orange-primary uppercase">{r.region}</span> },
            { key: 'city', header: 'City' },
            { key: 'country', header: 'Country' },
            { key: 'hostname', header: 'Hostname' },
            { key: 'status', header: 'Status', render: r =>
              <span className={r.status === 'online' ? 'text-status-low' : 'text-status-critical'}>{r.status}</span> },
            { key: 'inflight', header: 'Inflight' },
          ]}
        />
      </Panel>

      <Panel accent="QUOTAS" title="Per-Region Concurrent Job Caps">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {REGIONS.map(r => {
            const q = quotas[r];
            return (
              <div key={r} className="border border-border-subtle p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-orange-primary uppercase font-mono">{r}</span>
                  <span className="text-xs font-mono text-text-muted">
                    {q ? `${q.inflight} / ${q.max} (reserve ${q.reserved_for_platform})` : 'no quota set'}
                  </span>
                </div>
                <form onSubmit={(e) => {
                  e.preventDefault();
                  const fd = new FormData(e.currentTarget);
                  updateQuota(r, Number(fd.get('max')), Number(fd.get('reserved')));
                }} className="flex gap-2 text-xs">
                  <input name="max" type="number" min={1} defaultValue={q?.max ?? 32}
                         className="input w-24" placeholder="max" />
                  <input name="reserved" type="number" min={0} defaultValue={q?.reserved_for_platform ?? 2}
                         className="input w-24" placeholder="reserved" />
                  <button type="submit" className="btn-primary">UPDATE</button>
                  <button type="button" className="btn-muted" onClick={() => showYAML(r)}>POLICY YAML</button>
                </form>
              </div>
            );
          })}
        </div>
      </Panel>

      {yaml && (
        <Panel accent={`NETWORK POLICY · ${yaml.region.toUpperCase()}`} title="Kubernetes NetworkPolicy">
          <pre className="text-[10px] font-mono p-3 bg-bg-deep border border-border-subtle overflow-x-auto">
            {yaml.body}
          </pre>
        </Panel>
      )}
    </div>
  );
}
