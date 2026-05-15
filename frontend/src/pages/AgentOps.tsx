import { useEffect, useState } from 'react';
import { agentOps, AgentTelemetryBucket, EmergencyStopSLA } from '../api/ops';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { StatCard } from '../components/ui/StatCard';
import { PageHeader, ErrorBanner } from './_helpers';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';

interface AgentRow { id: string; name: string; status: string; }

export function AgentOps() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const [agents, setAgents] = useState<AgentRow[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [telemetry, setTelemetry] = useState<AgentTelemetryBucket[]>([]);
  const [sla, setSLA] = useState<EmergencyStopSLA | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!tenantId) return;
    api.get<{ items: AgentRow[] }>(`/api/v1/agents?tenant_id=${tenantId}`)
      .then(r => setAgents(r.items ?? []))
      .catch(e => setError((e as Error).message));
  }, [tenantId]);

  useEffect(() => {
    if (!selected) { setTelemetry([]); setSLA(null); return; }
    const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
    agentOps.listTelemetry(selected, since)
      .then(r => setTelemetry(r.buckets ?? []))
      .catch(e => setError((e as Error).message));
    agentOps.emergencyStopSLA(selected, new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString())
      .then(setSLA)
      .catch(() => {});
  }, [selected]);

  async function rollup() {
    if (!selected) return;
    try {
      const r = await agentOps.rollupTelemetry(selected);
      alert(`Wrote ${r.buckets_written} buckets`);
    } catch (e) { setError((e as Error).message); }
  }

  async function emergencyStop() {
    if (!selected) return;
    const reason = prompt('Emergency stop reason?');
    if (!reason) return;
    try {
      await agentOps.requestEmergencyStop(selected, reason, 'agent');
      alert('Emergency stop dispatched');
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="04 SCANNING" title="Internal Agent Operations" />
      <ErrorBanner error={error} />

      <Panel accent="AGENTS" title="Select an Agent" dense>
        <select className="input" value={selected ?? ''}
                onChange={(e) => setSelected(e.target.value || null)}>
          <option value="">— select —</option>
          {agents.map(a => (
            <option key={a.id} value={a.id}>{a.name} · {a.status}</option>
          ))}
        </select>
      </Panel>

      {selected && (
        <>
          <Panel accent="EMERGENCY STOP SLA" title="Last 30 Days">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <StatCard label="Samples" value={sla?.count ?? '—'} />
              <StatCard label="Avg (ms)" value={sla?.avg_ms?.toFixed(0) ?? '—'} />
              <StatCard label="P95 (ms)" value={sla?.p95_ms ?? '—'} />
              <StatCard label="Breaches (>30s)" value={sla?.breach_count ?? '—'}
                        tone={sla && sla.breach_count > 0 ? 'critical' : undefined} />
            </div>
            <div className="mt-3 flex gap-2">
              <button className="btn-muted" onClick={rollup}>ROLLUP TELEMETRY</button>
              <button className="btn-primary" onClick={emergencyStop}>EMERGENCY STOP</button>
            </div>
          </Panel>

          <Panel accent={`TELEMETRY · ${telemetry.length} BUCKETS`} title="5-Minute Rollups" dense>
            <DataTable<AgentTelemetryBucket>
              rows={telemetry}
              columns={[
                { key: 'bucket_start', header: 'When', render: r => new Date(r.bucket_start).toLocaleTimeString() },
                { key: 'samples', header: 'N' },
                { key: 'cpu_avg', header: 'CPU avg %', render: r => r.cpu_avg.toFixed(1) },
                { key: 'cpu_peak', header: 'CPU peak %', render: r => r.cpu_peak.toFixed(1) },
                { key: 'memory_avg', header: 'Mem avg %', render: r => r.memory_avg.toFixed(1) },
                { key: 'memory_peak', header: 'Mem peak %', render: r => r.memory_peak.toFixed(1) },
                { key: 'queue_peak', header: 'Queue peak' },
              ]}
            />
          </Panel>
        </>
      )}
    </div>
  );
}
