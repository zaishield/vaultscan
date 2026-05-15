import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';
import type { Agent } from '../types';

export function InternalAgents() {
  const tenantId  = useAuthStore((s) => s.tenantId);
  const partnerId = useAuthStore((s) => s.partnerId);
  const [items, setItems] = useState<Agent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [location, setLocation] = useState('');
  const [provisionResult, setProvisionResult] = useState<{ enrollment_token: string; agent: Agent } | null>(null);

  async function load() {
    if (!tenantId) return;
    try {
      const r = await api.get<{ items: Agent[] }>(`/api/v1/agents?tenant_id=${tenantId}`);
      setItems(r.items ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => {
    load();
    const t = setInterval(load, 30000);  // 30s heartbeat refresh per Blueprint §22.2
    return () => clearInterval(t);
  }, [tenantId]);

  async function provision() {
    try {
      const r = await api.post<{ enrollment_token: string; agent: Agent }>('/api/v1/agents', {
        tenant_id: tenantId, partner_id: partnerId,
        name, location, form_factor: 'linux_vm',
      });
      setProvisionResult(r);
      setName(''); setLocation('');
      load();
    } catch (e) { setError((e as Error).message); }
  }
  async function emergencyStop(agentId: string) {
    try { await api.post('/api/v1/scans/emergency-stop', { agent_id: agentId }); load(); }
    catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="04 SCANNING" title="Internal Agent Fleet" />
      <ErrorBanner error={error} />
      <Panel accent="PROVISION" title="Enroll New Agent">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <input className="input md:col-span-2" placeholder="Agent name" value={name} onChange={(e) => setName(e.target.value)} />
          <input className="input" placeholder="Location" value={location} onChange={(e) => setLocation(e.target.value)} />
          <button className="btn-primary" onClick={provision} disabled={!name}>GENERATE TOKEN</button>
        </div>
        {provisionResult && (
          <div className="mt-3 panel-elevated p-3">
            <div className="label-accent mb-1">Enrollment token (shown once)</div>
            <pre className="font-mono text-xs text-orange-primary break-all">{provisionResult.enrollment_token}</pre>
            <div className="text-text-muted text-[10px] font-mono mt-2">
              Install command:&nbsp;
              <span className="text-text-primary">vaultscan-agent --gateway https://agent.vaultscan.zaishield.com --agent-id {provisionResult.agent.id} --enroll-token &lt;TOKEN&gt;</span>
            </div>
          </div>
        )}
      </Panel>
      <Panel accent="FLEET" title="Agents (12-column view per Blueprint §33.3)" dense>
        <DataTable<Agent>
          rows={items}
          columns={[
            { key: 'name', header: 'Agent', render: (r) => <span className="text-orange-primary">{r.name}</span> },
            { key: 'tenant_id', header: 'Client', render: (r) => r.tenant_id.slice(0, 8) },
            { key: 'location', header: 'Location' },
            { key: 'status', header: 'Status', render: (r) => <span className={r.status === 'online' ? 'text-status-low' : 'text-text-muted'}>{r.status}</span> },
            { key: 'last_heartbeat', header: 'Last HB', render: (r) => r.last_heartbeat ? new Date(r.last_heartbeat).toLocaleTimeString() : '—' },
            { key: 'version', header: 'Version' },
            { key: '__scope', header: 'Scope', render: () => 'see policy' },
            { key: '__current', header: 'Current Scan', render: () => '—' },
            { key: 'cpu_percent', header: 'CPU', render: (r) => `${(r.cpu_percent ?? 0).toFixed(0)}%` },
            { key: 'memory_percent', header: 'MEM', render: (r) => `${(r.memory_percent ?? 0).toFixed(0)}%` },
            { key: 'cert_status', header: 'Cert' },
            { key: '__estop', header: 'E-Stop',
              render: (r) => <button className="btn-muted" onClick={() => emergencyStop(r.id)}>STOP</button> },
          ]}
        />
      </Panel>
    </div>
  );
}
