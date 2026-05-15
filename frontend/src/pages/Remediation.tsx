import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { SevBadge } from '../components/ui/Sev';
import { PageHeader, ErrorBanner } from './_helpers';
import type { Finding } from '../types';

export function Remediation() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const [items, setItems] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    if (!tenantId) return;
    try {
      const r = await api.get<{ items: Finding[] }>(
        `/api/v1/findings?tenant_id=${tenantId}&status=open,assigned,in_progress,retest_failed&severity=critical,high`);
      setItems(r.items ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, [tenantId]);

  async function markRemediated(id: string) {
    try { await api.patch(`/api/v1/findings/${id}`, { status: 'remediated' }); load(); }
    catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="06 OUTPUT" title="Remediation Queue" />
      <ErrorBanner error={error} />
      <Panel accent="OPEN HIGH+CRITICAL" title="Outstanding Work" dense>
        <DataTable<Finding>
          rows={items}
          columns={[
            { key: 'severity', header: 'Sev', render: (r) => <SevBadge severity={r.severity} /> },
            { key: 'title', header: 'Title', render: (r) => <span className="text-orange-primary">{r.title}</span> },
            { key: 'affected_endpoint', header: 'Endpoint' },
            { key: 'cve', header: 'CVE' },
            { key: 'status', header: 'Status' },
            { key: 'last_seen', header: 'Last Seen', render: (r) => r.last_seen.slice(0, 10) },
            { key: '__act', header: 'Action',
              render: (r) => <button className="btn-muted" onClick={() => markRemediated(r.id)}>MARK REMEDIATED</button> },
          ]}
        />
      </Panel>
    </div>
  );
}
