import { useEffect, useState } from 'react';
import { auditOps, AuditTimelineEvent, RetentionPolicy, ChainVerifyDeep } from '../api/ops';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { StatCard } from '../components/ui/StatCard';
import { PageHeader, ErrorBanner } from './_helpers';

export function AuditForensics() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const [deep, setDeep] = useState<ChainVerifyDeep | null>(null);
  const [events, setEvents] = useState<AuditTimelineEvent[]>([]);
  const [policies, setPolicies] = useState<RetentionPolicy[]>([]);
  const [since, setSince] = useState(new Date(Date.now() - 24 * 3600 * 1000).toISOString().slice(0, 16));
  const [until, setUntil] = useState(new Date().toISOString().slice(0, 16));
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    auditOps.retentionPolicies()
      .then(r => setPolicies(r.policies ?? []))
      .catch(e => setError((e as Error).message));
  }, []);

  async function runDeep() {
    try { setDeep(await auditOps.verifyDeep()); } catch (e) { setError((e as Error).message); }
  }

  async function loadTimeline() {
    if (!tenantId) return;
    try {
      const r = await auditOps.timeline(tenantId,
        new Date(since).toISOString(), new Date(until).toISOString());
      setEvents(r.events ?? []);
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="07 SYSTEM" title="Audit Forensics & Retention" />
      <ErrorBanner error={error} />

      <Panel accent="CHAIN VERIFY (DEEP)" title="Hash-chain integrity with full report">
        <div className="flex gap-3 items-center mb-3">
          <button className="btn-primary" onClick={runDeep}>VERIFY DEEP</button>
        </div>
        {deep && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard label="Rows" value={deep.total_rows} />
            <StatCard label="Last Good" value={deep.last_good_id || '—'} />
            <StatCard label="First Bad"
                      value={deep.first_bad_id || 'NONE'}
                      tone={deep.first_bad_id > 0 ? 'critical' : 'low'} />
            <StatCard label="Verified At"
                      value={new Date(deep.detected_at).toLocaleTimeString()} />
            {deep.detail && (
              <div className="md:col-span-4 text-xs font-mono text-status-critical">
                {deep.detail}
              </div>
            )}
          </div>
        )}
      </Panel>

      <Panel accent="TIMELINE" title="Per-Tenant Event Stream">
        <div className="flex gap-2 mb-3">
          <input className="input" type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
          <input className="input" type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} />
          <button className="btn-primary" onClick={loadTimeline}>LOAD</button>
        </div>
        <DataTable<AuditTimelineEvent>
          rows={events}
          columns={[
            { key: 'time', header: 'When', render: r => new Date(r.time).toLocaleString() },
            { key: 'event', header: 'Event',
              render: r => <span className="text-orange-primary">{r.event}</span> },
            { key: 'actor_type', header: 'Actor' },
            { key: 'target_type', header: 'Target', render: r => r.target_type ?? '—' },
            { key: 'target_id', header: 'ID', render: r => r.target_id?.slice(0, 12) ?? '—' },
          ]}
        />
      </Panel>

      <Panel accent="RETENTION POLICIES" title="Per-Event-Prefix Retention" dense>
        <DataTable<RetentionPolicy>
          rows={policies}
          columns={[
            { key: 'event_prefix', header: 'Prefix',
              render: r => <span className="font-mono text-orange-primary">{r.event_prefix}</span> },
            { key: 'retention_days', header: 'Days',
              render: r => `${r.retention_days} (${(r.retention_days / 365).toFixed(1)}y)` },
            { key: 'archive_target', header: 'Archive Target',
              render: r => <span className="font-mono text-xs">{r.archive_target ?? '—'}</span> },
          ]}
        />
      </Panel>
    </div>
  );
}
