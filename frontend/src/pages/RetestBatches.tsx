import { useState } from 'react';
import { retestOps, RetestBatch, RetestDiff } from '../api/ops';
import { Panel } from '../components/ui/Panel';
import { StatCard } from '../components/ui/StatCard';
import { PageHeader, ErrorBanner } from './_helpers';
import { useAuthStore } from '../store/auth';

export function RetestBatches() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const [reason, setReason] = useState('Quarterly retest');
  const [idText, setIDText] = useState('');
  const [batch, setBatch] = useState<RetestBatch | null>(null);
  const [retestID, setRetestID] = useState('');
  const [diff, setDiff] = useState<RetestDiff | null>(null);
  const [auto, setAuto] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!tenantId) return;
    const ids = idText.split(/\s|,/).map(s => s.trim()).filter(Boolean);
    if (ids.length === 0) { setError('paste at least one finding ID'); return; }
    try {
      const r = await retestOps.createBatch(tenantId, reason, ids);
      const b = await retestOps.getBatch(r.batch_id);
      setBatch(b);
    } catch (err) { setError((err as Error).message); }
  }

  async function loadDiff() {
    if (!retestID) return;
    try {
      const d = await retestOps.getDiff(retestID);
      setDiff(d);
    } catch (err) { setError((err as Error).message); }
  }

  async function toggleAuto() {
    if (!tenantId) return;
    try {
      const r = await retestOps.setAutoRetest(tenantId, !auto);
      setAuto(r.enabled);
    } catch (err) { setError((err as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="06 OUTPUT" title="Retest Batches · Auto-Retest · Diffs" right={
        <button className="btn-muted" onClick={toggleAuto}>
          AUTO-RETEST: {auto ? 'ON' : 'OFF'}
        </button>
      } />
      <ErrorBanner error={error} />

      <Panel accent="CREATE BATCH" title="Bulk-retest selected findings">
        <form onSubmit={create} className="space-y-2">
          <input className="input w-full" placeholder="batch reason"
                 value={reason} onChange={(e) => setReason(e.target.value)} />
          <textarea className="input w-full h-32 font-mono text-xs"
                    placeholder="paste finding UUIDs, one per line"
                    value={idText} onChange={(e) => setIDText(e.target.value)} />
          <button className="btn-primary" type="submit">QUEUE BATCH</button>
        </form>
      </Panel>

      {batch && (
        <Panel accent={`BATCH · ${batch.status.toUpperCase()}`} title={batch.reason}>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard label="Total" value={batch.total_items} />
            <StatCard label="Completed" value={batch.completed_items} tone="low" />
            <StatCard label="Failed" value={batch.failed_items}
                      tone={batch.failed_items > 0 ? 'critical' : undefined} />
            <StatCard label="Status" value={batch.status} />
          </div>
        </Panel>
      )}

      <Panel accent="DIFF" title="Original vs Post-Retest State">
        <div className="flex gap-2">
          <input className="input flex-1" placeholder="retest UUID"
                 value={retestID} onChange={(e) => setRetestID(e.target.value)} />
          <button className="btn-primary" onClick={loadDiff}>LOAD DIFF</button>
        </div>
        {diff && (
          <div className="mt-3 text-xs font-mono space-y-1">
            <div>Verdict: <span className={
              diff.verdict === 'resolved' ? 'text-status-low' :
              diff.verdict === 'regressed' ? 'text-status-critical' : 'text-text-primary'
            }>{diff.verdict.toUpperCase()}</span></div>
            {diff.severity_from && <div>Severity: {diff.severity_from} → {diff.severity_to}</div>}
            <pre className="text-[10px] mt-2 p-2 border border-border-subtle bg-bg-deep overflow-x-auto">
              {JSON.stringify(diff, null, 2)}
            </pre>
          </div>
        )}
      </Panel>
    </div>
  );
}
