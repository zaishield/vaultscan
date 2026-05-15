import { useState } from 'react';
import { api } from '../api/client';
import { Panel } from '../components/ui/Panel';
import { PageHeader, ErrorBanner } from './_helpers';

export function Retesting() {
  const [findingId, setFindingId] = useState('');
  const [retestId, setRetestId] = useState('');
  const [outcome, setOutcome] = useState<'passed' | 'failed'>('passed');
  const [summary, setSummary] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<string | null>(null);

  async function request() {
    try {
      const r = await api.post<{ id: string }>('/api/v1/retests', { finding_id: findingId, note: 'requested via UI' });
      setRetestId(r.id);
    } catch (e) { setError((e as Error).message); }
  }
  async function record() {
    try { await api.post(`/api/v1/retests/${retestId}/result`, { outcome, summary }); }
    catch (e) { setError((e as Error).message); }
  }
  async function load() {
    try {
      const r = await api.get(`/api/v1/retests/findings/${findingId}`);
      setHistory(JSON.stringify(r, null, 2));
    } catch (e) { setError((e as Error).message); }
  }
  return (
    <div className="space-y-4">
      <PageHeader accent="06 OUTPUT" title="Retesting Workflow" />
      <ErrorBanner error={error} />
      <Panel accent="REQUEST" title="Queue a Retest">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input className="input md:col-span-2" placeholder="Finding UUID" value={findingId} onChange={(e) => setFindingId(e.target.value)} />
          <button className="btn-primary" onClick={request} disabled={!findingId}>REQUEST RETEST</button>
        </div>
        {retestId && <div className="mt-2 text-xs font-mono text-orange-primary">retest id: {retestId}</div>}
      </Panel>
      <Panel accent="OUTCOME" title="Record Pass / Fail">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <input className="input md:col-span-2" placeholder="Retest UUID" value={retestId} onChange={(e) => setRetestId(e.target.value)} />
          <select className="input" value={outcome} onChange={(e) => setOutcome(e.target.value as 'passed' | 'failed')}>
            <option value="passed">passed</option>
            <option value="failed">failed</option>
          </select>
          <button className="btn-primary" onClick={record} disabled={!retestId}>RECORD</button>
        </div>
        <textarea className="input mt-3 min-h-[80px]" placeholder="Summary" value={summary} onChange={(e) => setSummary(e.target.value)} />
      </Panel>
      <Panel accent="HISTORY" title="Retest History for Finding">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input className="input md:col-span-2" placeholder="Finding UUID" value={findingId} onChange={(e) => setFindingId(e.target.value)} />
          <button className="btn-ghost" onClick={load} disabled={!findingId}>LOAD</button>
        </div>
        {history && (
          <pre className="mt-3 font-mono text-xs text-text-primary overflow-auto bg-bg-surface p-3 border border-border-subtle">
            {history}
          </pre>
        )}
      </Panel>
    </div>
  );
}
