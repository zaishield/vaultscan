import { useState } from 'react';
import { evidenceOps, CustodyEvent } from '../api/ops';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';

export function ChainOfCustody() {
  const [evidenceID, setEvidenceID] = useState('');
  const [events, setEvents] = useState<CustodyEvent[]>([]);
  const [integrity, setIntegrity] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load(e: React.FormEvent) {
    e.preventDefault();
    setError(null); setEvents([]); setIntegrity(null);
    if (!evidenceID) return;
    try {
      const r = await evidenceOps.chainOfCustody(evidenceID);
      setEvents(r.events ?? []);
    } catch (err) { setError((err as Error).message); }
  }

  async function verify() {
    if (!evidenceID) return;
    try {
      const r = await evidenceOps.verifyIntegrity(evidenceID);
      setIntegrity(r.integrity_ok);
      await load(new Event('submit') as unknown as React.FormEvent);
    } catch (err) { setError((err as Error).message); }
  }

  async function enableWORM() {
    if (!evidenceID) return;
    if (!confirm('Enable WORM lock for 7 years? This cannot be undone.')) return;
    try {
      await evidenceOps.enableWORM(evidenceID);
      alert('WORM enabled');
      await load(new Event('submit') as unknown as React.FormEvent);
    } catch (err) { setError((err as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="05 FINDINGS" title="Evidence Chain-of-Custody" right={
        evidenceID && (
          <a className="btn-muted" download={`custody-${evidenceID.slice(0, 8)}.md`}
             href={evidenceOps.chainOfCustodyMarkdownURL(evidenceID)}>EXPORT MD</a>
        )
      } />
      <ErrorBanner error={error} />

      <Panel accent="LOOKUP" title="Evidence ID">
        <form onSubmit={load} className="flex gap-2">
          <input className="input flex-1" placeholder="evidence UUID"
                 value={evidenceID} onChange={(e) => setEvidenceID(e.target.value)} />
          <button className="btn-primary" type="submit">LOAD</button>
          <button className="btn-muted" type="button" onClick={verify}>VERIFY INTEGRITY</button>
          <button className="btn-muted" type="button" onClick={enableWORM}>ENABLE WORM</button>
        </form>
        {integrity !== null && (
          <div className="mt-2 text-xs font-mono">
            Integrity: <span className={integrity ? 'text-status-low' : 'text-status-critical'}>
              {integrity ? 'OK — sha256 matches' : 'FAIL — sha256 mismatch'}
            </span>
          </div>
        )}
      </Panel>

      <Panel accent={`TIMELINE · ${events.length} EVENTS`} title="Custody Events" dense>
        <DataTable<CustodyEvent>
          rows={events}
          columns={[
            { key: 'occurred_at', header: 'When', render: r => new Date(r.occurred_at).toLocaleString() },
            { key: 'event', header: 'Event', render: r => <span className="text-orange-primary">{r.event}</span> },
            { key: 'actor_type', header: 'Actor' },
            { key: 'ip', header: 'IP', render: r => r.ip ?? '—' },
            { key: 'details', header: 'Detail',
              render: r => r.details ? <code className="text-[10px]">{JSON.stringify(r.details)}</code> : '—' },
          ]}
        />
      </Panel>
    </div>
  );
}
