import { useEffect, useState } from 'react';
import { integrationOps, DeadLetter } from '../api/ops';
import { api } from '../api/client';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';

interface Integration { id: string; name: string; type: string; }

export function DeadLetterQueue() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [selected, setSelected] = useState<string>('');
  const [letters, setLetters] = useState<DeadLetter[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.get<{ items: Integration[] }>(`/api/v1/integrations`)
      .then(r => setIntegrations(r.items ?? []))
      .catch(e => setError((e as Error).message));
  }, []);

  async function load() {
    if (!selected) return;
    try {
      const r = await integrationOps.listDeadLetters(selected);
      setLetters(r.dead_letters ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, [selected]);

  async function replay(dlqID: string) {
    try {
      await integrationOps.replay(dlqID);
      await load();
    } catch (e) { setError((e as Error).message); }
  }

  async function drop(dlqID: string) {
    if (!confirm('Drop this dead-letter without retrying?')) return;
    try {
      await integrationOps.resolve(dlqID, 'dropped');
      await load();
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="07 SYSTEM" title="Integration Dead-Letter Queue" />
      <ErrorBanner error={error} />

      <Panel accent="INTEGRATION" title="Select destination" dense>
        <select className="input" value={selected} onChange={(e) => setSelected(e.target.value)}>
          <option value="">— select integration —</option>
          {integrations.map(i => (
            <option key={i.id} value={i.id}>{i.name} ({i.type})</option>
          ))}
        </select>
      </Panel>

      <Panel accent={`PENDING · ${letters.filter(l => !l.resolved_at).length}`} title="Failed Deliveries" dense>
        <DataTable<DeadLetter>
          rows={letters}
          columns={[
            { key: 'enqueued_at', header: 'When', render: r => new Date(r.enqueued_at).toLocaleString() },
            { key: 'event_type', header: 'Event',
              render: r => <span className="text-orange-primary">{r.event_type}</span> },
            { key: 'attempts', header: 'Tries' },
            { key: 'last_status_code', header: 'Last Code', render: r => r.last_status_code ?? '—' },
            { key: 'last_error', header: 'Error',
              render: r => <span className="text-[10px]">{(r.last_error ?? '').slice(0, 60)}</span> },
            { key: 'resolution', header: 'State',
              render: r => r.resolved_at
                ? <span className="text-text-muted">{r.resolution ?? 'resolved'}</span>
                : <div className="flex gap-1">
                    <button className="btn-primary" onClick={() => replay(r.id)}>REPLAY</button>
                    <button className="btn-muted" onClick={() => drop(r.id)}>DROP</button>
                  </div> },
          ]}
        />
      </Panel>
    </div>
  );
}
