// §33 Customer feedback admin triage view + submit form.
//
// Two panels:
//   - Submit Feedback: any authenticated user can post. Category, optional
//     severity, optional NPS rating, message, current page context.
//   - Triage Inbox: requires manage_feedback permission. Filter by status,
//     bulk-walk through new items, transition status, leave resolution
//     note.

import { useEffect, useMemo, useState } from 'react';
import { Panel } from '../components/ui/Panel';
import { StatCard } from '../components/ui/StatCard';
import { PageHeader, ErrorBanner } from './_helpers';
import { feedback, FeedbackItem } from '../api/feedback';

const CATEGORIES: FeedbackItem['category'][] = [
  'bug', 'feature', 'question', 'compliment', 'complaint', 'nps',
];
const SEVERITIES: FeedbackItem['severity'][] = ['', 'cosmetic', 'minor', 'major', 'critical'];
const STATUSES: FeedbackItem['status'][] = [
  'new', 'triaging', 'planned', 'in_progress', 'resolved', 'wont_fix',
];

export function Feedback() {
  const [items, setItems] = useState<FeedbackItem[]>([]);
  const [npsScore, setNpsScore] = useState<number | undefined>();
  const [statusFilter, setStatusFilter] = useState<FeedbackItem['status'] | ''>('');
  const [error, setError] = useState<string | null>(null);

  // Submit form state.
  const [category, setCategory] = useState<FeedbackItem['category']>('bug');
  const [severity, setSeverity] = useState<FeedbackItem['severity']>('');
  const [rating, setRating] = useState<number | ''>('');
  const [message, setMessage] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submittedID, setSubmittedID] = useState<string | null>(null);

  // Triage state.
  const [editingID, setEditingID] = useState<string | null>(null);
  const [editStatus, setEditStatus] = useState<FeedbackItem['status']>('triaging');
  const [editNote, setEditNote] = useState('');

  const refresh = async () => {
    try {
      const r = await feedback.list(statusFilter || undefined);
      setItems(r.items ?? []);
      setNpsScore(r.nps_score);
    } catch (e) { setError((e as Error).message); }
  };
  useEffect(() => { refresh(); }, [statusFilter]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const r = await feedback.submit({
        category,
        severity: category === 'bug' ? severity : '',
        rating: category === 'nps' && rating !== '' ? Number(rating) : undefined,
        message,
        page_context: window.location.pathname,
      });
      setSubmittedID(r.id);
      setMessage(''); setRating('');
      await refresh();
    } catch (e) { setError((e as Error).message); }
    finally { setSubmitting(false); }
  }

  function startEdit(item: FeedbackItem) {
    setEditingID(item.id);
    setEditStatus(item.status === 'new' ? 'triaging' : item.status);
    setEditNote(item.resolution ?? '');
  }

  async function saveTriage(id: string) {
    try {
      await feedback.triage(id, { status: editStatus, resolution: editNote });
      setEditingID(null); setEditNote('');
      await refresh();
    } catch (e) { setError((e as Error).message); }
  }

  const counts = useMemo(() => ({
    new:        items.filter(i => i.status === 'new').length,
    triaging:   items.filter(i => i.status === 'triaging').length,
    in_progress:items.filter(i => i.status === 'in_progress').length,
    resolved:   items.filter(i => i.status === 'resolved').length,
  }), [items]);

  return (
    <div className="space-y-4">
      <PageHeader accent="07 SYSTEM" title="Customer Feedback · §33" right={
        npsScore !== undefined ? (
          <div className="text-xs font-mono text-text-muted">
            NPS: <span className={npsScore >= 50 ? 'text-status-low' :
                                  npsScore >= 0 ? 'text-orange-primary' :
                                  'text-status-critical'}>{npsScore.toFixed(1)}</span>
          </div>
        ) : null
      } />
      <ErrorBanner error={error} />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="New"          value={counts.new}        tone={counts.new > 0 ? 'high' : undefined} />
        <StatCard label="Triaging"     value={counts.triaging} />
        <StatCard label="In Progress"  value={counts.in_progress} />
        <StatCard label="Resolved"     value={counts.resolved}   tone="low" />
      </div>

      <Panel accent="SUBMIT" title="Send feedback to the product team">
        <form onSubmit={submit} className="grid grid-cols-1 md:grid-cols-2 gap-2">
          <select className="input" value={category}
                  onChange={(e) => setCategory(e.target.value as FeedbackItem['category'])}>
            {CATEGORIES.map(c => <option key={c} value={c}>{c.toUpperCase()}</option>)}
          </select>
          {category === 'bug' && (
            <select className="input" value={severity}
                    onChange={(e) => setSeverity(e.target.value as FeedbackItem['severity'])}>
              {SEVERITIES.map(s => <option key={s} value={s}>{(s || 'unset').toUpperCase()}</option>)}
            </select>
          )}
          {category === 'nps' && (
            <input className="input" type="number" min={0} max={10} placeholder="0-10"
                   value={rating}
                   onChange={(e) => setRating(e.target.value === '' ? '' : Number(e.target.value))} />
          )}
          <textarea className="input md:col-span-2 h-24" placeholder="What's on your mind?"
                    required value={message} onChange={(e) => setMessage(e.target.value)} />
          <div className="md:col-span-2 flex items-center gap-3">
            <button className="btn-primary" type="submit" disabled={submitting}>
              {submitting ? 'SUBMITTING...' : 'SUBMIT'}
            </button>
            {submittedID && <span className="text-xs text-status-low font-mono">
              Thanks — submitted as {submittedID.slice(0, 8)}
            </span>}
          </div>
        </form>
      </Panel>

      <Panel accent="TRIAGE" title="Inbox">
        <div className="flex gap-2 mb-3">
          <button className={`btn-muted text-[10px] ${statusFilter === '' ? 'border-orange-primary text-orange-primary' : ''}`}
                  onClick={() => setStatusFilter('')}>ALL</button>
          {STATUSES.map(s => (
            <button key={s}
                    className={`btn-muted text-[10px] ${statusFilter === s ? 'border-orange-primary text-orange-primary' : ''}`}
                    onClick={() => setStatusFilter(s)}>
              {s.toUpperCase().replace('_', ' ')}
            </button>
          ))}
        </div>
        {items.length === 0 ? (
          <div className="text-xs font-mono text-text-muted">No feedback in this view.</div>
        ) : (
          <div className="space-y-3">
            {items.map(item => (
              <div key={item.id} className="border border-border-subtle p-3 bg-bg-deep/40">
                <div className="flex items-center justify-between text-[10px] font-mono uppercase mb-1">
                  <div className="flex items-center gap-3">
                    <span className="text-orange-primary">{item.category}</span>
                    {item.severity && <span className="text-status-medium">{item.severity}</span>}
                    {item.rating !== undefined && <span className="text-text-muted">NPS: {item.rating}</span>}
                    <span className="text-text-muted">
                      {new Date(item.submitted_at).toISOString().slice(0, 19).replace('T', ' ')}
                    </span>
                    {item.user_email && <span className="text-text-muted">{item.user_email}</span>}
                  </div>
                  <span className={
                    item.status === 'new' ? 'text-status-medium' :
                    item.status === 'resolved' ? 'text-status-low' :
                    'text-text-primary'
                  }>{item.status}</span>
                </div>
                <div className="text-xs text-text-primary whitespace-pre-wrap mb-2">{item.message}</div>
                {item.page_context && (
                  <div className="text-[10px] font-mono text-text-muted">page: {item.page_context}</div>
                )}
                {editingID === item.id ? (
                  <div className="mt-2 space-y-2">
                    <select className="input text-xs" value={editStatus}
                            onChange={(e) => setEditStatus(e.target.value as FeedbackItem['status'])}>
                      {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                    <textarea className="input w-full text-xs" placeholder="resolution note (optional)"
                              value={editNote} onChange={(e) => setEditNote(e.target.value)} />
                    <div className="flex gap-2">
                      <button className="btn-primary text-[10px]" onClick={() => saveTriage(item.id)}>SAVE</button>
                      <button className="btn-muted text-[10px]" onClick={() => setEditingID(null)}>CANCEL</button>
                    </div>
                  </div>
                ) : (
                  <button className="btn-muted text-[10px] mt-2" onClick={() => startEdit(item)}>
                    {item.status === 'new' ? 'TRIAGE' : 'UPDATE'}
                  </button>
                )}
                {item.resolution && editingID !== item.id && (
                  <div className="text-xs italic text-text-muted mt-2">→ {item.resolution}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
