import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { PageHeader, ErrorBanner } from './_helpers';
import type { Engagement, Report } from '../types';

const REPORT_TYPES = [
  'executive', 'technical', 'external_attack_surface', 'internal_network',
  'web_api', 'cloud_security', 'ad_security', 'container_kubernetes',
  'retest', 'compliance', 'risk_register',
];
const FORMATS = ['pdf', 'docx', 'xlsx', 'html', 'json', 'csv'];

export function Reports() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const partnerId = useAuthStore((s) => s.partnerId);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [engId, setEngId] = useState('');
  const [type, setType] = useState('executive');
  const [title, setTitle] = useState('Executive VA/PT Report');
  const [formats, setFormats] = useState<string[]>(['pdf', 'html']);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!tenantId) return;
    api.get<{ items: Engagement[] }>(`/api/v1/engagements?tenant_id=${tenantId}`)
      .then((r) => setEngagements(r.items ?? [])).catch((e) => setError((e as Error).message));
  }, [tenantId]);

  async function generate() {
    setError(null);
    try {
      const r = await api.post<Report>('/api/v1/reports', {
        tenant_id: tenantId, partner_id: partnerId,
        engagement_id: engId, report_type: type, title, formats,
      });
      setReport(r);
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="06 OUTPUT" title="Reporting Engine" />
      <ErrorBanner error={error} />
      <Panel accent="GENERATE" title="New Report">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <select className="input" value={engId} onChange={(e) => setEngId(e.target.value)}>
            <option value="">— select engagement —</option>
            {engagements.map((e) => <option key={e.id} value={e.id}>{e.code} · {e.name}</option>)}
          </select>
          <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
            {REPORT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input className="input" placeholder="Title" value={title} onChange={(e) => setTitle(e.target.value)} />
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {FORMATS.map((f) => (
            <label key={f} className="flex items-center gap-1 text-xs font-mono uppercase">
              <input type="checkbox" checked={formats.includes(f)}
                     onChange={(e) => setFormats(e.target.checked ? [...formats, f] : formats.filter((x) => x !== f))} />
              {f}
            </label>
          ))}
        </div>
        <div className="mt-3"><button className="btn-primary" onClick={generate} disabled={!engId}>GENERATE REPORT</button></div>
      </Panel>

      {report && (
        <Panel accent="READY" title={report.title}>
          <div className="text-xs font-mono space-y-1">
            <div>id: <span className="text-orange-primary">{report.id}</span></div>
            <div>type: {report.report_type}</div>
            <div>generated: {new Date(report.generated_at).toLocaleString()}</div>
            <div className="mt-2">exports:</div>
            <ul className="list-disc list-inside text-text-primary">
              {report.exports.map((ex) => (
                <li key={ex.format} className="font-mono">
                  <span className="text-orange-primary uppercase">{ex.format}</span> · {ex.size_bytes} bytes ·
                  <span className="text-text-muted"> sha256={ex.sha256.slice(0, 12)}…</span>
                </li>
              ))}
            </ul>
          </div>
        </Panel>
      )}
    </div>
  );
}
