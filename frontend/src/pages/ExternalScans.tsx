import { useEffect, useState } from 'react';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { Panel } from '../components/ui/Panel';
import { PageHeader, ErrorBanner } from './_helpers';
import type { Engagement, ScanProfile } from '../types';

const REGIONS = ['ae', 'eu', 'in', 'us', 'sg'];

export function ExternalScans() {
  const tenantId = useAuthStore((s) => s.tenantId);
  const partnerId = useAuthStore((s) => s.partnerId);
  const [step, setStep] = useState(1);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [engId, setEngId] = useState('');
  const [profile, setProfile] = useState('external_standard_va');
  const [region, setRegion] = useState('ae');
  const [targets, setTargets] = useState('');
  const [scheduleAt, setScheduleAt] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState<string | null>(null);

  useEffect(() => {
    if (tenantId) {
      api.get<{ items: Engagement[] }>(`/api/v1/engagements?tenant_id=${tenantId}`)
        .then((r) => setEngagements(r.items ?? [])).catch((e) => setError((e as Error).message));
    }
    api.get<{ items: ScanProfile[] }>('/api/v1/scans/profiles')
      .then((r) => setProfiles((r.items ?? []).filter((p) => p.plane === 'external')))
      .catch((e) => setError((e as Error).message));
  }, [tenantId]);

  async function submit() {
    setError(null);
    try {
      const body = {
        tenant_id: tenantId, partner_id: partnerId,
        engagement_id: engId, profile_code: profile,
        region, targets: targets.split('\n').map((t) => t.trim()).filter(Boolean),
        schedule_at: scheduleAt ? new Date(scheduleAt).toISOString() : undefined,
        intensity: profile.includes('aggressive') ? 'aggressive' : 'standard',
      };
      const r = await api.post('/api/v1/scans/external', body);
      setSubmitted(JSON.stringify(r, null, 2));
      setStep(7);
    } catch (e) { setError((e as Error).message); }
  }

  const Header = () => (
    <div className="flex items-center gap-2 mb-3">
      {[1, 2, 3, 4, 5, 6, 7].map((n) => (
        <div key={n}
             className={`h-1 flex-1 ${n <= step ? 'bg-orange-primary' : 'bg-border-subtle'}`} />
      ))}
    </div>
  );

  return (
    <div className="space-y-4">
      <PageHeader accent="04 SCANNING" title="External Scan Wizard" />
      <ErrorBanner error={error} />
      <Header />

      {step === 1 && (
        <Panel accent="STEP 1 / 7" title="Select Engagement">
          <select className="input" value={engId} onChange={(e) => setEngId(e.target.value)}>
            <option value="">— select —</option>
            {engagements.map((e) => <option key={e.id} value={e.id}>{e.code} · {e.name}</option>)}
          </select>
          <div className="mt-3"><button className="btn-primary" onClick={() => setStep(2)} disabled={!engId}>NEXT</button></div>
        </Panel>
      )}
      {step === 2 && (
        <Panel accent="STEP 2 / 7" title="External Plane Confirmed">
          <p className="text-xs font-mono text-text-muted">External scans run from regional cloud scanner farms. Internal scans require an enrolled agent.</p>
          <div className="mt-3 flex gap-2"><button className="btn-muted" onClick={() => setStep(1)}>BACK</button><button className="btn-primary" onClick={() => setStep(3)}>NEXT</button></div>
        </Panel>
      )}
      {step === 3 && (
        <Panel accent="STEP 3 / 7" title="Approved Targets">
          <textarea className="input min-h-[160px] font-mono" placeholder="One target per line (FQDN, IP, CIDR, URL)"
                    value={targets} onChange={(e) => setTargets(e.target.value)} />
          <div className="mt-3 flex gap-2"><button className="btn-muted" onClick={() => setStep(2)}>BACK</button><button className="btn-primary" onClick={() => setStep(4)} disabled={!targets.trim()}>NEXT</button></div>
        </Panel>
      )}
      {step === 4 && (
        <Panel accent="STEP 4 / 7" title="Scan Profile">
          <select className="input" value={profile} onChange={(e) => setProfile(e.target.value)}>
            {profiles.map((p) => <option key={p.code} value={p.code}>{p.name} ({p.intensity}) · {p.tools.join('·')}</option>)}
          </select>
          <div className="mt-3 flex gap-2"><button className="btn-muted" onClick={() => setStep(3)}>BACK</button><button className="btn-primary" onClick={() => setStep(5)}>NEXT</button></div>
        </Panel>
      )}
      {step === 5 && (
        <Panel accent="STEP 5 / 7" title="Region & Time Window">
          <div className="grid grid-cols-2 gap-3">
            <select className="input" value={region} onChange={(e) => setRegion(e.target.value)}>
              {REGIONS.map((r) => <option key={r} value={r}>{r.toUpperCase()}</option>)}
            </select>
            <input className="input" type="datetime-local" value={scheduleAt} onChange={(e) => setScheduleAt(e.target.value)} placeholder="Schedule (optional)" />
          </div>
          <div className="mt-3 flex gap-2"><button className="btn-muted" onClick={() => setStep(4)}>BACK</button><button className="btn-primary" onClick={() => setStep(6)}>NEXT</button></div>
        </Panel>
      )}
      {step === 6 && (
        <Panel accent="STEP 6 / 7" title="Review Authorization">
          <div className="font-mono text-xs space-y-1">
            <div>engagement: <span className="text-orange-primary">{engId}</span></div>
            <div>profile:    <span className="text-orange-primary">{profile}</span></div>
            <div>region:     <span className="text-orange-primary">{region}</span></div>
            <div>targets:    <span className="text-orange-primary">{targets.split('\n').filter(Boolean).length}</span></div>
            <div>schedule:   <span className="text-orange-primary">{scheduleAt || 'immediate'}</span></div>
            <div className="text-text-muted mt-3">Scope Guard will validate every target against the approved scope and authorization documents on submit.</div>
          </div>
          <div className="mt-3 flex gap-2"><button className="btn-muted" onClick={() => setStep(5)}>BACK</button><button className="btn-primary" onClick={submit}>SUBMIT FOR SCAN</button></div>
        </Panel>
      )}
      {step === 7 && submitted && (
        <Panel accent="STEP 7 / 7" title="Submission Receipt">
          <pre className="font-mono text-xs text-text-primary overflow-auto bg-bg-surface p-3 border border-border-subtle">
            {submitted}
          </pre>
          <div className="mt-3"><button className="btn-ghost" onClick={() => { setStep(1); setSubmitted(null); }}>NEW SCAN</button></div>
        </Panel>
      )}
    </div>
  );
}
