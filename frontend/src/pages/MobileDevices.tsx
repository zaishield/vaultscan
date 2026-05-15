// §24 Mobile portal management — view enrolled devices, see the
// "what the mobile app sees" snapshot, push-test by triggering an
// emergency-stop ack flow.
//
// The actual mobile app (iOS/Android) consumes these endpoints; this
// admin page lets desktop ops see the same state + curate device
// enrolment.

import { useEffect, useState } from 'react';
import { Panel } from '../components/ui/Panel';
import { StatCard } from '../components/ui/StatCard';
import { PageHeader, ErrorBanner } from './_helpers';
import { mobile, MobileDashboard } from '../api/mobile';
import { useAuthStore } from '../store/auth';

export function MobileDevices() {
  const tenantId = useAuthStore(s => s.tenantId);
  const [dash, setDash] = useState<MobileDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [enrollLabel, setEnrollLabel] = useState('Operator iPhone 15');
  const [enrollPlatform, setEnrollPlatform] = useState<'ios' | 'android'>('ios');
  const [enrollToken, setEnrollToken] = useState('');
  const [emergencyReason, setEmergencyReason] = useState('Mobile-initiated kill (drill)');
  const [enrollResult, setEnrollResult] = useState<string | null>(null);
  const [stopResult, setStopResult] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const d = await mobile.dashboard();
      setDash(d);
    } catch (e) { setError((e as Error).message); }
  };
  useEffect(() => { refresh(); }, []);

  async function enroll(e: React.FormEvent) {
    e.preventDefault();
    if (!tenantId) { setError('no tenant context'); return; }
    if (!enrollToken) { setError('push_token required'); return; }
    try {
      const r = await mobile.enrollDevice({
        tenant_id: tenantId,
        device_label: enrollLabel,
        platform: enrollPlatform,
        push_token: enrollToken,
      });
      setEnrollResult(r.device_id);
      setEnrollToken('');
    } catch (e) { setError((e as Error).message); }
  }

  async function fireEmergencyStop() {
    if (!tenantId) return;
    try {
      const r = await mobile.emergencyStop(tenantId, emergencyReason);
      setStopResult(`stopped ${r.stopped} job(s) · reason: ${r.reason}`);
      await refresh();
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="07 SYSTEM" title="Mobile Portal · §24" />
      <ErrorBanner error={error} />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Critical Findings"  value={dash?.open_critical_count ?? 0}
                  tone={(dash?.open_critical_count ?? 0) > 0 ? 'critical' : undefined} />
        <StatCard label="Agents Online"      value={dash?.agents_online ?? 0} tone="low" />
        <StatCard label="Agents Offline"     value={dash?.agents_offline ?? 0}
                  tone={(dash?.agents_offline ?? 0) > 0 ? 'high' : undefined} />
        <StatCard label="Jobs Running"       value={dash?.jobs_running ?? 0} />
      </div>

      <Panel accent="ENROLL" title="Register a mobile device">
        <p className="text-xs text-text-muted mb-2">
          Production: the iOS/Android app calls /api/v1/mobile/devices with
          its APNS/FCM push token at first launch + after MFA verification.
          Use this admin form to enroll a test handset.
        </p>
        <form onSubmit={enroll} className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <input className="input" placeholder="device label" value={enrollLabel}
                 onChange={(e) => setEnrollLabel(e.target.value)} />
          <select className="input" value={enrollPlatform}
                  onChange={(e) => setEnrollPlatform(e.target.value as 'ios' | 'android')}>
            <option value="ios">iOS</option>
            <option value="android">Android</option>
          </select>
          <input className="input" placeholder="push token" value={enrollToken}
                 onChange={(e) => setEnrollToken(e.target.value)} />
          <div className="md:col-span-3">
            <button className="btn-primary text-xs" type="submit">ENROLL</button>
            {enrollResult && (
              <span className="ml-3 text-xs text-status-low font-mono">
                Enrolled: {enrollResult.slice(0, 8)}
              </span>
            )}
          </div>
        </form>
      </Panel>

      <Panel accent="ALERTS" title="Pending push-notification approvals">
        {(dash?.pending_approvals?.length ?? 0) === 0 ? (
          <div className="text-xs font-mono text-text-muted">
            No alerts awaiting mobile acknowledgement.
          </div>
        ) : (
          <table className="w-full text-xs font-mono">
            <thead className="text-text-muted border-b border-border-subtle">
              <tr><th className="text-left py-2">TITLE</th><th>SEVERITY</th><th>REQUESTED</th></tr>
            </thead>
            <tbody>
              {dash?.pending_approvals.map(a => (
                <tr key={a.id} className="border-b border-border-subtle/30">
                  <td className="py-1.5 text-text-primary">{a.title}</td>
                  <td className={
                    a.severity === 'critical' ? 'text-status-critical' :
                    a.severity === 'high' ? 'text-orange-primary' :
                    'text-status-medium'}>{a.severity}</td>
                  <td className="text-text-muted">
                    {new Date(a.requested_at).toISOString().slice(0, 19).replace('T', ' ')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel accent="EMERGENCY" title="Mobile-initiated emergency stop">
        <p className="text-xs text-text-muted mb-2">
          MFA-verified mobile sessions can halt all running scans for the
          current tenant. This panel exercises the same code path so you
          can drill the §11.6 30-second SLA.
        </p>
        <div className="flex gap-2">
          <input className="input flex-1" placeholder="reason"
                 value={emergencyReason}
                 onChange={(e) => setEmergencyReason(e.target.value)} />
          <button className="btn-primary text-xs" onClick={fireEmergencyStop}>FIRE</button>
        </div>
        {stopResult && (
          <div className="mt-2 text-xs font-mono text-status-low">{stopResult}</div>
        )}
      </Panel>
    </div>
  );
}
