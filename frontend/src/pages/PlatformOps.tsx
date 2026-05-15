import { useEffect, useState } from 'react';
import { guardrailsOps, authOps, IPLockout, MaintenanceState, PolicyRule } from '../api/ops';
import { Panel } from '../components/ui/Panel';
import { DataTable } from '../components/ui/DataTable';
import { PageHeader, ErrorBanner } from './_helpers';

export function PlatformOps() {
  const [maint, setMaint] = useState<MaintenanceState | null>(null);
  const [reason, setReason] = useState('');
  const [lockouts, setLockouts] = useState<IPLockout[]>([]);
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [bgPerm, setBGPerm] = useState('reports.export_legal_bundle');
  const [bgReason, setBGReason] = useState('');
  const [bgIssued, setBGIssued] = useState<{ token: string; expires_at: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      setMaint(await guardrailsOps.maintenanceStatus());
      setLockouts((await authOps.listIPLockouts()).lockouts ?? []);
      setRules((await guardrailsOps.policyRules()).rules ?? []);
    } catch (e) { setError((e as Error).message); }
  }
  useEffect(() => { load(); }, []);

  async function toggleMaint() {
    if (!maint) return;
    const next = !maint.enabled;
    if (next && !reason) { setError('reason required to enable maintenance'); return; }
    try {
      await guardrailsOps.setMaintenance(next, reason || maint.reason || '');
      await load();
    } catch (e) { setError((e as Error).message); }
  }

  async function unlock(ip: string) {
    try {
      await authOps.unlockIP(ip);
      await load();
    } catch (e) { setError((e as Error).message); }
  }

  async function issueBG(e: React.FormEvent) {
    e.preventDefault();
    if (!bgReason) { setError('reason required'); return; }
    try {
      const r = await guardrailsOps.issueBreakGlass(bgPerm, bgReason, 15);
      setBGIssued({ token: r.token, expires_at: r.expires_at });
    } catch (err) { setError((err as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="07 SYSTEM" title="Platform Operations" />
      <ErrorBanner error={error} />

      <Panel accent="MAINTENANCE MODE" title={maint?.enabled ? 'ACTIVE — writes blocked' : 'off'}>
        <div className="flex gap-2 items-center">
          <input className="input flex-1" placeholder="reason (required to enable)"
                 value={reason} onChange={(e) => setReason(e.target.value)} />
          <button className={maint?.enabled ? 'btn-muted' : 'btn-primary'} onClick={toggleMaint}>
            {maint?.enabled ? 'DISABLE' : 'ENABLE'}
          </button>
        </div>
        {maint?.reason && (
          <div className="mt-2 text-xs font-mono text-text-muted">
            current reason: <span className="text-text-primary">{maint.reason}</span>
          </div>
        )}
      </Panel>

      <Panel accent="BREAK-GLASS" title="One-time elevated-permission token">
        {bgIssued ? (
          <div className="font-mono text-xs space-y-1">
            <div className="text-status-high">SHOW ONCE — store securely:</div>
            <pre className="p-2 bg-bg-deep border border-status-high text-status-high">{bgIssued.token}</pre>
            <div className="text-text-muted">expires {new Date(bgIssued.expires_at).toLocaleString()}</div>
            <button className="btn-muted" onClick={() => setBGIssued(null)}>DISMISS</button>
          </div>
        ) : (
          <form onSubmit={issueBG} className="flex gap-2">
            <input className="input flex-1" placeholder="permission code" required
                   value={bgPerm} onChange={(e) => setBGPerm(e.target.value)} />
            <input className="input flex-1" placeholder="reason (ticket #, etc.)" required
                   value={bgReason} onChange={(e) => setBGReason(e.target.value)} />
            <button className="btn-primary" type="submit">ISSUE (15m)</button>
          </form>
        )}
      </Panel>

      <Panel accent={`IP LOCKOUTS · ${lockouts.length}`} title="Brute-force shield" dense>
        <DataTable<IPLockout>
          rows={lockouts}
          columns={[
            { key: 'ip', header: 'IP', render: r => <span className="font-mono">{r.ip}</span> },
            { key: 'locked_until', header: 'Until', render: r => new Date(r.locked_until).toLocaleString() },
            { key: 'reason', header: 'Reason' },
            { key: 'ip', header: 'Action',
              render: r => <button className="btn-muted" onClick={() => unlock(r.ip)}>UNLOCK</button> },
          ]}
        />
      </Panel>

      <Panel accent={`POLICY RULES · ${rules.length}`} title="Operational guardrails (§36)" dense>
        <DataTable<PolicyRule>
          rows={rules}
          columns={[
            { key: 'name', header: 'Rule',
              render: r => <span className="text-orange-primary">{r.name}</span> },
            { key: 'rule_class', header: 'Class' },
            { key: 'subject', header: 'Subject' },
            { key: 'verdict', header: 'Verdict' },
            { key: 'description', header: 'Description' },
          ]}
        />
      </Panel>
    </div>
  );
}
