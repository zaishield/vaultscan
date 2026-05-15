import { FormEvent, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuthStore } from '../store/auth';
import { useBranding } from '../store/branding';
import { Logo } from '../components/ui/Logo';

export function Login() {
  const navigate = useNavigate();
  const setSession = useAuthStore((s) => s.setSession);
  const { bundle, load } = useBranding();
  useEffect(() => { load(); }, [load]);

  const [email, setEmail] = useState('admin@zaishield.com');
  const [tenantId, setTenantId] = useState('');
  const [partnerId, setPartnerId] = useState('00000000-0000-0000-0000-0000000000b1');
  const [roles, setRoles] = useState('zaishield_super_admin');
  const [mfa, setMfa] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setLoading(true); setError(null);
    try {
      const r = await api.post<{ token: string }>('/api/v1/auth/dev-token', {
        email, full_name: email, mfa,
        partner_id: partnerId, tenant_id: tenantId,
        roles: roles.split(',').map((s) => s.trim()).filter(Boolean),
      });
      setSession({
        token: r.token, email, fullName: email,
        roles: roles.split(',').map((s) => s.trim()),
        partnerId, tenantId: tenantId || null,
      });
      navigate('/');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-void relative overflow-hidden">
      <div className="fixed inset-0 bg-grid"></div>
      <div className="fixed top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-orange-primary to-transparent" />
      <div className="relative z-10 w-full max-w-md">
        <div className="text-center mb-8">
          <Logo size={64} className="mx-auto mb-4" />
          <div className="text-[10px] tracking-widest-5 text-orange-primary uppercase font-mono mb-1">
            Enterprise Hybrid VA/PT Platform
          </div>
          <h1 className="text-2xl font-bold tracking-widest-2 uppercase">
            ZAISHIELD<span className="text-orange-primary">_</span>VAULTSCAN
          </h1>
          {bundle && (
            <div className="text-[10px] tracking-widest-2 text-text-muted uppercase font-mono mt-2">
              · {bundle.partner.name} portal ·
            </div>
          )}
        </div>

        <form onSubmit={submit} className="panel p-6 space-y-3">
          <div className="label-accent">Authenticate</div>
          <div>
            <div className="label mb-1">Email</div>
            <input className="input" value={email} onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <div className="label mb-1">Tenant ID (optional)</div>
            <input className="input" value={tenantId} onChange={(e) => setTenantId(e.target.value)} placeholder="UUID" />
          </div>
          <div>
            <div className="label mb-1">Partner ID</div>
            <input className="input" value={partnerId} onChange={(e) => setPartnerId(e.target.value)} />
          </div>
          <div>
            <div className="label mb-1">Roles (comma-separated)</div>
            <input className="input" value={roles} onChange={(e) => setRoles(e.target.value)} />
          </div>
          <label className="flex items-center gap-2 text-xs font-mono text-text-muted">
            <input type="checkbox" checked={mfa} onChange={(e) => setMfa(e.target.checked)} />
            <span>Mark this session MFA-verified (required for evidence downloads, aggressive scans)</span>
          </label>
          {error && (
            <div className="text-status-critical text-xs font-mono p-2 border border-status-critical/30 bg-status-critical/5">
              {error}
            </div>
          )}
          <button className="btn-primary w-full" disabled={loading}>
            {loading ? 'AUTHENTICATING…' : 'INITIATE SESSION'}
          </button>
          <div className="text-[10px] font-mono text-text-muted">
            Production deployments use Keycloak / OIDC / SAML SSO. This dev token issuer is enabled
            only when VAULTSCAN_ENV=development.
          </div>
        </form>
      </div>
    </div>
  );
}
