import { ReactNode, useEffect } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { useBranding } from '../../store/branding';
import { useAuthStore } from '../../store/auth';
import { Logo } from '../ui/Logo';

const NAV: { label: string; to: string; section?: string }[] = [
  { label: 'Dashboard',      to: '/',                section: '01 OVERVIEW' },
  { label: 'Clients',        to: '/clients',         section: '02 ESTATE'   },
  { label: 'Distributors',   to: '/distributors' },
  { label: 'Resellers',      to: '/resellers' },
  { label: 'Engagements',    to: '/engagements',     section: '03 OPERATIONS' },
  { label: 'Scope',          to: '/scope' },
  { label: 'Assets',         to: '/assets' },
  { label: 'External Scans', to: '/scans/external',  section: '04 SCANNING' },
  { label: 'Internal Agents',to: '/agents' },
  { label: 'Scan Jobs',      to: '/scans' },
  { label: 'Findings',       to: '/findings',        section: '05 FINDINGS' },
  { label: 'Evidence Vault', to: '/evidence' },
  { label: 'Reports',        to: '/reports',         section: '06 OUTPUT' },
  { label: 'Retesting',      to: '/retesting' },
  { label: 'Remediation',    to: '/remediation' },
  { label: 'Integrations',   to: '/integrations',    section: '07 SYSTEM' },
  { label: 'Audit Trail',    to: '/audit' },
  { label: 'Settings',       to: '/settings' },
];

export function AppShell({ children }: { children?: ReactNode }) {
  const { bundle, load } = useBranding();
  const location = useLocation();
  const { email, roles, clear, tenantId } = useAuthStore();

  useEffect(() => { load(); }, [load]);

  const productName = bundle?.branding.product_name ?? 'ZAISHIELD VAULTSCAN';
  const confTag     = bundle?.branding.confidentiality_tag ?? 'CONFIDENTIAL // INTERNAL USE ONLY';

  return (
    <div className="min-h-screen flex flex-col bg-bg-void text-text-primary relative overflow-hidden">
      <div className="fixed inset-0 bg-grid"></div>
      <div className="h-[2px] bg-gradient-to-r from-transparent via-orange-primary to-transparent" />

      <header className="relative z-10 border-b border-border-subtle bg-bg-deep/80 backdrop-blur">
        <div className="flex items-center px-6 py-3 gap-6">
          <Link to="/" className="flex items-center gap-3">
            <Logo size={32} partnerLogoURL={bundle?.branding.logo_url ?? null} className="h-8 w-8" />
            <div className="leading-tight">
              <div className="text-[9px] font-mono tracking-widest-4 text-orange-primary uppercase">
                Enterprise Hybrid VA/PT Platform
              </div>
              <div className="text-base font-bold tracking-widest-2 uppercase font-inter">
                {splitProduct(productName)}
              </div>
            </div>
          </Link>
          <div className="flex-1" />
          <div className="hidden md:flex items-center gap-6 text-[10px] font-mono tracking-widest-2 uppercase text-text-muted">
            <span>tenant: <span className="text-orange-primary">{tenantId?.slice(0, 8) ?? '—'}</span></span>
            <span>roles: <span className="text-text-primary">{roles.length ? roles.join(', ') : 'guest'}</span></span>
            <span>{email ?? 'unauthenticated'}</span>
            <button onClick={() => { clear(); window.location.assign('/login'); }} className="btn-muted">Sign Out</button>
          </div>
        </div>
      </header>

      <div className="relative z-10 flex-1 flex">
        <aside className="hidden md:block w-60 border-r border-border-subtle bg-bg-deep/60 backdrop-blur">
          <nav className="py-4 px-3">
            {NAV.map((n, i) => (
              <div key={n.to}>
                {n.section && (
                  <div className="mt-4 mb-1 px-3 label">{n.section}</div>
                )}
                <NavLink to={n.to} end={n.to === '/'}
                  className={({ isActive }) =>
                    `flex items-center gap-2 px-3 py-1.5 text-xs uppercase tracking-widest-2 font-mono ${
                      isActive
                        ? 'bg-orange-primary/10 text-orange-primary border-l-2 border-orange-primary'
                        : 'text-text-muted hover:text-text-primary hover:bg-bg-surface/50 border-l-2 border-transparent'
                    }`}>
                  <span className="text-orange-primary">›</span>
                  <span>{n.label}</span>
                </NavLink>
              </div>
            ))}
          </nav>
        </aside>

        <main className="flex-1 px-6 py-6 overflow-y-auto">
          <BreadCrumb path={location.pathname} />
          <div className="mt-4">
            {children ?? <Outlet />}
          </div>
        </main>
      </div>

      <footer className="relative z-10 border-t border-border-subtle px-6 py-3 flex items-center justify-between bg-bg-deep">
        <div className="text-[10px] font-mono tracking-widest-2 text-text-muted">
          {bundle?.branding.legal_footer ?? '© ZAISHIELD VAULTSCAN'}
        </div>
        <div className="text-[10px] font-mono tracking-widest-2 text-orange-primary">{confTag}</div>
      </footer>
      <div className="h-[2px] bg-gradient-to-r from-transparent via-orange-primary to-transparent" />
    </div>
  );
}

function BreadCrumb({ path }: { path: string }) {
  const parts = path.split('/').filter(Boolean);
  return (
    <div className="flex items-center gap-2 text-[10px] font-mono tracking-widest-2 uppercase text-text-muted">
      <span className="text-orange-primary">›</span>
      <Link to="/" className="hover:text-text-primary">Home</Link>
      {parts.map((p, i) => (
        <span key={i} className="flex items-center gap-2">
          <span className="text-text-muted">/</span>
          <span className="text-text-primary">{p}</span>
        </span>
      ))}
    </div>
  );
}

function splitProduct(name: string) {
  // Render "ZAISHIELD VAULTSCAN" with the orange underscore between the two
  // tokens, matching the brand mark.
  const parts = name.split(' ');
  if (parts.length >= 2) {
    return (
      <>
        {parts[0]}
        <span className="text-orange-primary">_</span>
        {parts.slice(1).join(' ')}
      </>
    );
  }
  return name;
}
