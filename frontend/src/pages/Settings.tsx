import { useEffect, useState } from 'react';
import { useBranding } from '../store/branding';
import { useAuthStore } from '../store/auth';
import { api } from '../api/client';
import { Panel } from '../components/ui/Panel';
import { PageHeader, ErrorBanner } from './_helpers';

export function Settings() {
  const { bundle, load } = useBranding();
  const partnerId = useAuthStore((s) => s.partnerId);
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<'dark' | 'light'>(
    (document.documentElement.getAttribute('data-theme') as 'dark' | 'light') || 'dark');

  // Branding form
  const [productName, setProductName] = useState(bundle?.branding.product_name ?? '');
  const [primary, setPrimary] = useState(bundle?.branding.primary_color ?? '#FF6B00');
  const [secondary, setSecondary] = useState(bundle?.branding.secondary_color ?? '#FF8C00');
  const [logoURL, setLogoURL] = useState(bundle?.branding.logo_url ?? '');
  const [legalFooter, setLegalFooter] = useState(bundle?.branding.legal_footer ?? '');
  const [confTag, setConfTag] = useState(bundle?.branding.confidentiality_tag ?? '');
  const [supportEmail, setSupportEmail] = useState(bundle?.branding.support_email ?? '');

  useEffect(() => {
    if (bundle) {
      setProductName(bundle.branding.product_name);
      setPrimary(bundle.branding.primary_color);
      setSecondary(bundle.branding.secondary_color);
      setLogoURL(bundle.branding.logo_url ?? '');
      setLegalFooter(bundle.branding.legal_footer ?? '');
      setConfTag(bundle.branding.confidentiality_tag ?? '');
      setSupportEmail(bundle.branding.support_email ?? '');
    }
  }, [bundle]);

  function applyTheme(t: 'dark' | 'light') {
    setTheme(t);
    document.documentElement.setAttribute('data-theme', t);
  }

  async function saveBranding() {
    if (!partnerId) { setError('partner_id missing'); return; }
    try {
      await api.put(`/api/v1/partners/${partnerId}/branding`, {
        ProductName: productName, PrimaryColor: primary, SecondaryColor: secondary,
        LogoURL: logoURL, LegalFooter: legalFooter,
        ConfidentialityTag: confTag, SupportEmail: supportEmail,
      });
      load();
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="07 SYSTEM" title="Settings" />
      <ErrorBanner error={error} />
      <Panel accent="THEME" title="Display Mode">
        <div className="flex gap-2">
          <button className={theme === 'dark' ? 'btn-primary' : 'btn-muted'} onClick={() => applyTheme('dark')}>DARK</button>
          <button className={theme === 'light' ? 'btn-primary' : 'btn-muted'} onClick={() => applyTheme('light')}>LIGHT</button>
        </div>
        <p className="text-text-muted text-xs font-mono mt-2">
          The brand mark switches between dark / light variants automatically.
          VAULTSCAN is dark-first by design.
        </p>
      </Panel>

      <Panel accent="WHITE-LABEL" title="Partner Branding">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Field label="Product Name"  value={productName}  set={setProductName} />
          <Field label="Logo URL (overrides built-in mark)" value={logoURL} set={setLogoURL} />
          <Field label="Primary Color"   value={primary}    set={setPrimary} />
          <Field label="Secondary Color" value={secondary}  set={setSecondary} />
          <Field label="Support Email"   value={supportEmail} set={setSupportEmail} />
          <Field label="Confidentiality Tag" value={confTag} set={setConfTag} />
          <Field label="Legal Footer" value={legalFooter} set={setLegalFooter} />
        </div>
        <div className="mt-3"><button className="btn-primary" onClick={saveBranding}>SAVE BRANDING</button></div>
      </Panel>

      {bundle && (
        <Panel accent="LIVE BUNDLE" title="Resolved Branding (debug)">
          <pre className="font-mono text-xs text-text-primary overflow-auto bg-bg-surface p-3 border border-border-subtle">
            {JSON.stringify(bundle, null, 2)}
          </pre>
        </Panel>
      )}
    </div>
  );
}

function Field({ label, value, set }: { label: string; value: string; set: (s: string) => void }) {
  return (
    <div>
      <div className="label mb-1">{label}</div>
      <input className="input" value={value} onChange={(e) => set(e.target.value)} />
    </div>
  );
}
