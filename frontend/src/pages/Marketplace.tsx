// §34 Partner integration marketplace — browse catalog, install,
// configure (with the listing's JSON Schema rendered as a form),
// uninstall.
//
// Lifecycle:
//   pending_config → operator fills schema fields → active
//   active → operator clicks UNINSTALL → suspended
//
// Re-installing a previously-suspended listing reuses the same
// install row (UPSERT in the API).

import { useEffect, useMemo, useState } from 'react';
import { Panel } from '../components/ui/Panel';
import { StatCard } from '../components/ui/StatCard';
import { PageHeader, ErrorBanner } from './_helpers';
import {
  marketplace,
  MarketplaceListing,
  MarketplaceInstall,
} from '../api/marketplace';

type SchemaProperty = {
  type?: string;
  title?: string;
  description?: string;
  format?: string;
  enum?: string[];
};

type Schema = {
  type?: string;
  required?: string[];
  properties?: Record<string, SchemaProperty>;
};

const CATEGORY_TONES: Record<string, string> = {
  chat:       'text-status-low',
  ticketing:  'text-status-medium',
  siem:       'text-orange-primary',
  devops:     'text-text-primary',
  identity:   'text-status-info',
  incident:   'text-status-critical',
};

export function Marketplace() {
  const [listings, setListings] = useState<MarketplaceListing[]>([]);
  const [installs, setInstalls] = useState<MarketplaceInstall[]>([]);
  const [category, setCategory] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [installing, setInstalling] = useState<MarketplaceListing | null>(null);
  const [configValues, setConfigValues] = useState<Record<string, string>>({});

  const refresh = async () => {
    try {
      const [l, i] = await Promise.all([
        marketplace.listListings(category || undefined),
        marketplace.listInstalls(),
      ]);
      setListings(l.listings ?? []);
      setInstalls(i.installs ?? []);
    } catch (e) { setError((e as Error).message); }
  };

  useEffect(() => { refresh(); }, [category]);

  const installedSlugs = useMemo(() => {
    const m = new Map<string, MarketplaceInstall>();
    for (const inst of installs) {
      if (inst.state !== 'suspended') m.set(inst.listing_slug, inst);
    }
    return m;
  }, [installs]);

  const categories = useMemo(() => {
    const s = new Set<string>();
    for (const l of listings) s.add(l.category);
    return Array.from(s).sort();
  }, [listings]);

  const counts = useMemo(() => ({
    available: listings.length,
    installed: installs.filter(i => i.state === 'active').length,
    pending:   installs.filter(i => i.state === 'pending_config').length,
    suspended: installs.filter(i => i.state === 'suspended').length,
  }), [listings, installs]);

  async function startInstall(l: MarketplaceListing) {
    const schema = l.config_schema as Schema;
    // If the listing has no required fields, install in one shot (active).
    if (!schema?.required || schema.required.length === 0) {
      try {
        await marketplace.install({ listing_slug: l.slug, config: {} });
        await refresh();
      } catch (e) { setError((e as Error).message); }
      return;
    }
    setInstalling(l);
    setConfigValues({});
  }

  async function submitInstall(e: React.FormEvent) {
    e.preventDefault();
    if (!installing) return;
    try {
      const config: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(configValues)) {
        if (v.trim() !== '') config[k] = v.trim();
      }
      await marketplace.install({ listing_slug: installing.slug, config });
      setInstalling(null);
      setConfigValues({});
      await refresh();
    } catch (e) { setError((e as Error).message); }
  }

  async function uninstall(installID: string) {
    try {
      await marketplace.uninstall(installID);
      await refresh();
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="07 SYSTEM" title="Integration Marketplace · §34" />
      <ErrorBanner error={error} />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Available"  value={counts.available} />
        <StatCard label="Active"     value={counts.installed} tone="low" />
        <StatCard label="Pending"    value={counts.pending}   tone={counts.pending > 0 ? 'high' : undefined} />
        <StatCard label="Suspended"  value={counts.suspended} tone={counts.suspended > 0 ? 'critical' : undefined} />
      </div>

      <Panel accent="FILTER" title="Catalog">
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => setCategory('')}
            className={`btn-muted text-[10px] ${category === '' ? 'border-orange-primary text-orange-primary' : ''}`}>
            ALL
          </button>
          {categories.map(c => (
            <button
              key={c}
              onClick={() => setCategory(c)}
              className={`btn-muted text-[10px] ${category === c ? 'border-orange-primary text-orange-primary' : ''}`}>
              {c.toUpperCase()}
            </button>
          ))}
        </div>
        <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
          {listings.map(l => {
            const inst = installedSlugs.get(l.slug);
            return (
              <div key={l.id} className="border border-border-subtle p-3 bg-bg-deep/40">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <div className="text-xs font-bold tracking-widest-2 uppercase text-text-primary">
                      {l.name}
                    </div>
                    <div className="text-[10px] font-mono text-text-muted mt-0.5">
                      {l.publisher} · <span className={CATEGORY_TONES[l.category] ?? ''}>{l.category}</span>
                      {l.verified && <span className="ml-2 text-status-low">✓ VERIFIED</span>}
                    </div>
                  </div>
                  {inst ? (
                    <span className={`text-[10px] font-mono px-2 py-1 border ${
                      inst.state === 'active'
                        ? 'border-status-low text-status-low'
                        : 'border-status-medium text-status-medium'
                    }`}>
                      {inst.state.replace('_', ' ').toUpperCase()}
                    </span>
                  ) : null}
                </div>
                <div className="text-xs text-text-muted">{l.description}</div>
                <div className="mt-3 flex items-center gap-2">
                  {!inst && (
                    <button className="btn-primary text-[10px]" onClick={() => startInstall(l)}>
                      INSTALL
                    </button>
                  )}
                  {inst && (
                    <button className="btn-muted text-[10px]" onClick={() => uninstall(inst.id)}>
                      UNINSTALL
                    </button>
                  )}
                  {l.docs_url && (
                    <a href={l.docs_url} target="_blank" rel="noreferrer"
                       className="text-[10px] font-mono text-text-muted hover:text-orange-primary">
                      DOCS ↗
                    </a>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </Panel>

      {installs.length > 0 && (
        <Panel accent="LIFECYCLE" title="Per-Tenant Installs">
          <table className="w-full text-xs font-mono">
            <thead className="text-text-muted border-b border-border-subtle">
              <tr>
                <th className="text-left py-2">LISTING</th>
                <th className="text-left">CATEGORY</th>
                <th className="text-left">STATE</th>
                <th className="text-left">INSTALLED</th>
              </tr>
            </thead>
            <tbody>
              {installs.map(inst => (
                <tr key={inst.id} className="border-b border-border-subtle/30">
                  <td className="py-1.5 text-text-primary">{inst.listing_name}</td>
                  <td className="text-text-muted">{inst.category}</td>
                  <td className={
                    inst.state === 'active' ? 'text-status-low' :
                    inst.state === 'pending_config' ? 'text-status-medium' :
                    'text-status-critical'
                  }>{inst.state}</td>
                  <td className="text-text-muted">
                    {new Date(inst.installed_at).toISOString().slice(0, 19).replace('T', ' ')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      {installing && (
        <Panel accent="CONFIGURE" title={`Configure: ${installing.name}`}>
          <form onSubmit={submitInstall} className="space-y-2">
            {renderSchemaFields(installing.config_schema as Schema, configValues, setConfigValues)}
            <div className="flex gap-2 mt-3">
              <button className="btn-primary text-xs" type="submit">INSTALL</button>
              <button className="btn-muted text-xs" type="button" onClick={() => setInstalling(null)}>
                CANCEL
              </button>
            </div>
          </form>
        </Panel>
      )}
    </div>
  );
}

function renderSchemaFields(
  schema: Schema,
  values: Record<string, string>,
  setValues: React.Dispatch<React.SetStateAction<Record<string, string>>>,
) {
  if (!schema?.properties) return null;
  const required = new Set(schema.required ?? []);
  return Object.entries(schema.properties).map(([key, prop]) => {
    const isRequired = required.has(key);
    const label = prop.title || key;
    const placeholder = prop.description || (prop.format === 'uri' ? 'https://...' : '');
    return (
      <div key={key}>
        <label className="text-[10px] font-mono uppercase tracking-widest-2 text-text-muted">
          {label} {isRequired && <span className="text-status-critical">*</span>}
        </label>
        {prop.enum ? (
          <select
            className="input w-full"
            value={values[key] ?? ''}
            onChange={(e) => setValues(v => ({ ...v, [key]: e.target.value }))}>
            <option value="">(select)</option>
            {prop.enum.map(opt => <option key={opt} value={opt}>{opt}</option>)}
          </select>
        ) : (
          <input
            className="input w-full"
            placeholder={placeholder}
            required={isRequired}
            value={values[key] ?? ''}
            onChange={(e) => setValues(v => ({ ...v, [key]: e.target.value }))} />
        )}
      </div>
    );
  });
}
