import { useEffect, useState } from 'react';
import { useAuthStore } from '../store/auth';
import { api } from '../api/client';
import { Panel } from '../components/ui/Panel';
import { PageHeader, ErrorBanner } from './_helpers';

export function EvidenceVault() {
  const [evidenceId, setEvidenceId] = useState('');
  const [downloadURL, setDownloadURL] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function getURL() {
    setError(null); setDownloadURL(null);
    try {
      const r = await api.get<{ url: string; expires_at: string }>(`/api/v1/evidence/${evidenceId}/url`);
      setDownloadURL(r.url);
    } catch (e) { setError((e as Error).message); }
  }

  return (
    <div className="space-y-4">
      <PageHeader accent="05 FINDINGS" title="Evidence Vault" />
      <ErrorBanner error={error} />
      <Panel accent="ENCRYPTED STORE" title="Signed Download">
        <p className="text-xs font-mono text-text-muted mb-3">
          Evidence is AES-256-GCM encrypted at rest, tenant-isolated, and access-logged.
          Download URLs expire 5 minutes after issue. Downloads require an MFA-verified
          session (Blueprint §18, §29.3).
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input className="input md:col-span-2" placeholder="Evidence UUID" value={evidenceId} onChange={(e) => setEvidenceId(e.target.value)} />
          <button className="btn-primary" onClick={getURL} disabled={!evidenceId}>SIGN DOWNLOAD URL</button>
        </div>
        {downloadURL && (
          <div className="mt-3 panel-elevated p-3 break-all">
            <div className="label-accent mb-1">Signed URL (5 min TTL)</div>
            <a className="text-orange-primary hover:underline font-mono text-xs" href={downloadURL} target="_blank" rel="noreferrer">
              {downloadURL}
            </a>
          </div>
        )}
      </Panel>
      <Panel accent="USAGE" title="How to Find Evidence IDs">
        <ul className="text-xs font-mono text-text-muted space-y-1 list-disc list-inside">
          <li>Open a finding → "Evidence" section in detail view</li>
          <li>Run an internal scan → agent uploads results, evidence_id returned</li>
          <li>Use the audit endpoint to find evidence.uploaded events</li>
        </ul>
      </Panel>
    </div>
  );
}
