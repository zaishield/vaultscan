// Common page helpers - tiny because the panels and tables already do most work.

import { ReactNode } from 'react';

export function PageHeader({
  accent, title, right,
}: { accent: string; title: string; right?: ReactNode }) {
  return (
    <div className="flex items-end justify-between mb-4">
      <div>
        <div className="label-accent mb-1">{accent}</div>
        <h1 className="h-section">{title}</h1>
        <div className="accent-line mt-2 w-64" />
      </div>
      {right}
    </div>
  );
}

export function ErrorBanner({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <div className="text-status-critical text-xs font-mono p-2 border border-status-critical/30 bg-status-critical/5 mb-3">
      {error}
    </div>
  );
}
