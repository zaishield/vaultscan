import { ReactNode } from 'react';

export function Panel({
  title, accent, right, children, dense = false,
}: {
  title?: string; accent?: string; right?: ReactNode; children: ReactNode; dense?: boolean;
}) {
  return (
    <section className="panel">
      {(title || right) && (
        <div className="flex items-center justify-between border-b border-border-subtle px-4 py-2 bg-bg-surface">
          <div className="flex items-center gap-3">
            {accent && <span className="label-accent">{accent}</span>}
            {title && <h2 className="text-sm font-semibold tracking-widest-2 uppercase">{title}</h2>}
          </div>
          {right}
        </div>
      )}
      <div className={dense ? '' : 'p-4'}>{children}</div>
    </section>
  );
}
