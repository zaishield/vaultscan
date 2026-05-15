import type { Severity } from '../../types';

export function SevBadge({ severity }: { severity: Severity }) {
  const cls = `sev sev-${severity}`;
  return <span className={cls}>{severity}</span>;
}

export function StatusDot({ label, color }: { label: string; color: string }) {
  return (
    <span className="inline-flex items-center gap-2 font-mono text-[10px] tracking-widest-2 uppercase" style={{ color }}>
      <span className="w-2 h-2 animate-pulse-orange" style={{ background: color, borderRadius: 9999 }} />
      {label}
    </span>
  );
}
