interface Props { label: string; value: string | number; delta?: string; tone?: 'default' | 'critical' | 'high' | 'low' }

export function StatCard({ label, value, delta, tone = 'default' }: Props) {
  const valueColor =
    tone === 'critical' ? 'text-status-critical'
    : tone === 'high'   ? 'text-orange-primary'
    : tone === 'low'    ? 'text-status-low'
                        : 'text-text-primary';
  return (
    <div className="panel border-orange-primary/30 p-4">
      <div className="label">{label}</div>
      <div className={`text-3xl font-mono font-bold mt-1 ${valueColor}`}>{value}</div>
      {delta && <div className="text-[10px] font-mono mt-1 text-status-critical">{delta}</div>}
    </div>
  );
}
