import { ReactNode } from 'react';

export interface Column<T> {
  key: keyof T | string;
  header: string;
  width?: string;
  render?: (row: T) => ReactNode;
}

export function DataTable<T extends Record<string, any>>({
  columns, rows, empty = 'No records.',
}: { columns: Column<T>[]; rows: T[]; empty?: string }) {
  return (
    <div className="panel overflow-x-auto">
      <table className="w-full font-mono text-xs">
        <thead>
          <tr className="bg-bg-surface text-text-muted">
            {columns.map((c) => (
              <th key={String(c.key)}
                  className="text-left px-3 py-2 tracking-widest uppercase text-[10px] font-semibold"
                  style={{ width: c.width }}>
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr><td className="px-3 py-3 text-text-muted" colSpan={columns.length}>{empty}</td></tr>
          )}
          {rows.map((row, i) => (
            <tr key={i} className="row-divider hover:bg-bg-surface/50">
              {columns.map((c) => (
                <td key={String(c.key)} className="px-3 py-2 text-text-primary align-top">
                  {c.render ? c.render(row) : String(row[c.key as keyof T] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
