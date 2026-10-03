import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Cell
} from 'recharts';

const BRAND_TEAL  = '#035352';
const CREAM       = '#F3E8BC';

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'rgba(3,10,10,0.95)',
      border: '1px solid rgba(3,83,82,0.35)',
      borderRadius: 8,
      padding: '8px 12px',
    }}>
      <p style={{ color: CREAM, fontSize: 12, fontWeight: 600, marginBottom: 2 }}>{label}</p>
      <p style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
        Attacks: <span style={{ color: '#f87171', fontWeight: 700 }}>{payload[0].value}</span>
      </p>
    </div>
  );
};

/**
 * Horizontal bar chart — top attacking source IPs.
 * @param {Array<{ip: string, attacks: number}>} data
 */
export default function TopIPsChart({ data = [] }) {
  if (!data.length) return (
    <div className="flex items-center justify-center h-32"
         style={{ color: 'var(--text-muted)', fontSize: 13 }}>
      No IP data available
    </div>
  );

  const maxVal = Math.max(...data.map(d => d.attacks));

  return (
    <div className="space-y-2">
      {data.map((row, i) => {
        const pct = maxVal > 0 ? (row.attacks / maxVal) * 100 : 0;
        // Intensity fades from full teal → dimmer for lower IPs
        const opacity = 1 - (i * 0.12);
        return (
          <div key={row.ip} className="flex items-center gap-3">
            {/* IP label */}
            <span
              className="font-mono text-[11px] flex-shrink-0 w-28 truncate"
              style={{ color: i === 0 ? CREAM : 'var(--text-secondary)' }}
            >
              {row.ip}
            </span>

            {/* Bar track */}
            <div
              className="flex-1 relative h-5 rounded-md overflow-hidden"
              style={{ background: 'rgba(3,83,82,0.08)' }}
            >
              <div
                className="h-full rounded-md transition-all"
                style={{
                  width: `${pct}%`,
                  background: `rgba(3,83,82,${opacity})`,
                  minWidth: pct > 0 ? 8 : 0,
                }}
              />
            </div>

            {/* Count */}
            <span
              className="text-xs font-mono font-semibold flex-shrink-0 w-6 text-right"
              style={{ color: i === 0 ? '#f87171' : 'var(--text-muted)' }}
            >
              {row.attacks}
            </span>
          </div>
        );
      })}

      <p className="text-[10px] font-mono pt-1" style={{ color: 'var(--text-muted)' }}>
        attacks per source IP · live data
      </p>
    </div>
  );
}
