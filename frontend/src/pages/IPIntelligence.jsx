import { useState } from 'react';
import { format, parseISO } from 'date-fns';
import {
  Search, Globe, ShieldAlert, Clock,
  BarChart2, Activity, Hash, Info
} from 'lucide-react';

import { getIPDetail } from '../api/apiService.js';
import { mockIPProfiles } from '../mock/mockData.js';
import usePageMeta from '../hooks/usePageMeta.js';
import RiskBadge      from '../components/common/RiskBadge.jsx';
import LoadingSpinner from '../components/common/LoadingSpinner.jsx';
import EmptyState     from '../components/common/EmptyState.jsx';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts';

const RISK_RING = (s) => {
  if (s >= 85) return '#f87171';
  if (s >= 65) return '#fb923c';
  if (s >= 40) return '#fbbf24';
  return '#4ade80';
};
const RISK_TEXT = (s) => {
  if (s >= 85) return '#f87171';
  if (s >= 65) return '#fb923c';
  if (s >= 40) return '#fbbf24';
  return '#4ade80';
};

const KNOWN_IPS = Object.keys(mockIPProfiles);

// ── Risk Gauge ──────────────────────────────────────────────
function RiskGauge({ score }) {
  const color = RISK_RING(score);
  const circumference = 2 * Math.PI * 42;
  const progress = ((100 - score) / 100) * circumference;

  return (
    <div className="relative w-36 h-36 flex items-center justify-center">
      <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(3,83,82,0.15)" strokeWidth="7" />
        <circle
          cx="50" cy="50" r="42" fill="none"
          stroke={color} strokeWidth="7"
          strokeDasharray={circumference}
          strokeDashoffset={progress}
          strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 1s ease' }}
        />
      </svg>
      <div className="absolute text-center">
        <p className="text-3xl font-bold num-display" style={{ color }}>{score}</p>
        <p className="text-[10px] font-mono uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Risk Score</p>
      </div>
    </div>
  );
}

// ── Chart Tooltip ───────────────────────────────────────────
function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'rgba(3, 12, 12, 0.95)',
      border: '1px solid rgba(3,83,82,0.35)',
      borderRadius: 10,
      padding: '10px 14px',
      boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
    }}>
      <p style={{ color: '#F3E8BC', fontSize: 12, marginBottom: 4 }}>{label}</p>
      {payload.map(p => (
        <p key={p.dataKey} style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
          {p.name}: <span style={{ color: '#F3E8BC', fontWeight: 700 }}>{p.value}</span>
        </p>
      ))}
    </div>
  );
}

export default function IPIntelligence() {
  usePageMeta('IP Intelligence', 'URL Tracer Security — Investigate IP risk profiles, attack history, and threat patterns.');
  const [query, setQuery]     = useState('');
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

  const search = async (ip) => {
    const q = (ip ?? query).trim();
    if (!q) return;
    setLoading(true);
    setError('');
    setProfile(null);
    try {
      const data = await getIPDetail(q);
      setProfile(data);
    } catch (err) {
      setError(`No data found for "${q}". Try one of the example IPs below.`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5 animate-fade-in">

      {/* ── Page heading ──────────────────────── */}
      <div>
        <h1 className="text-base font-bold flex items-center gap-2" style={{ color: '#F3E8BC' }}>
          <Globe className="w-4 h-4" />
          IP Intelligence
        </h1>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Investigate source IPs, review risk scores, and explore attack history
        </p>
      </div>

      {/* ── Search Panel ────────────────────── */}
      <div className="glass-card p-5">
        <label className="block text-xs font-semibold uppercase tracking-widest mb-3"
               style={{ color: 'var(--text-muted)' }}>
          IP Address Investigation
        </label>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Enter IP address, e.g. 192.168.1.25"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && search()}
              className="cyber-input pl-10 font-mono"
            />
          </div>
          <button onClick={() => search()} className="btn-primary px-6">
            <Search className="w-4 h-4" />
            Analyse
          </button>
        </div>

        {/* Quick IPs */}
        <div className="mt-4">
          <p className="text-[11px] font-mono uppercase tracking-wider mb-2" style={{ color: 'var(--text-muted)' }}>
            Example IPs — click to load:
          </p>
          <div className="flex flex-wrap gap-2">
            {KNOWN_IPS.map(ip => (
              <button
                key={ip}
                onClick={() => { setQuery(ip); search(ip); }}
                className="px-2.5 py-1 text-xs font-mono rounded-lg transition-all"
                style={{
                  background: 'rgba(3,83,82,0.10)',
                  border: '1px solid rgba(3,83,82,0.25)',
                  color: '#F3E8BC',
                }}
                onMouseEnter={e => { e.currentTarget.style.background = 'rgba(3,83,82,0.22)'; e.currentTarget.style.borderColor = 'rgba(3,83,82,0.5)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'rgba(3,83,82,0.10)'; e.currentTarget.style.borderColor = 'rgba(3,83,82,0.25)'; }}
              >
                {ip}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Loading / Error */}
      {loading && <LoadingSpinner message="Analysing IP..." />}
      {error && !loading && <EmptyState title="IP Not Found" message={error} icon="search" />}

      {/* ── Profile ───────────────────────────────────── */}
      {profile && !loading && (
        <div className="space-y-5 animate-fade-in">

          {/* IP Header Card */}
          <div className="glass-card p-6">
            <div className="flex flex-wrap items-center gap-6">
              <RiskGauge score={profile.risk_score} />

              <div className="flex-1 min-w-60">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-2xl font-bold font-mono" style={{ color: '#F3E8BC' }}>{profile.ip}</span>
                  <RiskBadge severity={profile.risk_level === 'CRITICAL' ? 'CRITICAL' : profile.risk_level} />
                </div>
                <p className="text-xs font-mono mb-5" style={{ color: 'var(--text-muted)' }}>{profile.hostname}</p>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: 'Total Requests', value: profile.total_requests, icon: Activity },
                    { label: 'Attacks',         value: profile.attack_count,   icon: ShieldAlert },
                    { label: 'First Seen',       value: format(parseISO(profile.first_seen), 'MMM d'), icon: Clock },
                    { label: 'Last Seen',        value: format(parseISO(profile.last_seen), 'MMM d HH:mm'), icon: Clock },
                  ].map(({ label, value, icon: Icon }) => (
                    <div key={label} className="rounded-xl p-3"
                         style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.15)' }}>
                      <div className="flex items-center gap-1.5 mb-1">
                        <Icon className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
                        <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{label}</p>
                      </div>
                      <p className="text-sm font-bold font-mono" style={{ color: 'var(--text-primary)' }}>{value}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Attack types + Activity */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Attack types breakdown */}
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: '#F3E8BC' }}>
                <Hash className="w-4 h-4" style={{ color: '#F3E8BC' }} />
                Attack Types
              </h3>
              <div className="space-y-3">
                {profile.attack_types.map((type, i) => {
                  const attacks = (profile.attacks ?? []).filter(a => a.attack_type === type);
                  const pct = profile.attack_count > 0
                    ? Math.round((attacks.length / profile.attack_count) * 100)
                    : Math.round(100 / profile.attack_types.length);
                  const shades = ['#035352','#046a69','#059894','#06b0ac','#04817f','#2b7070','#1a8f8e'];
                  return (
                    <div key={type}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{type}</span>
                        <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                          {attacks.length > 0 ? attacks.length : '—'}
                        </span>
                      </div>
                      <div className="progress-bar">
                        <div className="progress-fill" style={{ width: `${pct}%`, background: shades[i % shades.length] }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Daily activity mini-chart */}
            <div className="glass-card p-5">
              <h3 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: '#F3E8BC' }}>
                <BarChart2 className="w-4 h-4" style={{ color: '#F3E8BC' }} />
                Daily Activity
              </h3>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={profile.daily_activity} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(3,83,82,0.12)" vertical={false} />
                  <XAxis dataKey="date" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Bar dataKey="requests" name="Requests" fill="#035352" radius={[3,3,0,0]} />
                  <Bar dataKey="attacks"  name="Attacks"  fill="#f87171" radius={[3,3,0,0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Attacks from this IP */}
          {profile.attacks?.length > 0 && (
            <div className="glass-card overflow-hidden">
              <div className="section-header">
                <h3 className="section-title">
                  Attacks from {profile.ip}
                  <span className="ml-2 text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                    ({profile.attacks.length})
                  </span>
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Attack Type</th>
                      <th>Severity</th>
                      <th>Result</th>
                      <th>Method</th>
                    </tr>
                  </thead>
                  <tbody>
                    {profile.attacks.slice(0, 10).map(atk => (
                      <tr key={atk.id}>
                        <td className="font-mono text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                          {format(parseISO(atk.timestamp), 'MM/dd HH:mm')}
                        </td>
                        <td style={{ color: 'var(--text-primary)' }}>{atk.attack_type}</td>
                        <td><RiskBadge severity={atk.severity} /></td>
                        <td>
                          <span className="text-xs font-mono"
                                style={{ color: atk.result === 'POTENTIAL_SUCCESS' ? '#f87171' : '#fbbf24' }}>
                            {atk.result === 'POTENTIAL_SUCCESS' ? '⚡ SUCCESS' : '⚠ ATTEMPT'}
                          </span>
                        </td>
                        <td className="text-xs" style={{ color: 'var(--text-muted)' }}>{atk.detection_method}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Initial empty state */}
      {!profile && !loading && !error && (
        <EmptyState
          title="Enter an IP address"
          message="Type an IP address above or click one of the example IPs to see a full risk profile."
          icon="search"
        />
      )}
    </div>
  );
}
