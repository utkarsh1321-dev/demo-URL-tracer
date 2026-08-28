import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Activity, ShieldAlert, Globe, CheckCircle2, RefreshCw,
  FileSearch, Brain, ArrowRight, Shield, Clock,
  AlertTriangle, ChevronRight, Target, BarChart2,
  Crosshair, Wifi, Link2, Search, TrendingUp, AlertCircle
} from 'lucide-react';
import { format, parseISO } from 'date-fns';
import usePageMeta from '../hooks/usePageMeta.js';

import { getDashboard, getAttacks, getTopSourceIPs, getURLStats } from '../api/apiService.js';
import StatCard        from '../components/common/StatCard.jsx';
import ChartCard       from '../components/common/ChartCard.jsx';
import RiskBadge       from '../components/common/RiskBadge.jsx';
import LoadingSpinner  from '../components/common/LoadingSpinner.jsx';
import AttackChart     from '../components/charts/AttackChart.jsx';
import SeverityChart   from '../components/charts/SeverityChart.jsx';
import Timeline        from '../components/charts/Timeline.jsx';
import TopIPsChart     from '../components/charts/TopIPsChart.jsx';

const SEV_DOT = {
  CRITICAL: '#f87171',
  HIGH:     '#fb923c',
  MEDIUM:   '#fbbf24',
  LOW:      '#4ade80',
};


// ── Threat Detail Drawer ─────────────────────────────────────
function ThreatDrawer({ attack, onClose }) {
  if (!attack) return null;

  const riskColor =
    attack.severity === 'CRITICAL' ? '#f87171' :
    attack.severity === 'HIGH'     ? '#fb923c' :
    attack.severity === 'MEDIUM'   ? '#fbbf24' : '#4ade80';

  const circumference = 2 * Math.PI * 40;
  const confidence    = attack.confidence ?? 0.9;
  const offset        = circumference * (1 - confidence);

  return (
    <>
      <div
        className="fixed inset-0 z-50"
        style={{ background: 'rgba(2,8,8,0.7)', backdropFilter: 'blur(4px)' }}
        onClick={onClose}
      />
      <aside className="drawer z-50">
        {/* Header */}
        <div
          className="flex items-center justify-between px-6 py-5 flex-shrink-0"
          style={{ borderBottom: '1px solid rgba(3,83,82,0.2)' }}
        >
          <div>
            <div className="flex items-center gap-2 mb-1">
              <RiskBadge severity={attack.severity} />
              <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{attack.id}</span>
            </div>
            <h2 className="text-lg font-bold" style={{ color: '#F3E8BC' }}>Threat Analysis</h2>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: 'rgba(3,83,82,0.12)', border: '1px solid rgba(3,83,82,0.25)', color: 'var(--text-secondary)' }}
          >
            ✕
          </button>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Confidence gauge */}
          <div className="text-center py-4">
            <div className="relative w-24 h-24 mx-auto mb-3">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(3,83,82,0.15)" strokeWidth="6"/>
                <circle
                  cx="50" cy="50" r="40" fill="none"
                  stroke={riskColor} strokeWidth="6"
                  strokeLinecap="round"
                  strokeDasharray={circumference}
                  strokeDashoffset={offset}
                  style={{ transition: 'stroke-dashoffset 1s ease' }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-xl font-bold num-display" style={{ color: riskColor }}>
                  {Math.round(confidence * 100)}
                </span>
                <span className="text-[9px]" style={{ color: 'var(--text-muted)' }}>CONFIDENCE</span>
              </div>
            </div>
            <h3 className="text-xl font-bold" style={{ color: '#F3E8BC' }}>{attack.attack_type}</h3>
            <p className="text-sm mt-1" style={{ color: riskColor }}>● {attack.severity} SEVERITY</p>
          </div>

          {/* Fields grid */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'Source IP', value: attack.source_ip, accent: true },
              { label: 'Timestamp', value: format(parseISO(attack.timestamp), 'MM/dd HH:mm:ss'), mono: true },
              { label: 'Method',    value: attack.detection_method },
              { label: 'Result',
                value: attack.result === 'POTENTIAL_SUCCESS' ? '⚡ Potential Success' : '⚠ Attempt',
                color: attack.result === 'POTENTIAL_SUCCESS' ? '#f87171' : '#fbbf24' },
            ].map(({ label, value, mono, accent, color }) => (
              <div
                key={label}
                className="rounded-xl p-3"
                style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.15)' }}
              >
                <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>{label}</p>
                <p className={`text-sm font-medium ${mono ? 'font-mono' : ''}`}
                   style={{ color: accent ? '#F3E8BC' : color ?? 'var(--text-primary)' }}>
                  {value}
                </p>
              </div>
            ))}
          </div>

          {/* Target URL */}
          <div className="rounded-xl p-3" style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.15)' }}>
            <p className="text-[10px] uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>Target URL</p>
            <p className="text-xs font-mono break-all leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
              {attack.target_url}
            </p>
          </div>

          {/* Payload */}
          <div className="rounded-xl p-3" style={{ background: 'rgba(180,30,30,0.08)', border: '1px solid rgba(180,30,30,0.20)' }}>
            <p className="text-[10px] uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>Payload / Indicator</p>
            <p className="text-xs font-mono break-all leading-relaxed" style={{ color: '#f87171' }}>
              {attack.payload}
            </p>
          </div>

          {/* Detected indicators */}
          <div className="rounded-xl p-4" style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.18)' }}>
            <p className="text-xs font-semibold mb-3" style={{ color: '#F3E8BC' }}>Detected Indicators</p>
            <div className="space-y-2">
              {['Suspicious query parameter', 'Known attack pattern match', 'Abnormal URL structure'].map(ind => (
                <div key={ind} className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ background: '#f87171' }} />
                  <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{ind}</span>
                </div>
              ))}
            </div>
          </div>



        </div>

        {/* Footer */}
        <div className="px-6 py-4 flex-shrink-0" style={{ borderTop: '1px solid rgba(3,83,82,0.2)' }}>
          <Link to="/attacks" className="btn-primary w-full justify-center">
            <ShieldAlert className="w-4 h-4" />
            View in Attack Explorer
          </Link>
        </div>
      </aside>
    </>
  );
}

// ── Quick Action Button ──────────────────────────────────────
function QuickAction({ to, icon: Icon, label }) {
  return (
    <Link
      to={to}
      className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all"
      style={{
        background: 'rgba(3,83,82,0.08)',
        border: '1px solid rgba(3,83,82,0.20)',
        color: 'var(--text-secondary)',
      }}
      onMouseEnter={e => {
        e.currentTarget.style.background = 'rgba(3,83,82,0.18)';
        e.currentTarget.style.borderColor = 'rgba(3,83,82,0.40)';
        e.currentTarget.style.color = '#F3E8BC';
      }}
      onMouseLeave={e => {
        e.currentTarget.style.background = 'rgba(3,83,82,0.08)';
        e.currentTarget.style.borderColor = 'rgba(3,83,82,0.20)';
        e.currentTarget.style.color = 'var(--text-secondary)';
      }}
    >
      <Icon className="w-3.5 h-3.5 flex-shrink-0" />
      {label}
    </Link>
  );
}

// ── Main Dashboard ───────────────────────────────────────────
export default function Dashboard() {
  usePageMeta('Dashboard', 'URL Tracer Security — Real-time URL threat intelligence and attack detection dashboard.');
  const navigate = useNavigate();

  const [dashboard, setDashboard] = useState(null);
  const [urlStats,  setUrlStats]  = useState(null);
  const [recent,    setRecent]    = useState([]);
  const [topIPs,    setTopIPs]    = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [selected,  setSelected]  = useState(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [dash, attacksResp, ips, urlStatsResp] = await Promise.all([
        getDashboard(),
        getAttacks({ page_size: 8 }),
        getTopSourceIPs(6),
        getURLStats().catch(() => null),  // non-fatal if not available
      ]);
      setDashboard(dash);
      setUrlStats(urlStatsResp);
      // getAttacks returns { total, page, page_size, items }
      setRecent((attacksResp.items ?? []).slice(0, 8));
      setTopIPs(ips);
    } catch (err) {
      console.error('Dashboard load error:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadData(); }, []);

  if (loading) return <LoadingSpinner message="Loading dashboard..." />;

  // Dashboard may be null if the backend returned an error
  if (!dashboard) {
    return (
      <div className="flex flex-col items-center justify-center py-20 gap-4">
        <Shield className="w-12 h-12" style={{ color: 'var(--text-muted)', opacity: 0.4 }} />
        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
          Could not load dashboard. Is the backend running?
        </p>
        <button onClick={loadData} className="btn-secondary text-xs gap-1.5 px-3 py-2">
          <RefreshCw className="w-3.5 h-3.5" /> Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-5 animate-fade-in">

      {/* ── Top Bar: title + quick actions + refresh ──── */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Page title + live indicator */}
        <div className="flex items-center gap-2.5 mr-auto">
          <div className="flex items-center gap-1.5">
            <span className="live-dot" />
            <span className="text-[11px] font-mono font-semibold uppercase tracking-widest" style={{ color: '#4ade80' }}>
              Live
            </span>
          </div>
          <span className="text-sm font-semibold" style={{ color: '#F3E8BC' }}>
            Security Overview
          </span>
        </div>


        {/* Quick actions */}
        <div className="flex flex-wrap items-center gap-2">
          <QuickAction to="/url-analysis"   icon={Search}      label="URL Scan"    />
          <QuickAction to="/attacks"         icon={ShieldAlert} label="Attacks"      />
          <QuickAction to="/ip-intelligence" icon={Globe}       label="IP Intel"     />
          <QuickAction to="/pcap"            icon={FileSearch}  label="PCAP"         />
          <QuickAction to="/ml"              icon={Brain}       label="ML"           />
        </div>

        {/* Refresh + timestamp */}
        <div className="flex items-center gap-2 pl-1" style={{ borderLeft: '1px solid rgba(3,83,82,0.25)' }}>
          <Clock className="w-3 h-3" style={{ color: 'var(--text-muted)' }} />
          <span className="text-[11px] font-mono hidden sm:inline" style={{ color: 'var(--text-muted)' }}>
            {format(new Date(), 'HH:mm:ss')}
          </span>
          <button onClick={loadData} className="btn-secondary text-xs gap-1.5 px-2.5 py-1.5">
            <RefreshCw className="w-3 h-3" />
            Refresh
          </button>
        </div>
      </div>

      {/* ── Row 1: 5 KPI Cards ────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-4">
        <StatCard
          label="Total Requests"
          value={dashboard.total_requests}
          icon={Activity}
          color="teal"
          sub="All uploads"
        />
        <StatCard
          label="Attacks Detected"
          value={dashboard.total_attacks}
          icon={ShieldAlert}
          color="red"
          sub="All severities"
        />
        <StatCard
          label="Potential Successes"
          value={dashboard.potential_success_count ?? 0}
          icon={Crosshair}
          color="purple"
          sub="Possibly exploited"
        />
        <StatCard
          label="Attempts Blocked"
          value={(dashboard.total_attacks ?? 0) - (dashboard.potential_success_count ?? 0)}
          icon={CheckCircle2}
          color="orange"
          sub="Detected attempts"
        />
        <StatCard
          label="High-Risk IPs"
          value={dashboard.high_risk_ips}
          icon={Globe}
          color="cream"
          sub="CRITICAL / HIGH"
        />
      </div>


      {/* ── Row 2: URL Analysis Overview (Phase 6 — real data) ─ */}
      <div className="glass-card overflow-hidden">
        {/* Header */}
        <div
          className="flex items-center justify-between px-5 py-4"
          style={{ borderBottom: '1px solid rgba(3,83,82,0.12)' }}
        >
          <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: '#F3E8BC' }}>
            <Link2 className="w-4 h-4" style={{ color: '#F3E8BC' }} />
            URL Analysis Overview
            {urlStats && (
              <span
                className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                style={{ background: 'rgba(3,83,82,0.18)', border: '1px solid rgba(3,83,82,0.3)', color: 'var(--text-secondary)' }}
              >
                {urlStats.total_analyses} URLs scanned
              </span>
            )}
          </h2>
          <button
            onClick={() => navigate('/url-analysis')}
            className="text-xs flex items-center gap-1 transition-colors"
            style={{ color: 'var(--text-muted)' }}
            onMouseEnter={e => e.currentTarget.style.color = '#F3E8BC'}
            onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
          >
            Analyse URL <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Body */}
        {!urlStats || urlStats.total_analyses === 0 ? (
          /* ── Empty State ─────────────────────────────────────────── */
          <div className="flex flex-col items-center justify-center py-12 gap-3 px-6">
            <Search className="w-10 h-10" style={{ color: 'var(--text-muted)', opacity: 0.35 }} />
            <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
              No analyses yet.
            </p>
            <p className="text-xs text-center" style={{ color: 'var(--text-muted)', maxWidth: 300 }}>
              Submit your first URL to begin. Results will appear here with risk scores,
              predictions, and full history.
            </p>
            <button
              onClick={() => navigate('/url-analysis')}
              className="btn-primary text-xs px-4 py-2 mt-1"
            >
              <Search className="w-3.5 h-3.5" />
              Analyse a URL
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        ) : (
          /* ── Real Data ───────────────────────────────────────────── */
          <div className="p-5 space-y-5">
            {/* KPI row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {/* Total Analyses */}
              <div className="rounded-xl p-4 flex flex-col gap-1"
                style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.18)' }}>
                <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Total Analyses</p>
                <p className="text-2xl font-bold num-display" style={{ color: '#F3E8BC' }}>
                  {urlStats.total_analyses}
                </p>
                <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>URLs scanned</p>
              </div>

              {/* Threats Detected */}
              <div className="rounded-xl p-4 flex flex-col gap-1"
                style={{ background: 'rgba(248,113,113,0.06)', border: '1px solid rgba(248,113,113,0.18)' }}>
                <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Threats Detected</p>
                <p className="text-2xl font-bold num-display" style={{ color: '#f87171' }}>
                  {urlStats.threats_detected}
                </p>
                <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
                  {urlStats.total_analyses > 0
                    ? `${Math.round(urlStats.threats_detected / urlStats.total_analyses * 100)}% of scans`
                    : 'Phishing / Malware'}
                </p>
              </div>

              {/* High Risk URLs */}
              <div className="rounded-xl p-4 flex flex-col gap-1"
                style={{ background: 'rgba(251,146,60,0.06)', border: '1px solid rgba(251,146,60,0.18)' }}>
                <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>High Risk URLs</p>
                <p className="text-2xl font-bold num-display" style={{ color: '#fb923c' }}>
                  {urlStats.high_risk_urls}
                </p>
                <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>HIGH + CRITICAL</p>
              </div>

              {/* Avg Risk Score */}
              <div className="rounded-xl p-4 flex flex-col gap-1"
                style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.18)' }}>
                <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>Avg Risk Score</p>
                <p className="text-2xl font-bold num-display" style={{ color: '#F3E8BC' }}>
                  {urlStats.avg_risk_score}
                </p>
                <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>out of 100</p>
              </div>
            </div>

            {/* Risk distribution bar + recent table side by side */}
            <div className="grid grid-cols-1 xl:grid-cols-5 gap-5">

              {/* Risk Distribution — 2/5 */}
              <div className="xl:col-span-2 rounded-xl p-4 space-y-3"
                style={{ background: 'rgba(3,83,82,0.06)', border: '1px solid rgba(3,83,82,0.14)' }}>
                <p className="text-xs font-semibold" style={{ color: '#F3E8BC' }}>Risk Distribution</p>
                {[
                  { level: 'CRITICAL', color: '#f87171' },
                  { level: 'HIGH',     color: '#fb923c' },
                  { level: 'MEDIUM',   color: '#fbbf24' },
                  { level: 'LOW',      color: '#4ade80' },
                ].map(({ level, color }) => {
                  const count = urlStats.risk_distribution?.[level] ?? 0;
                  const pct   = urlStats.total_analyses > 0
                    ? Math.round(count / urlStats.total_analyses * 100) : 0;
                  return (
                    <div key={level} className="space-y-1">
                      <div className="flex justify-between items-center">
                        <span className="text-[11px] font-mono font-semibold" style={{ color }}>{level}</span>
                        <span className="text-[11px] font-mono" style={{ color: 'var(--text-muted)' }}>
                          {count} ({pct}%)
                        </span>
                      </div>
                      <div className="h-1.5 rounded-full" style={{ background: 'rgba(3,83,82,0.15)' }}>
                        <div
                          className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${pct}%`, background: color }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Recent Analyses — 3/5 */}
              <div className="xl:col-span-3 overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>URL</th>
                      <th>Prediction</th>
                      <th>Risk Score</th>
                      <th>Confidence</th>
                      <th>Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(urlStats.recent_analyses ?? []).slice(0, 8).map((a, i) => (
                      <tr key={a.id ?? i}>
                        <td className="font-mono text-xs max-w-[180px] truncate" style={{ color: 'var(--text-secondary)' }}
                          title={a.url}>
                          {a.url?.replace(/^https?:\/\//, '').slice(0, 35)}{a.url?.length > 35 ? '…' : ''}
                        </td>
                        <td>
                          <span
                            className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded"
                            style={{
                              color: a.prediction === 'PHISHING' || a.prediction === 'MALWARE'
                                ? '#f87171' : '#4ade80',
                              background: a.prediction === 'PHISHING' || a.prediction === 'MALWARE'
                                ? 'rgba(248,113,113,0.1)' : 'rgba(74,222,128,0.1)',
                              border: `1px solid ${a.prediction === 'PHISHING' || a.prediction === 'MALWARE'
                                ? 'rgba(248,113,113,0.25)' : 'rgba(74,222,128,0.25)'}`,
                            }}
                          >
                            {a.prediction}
                          </span>
                        </td>
                        <td>
                          <div className="flex items-center gap-2">
                            <div className="progress-bar w-12">
                              <div
                                className="progress-fill"
                                style={{
                                  width: `${a.risk_score}%`,
                                  background: a.risk_score >= 70 ? '#f87171'
                                    : a.risk_score >= 40 ? '#fbbf24' : '#4ade80',
                                }}
                              />
                            </div>
                            <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                              {a.risk_score}
                            </span>
                          </div>
                        </td>
                        <td className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                          {Math.round((a.confidence ?? 0) * 100)}%
                        </td>
                        <td className="text-[11px] font-mono whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                          {a.created_at ? format(new Date(a.created_at), 'MM/dd HH:mm') : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Footer link */}
            <div className="flex justify-end pt-1">
              <button
                onClick={() => navigate('/url-analysis')}
                className="btn-primary text-xs px-3 py-1.5"
              >
                <Link2 className="w-3.5 h-3.5" />
                View Full History
                <ArrowRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Row 3: Timeline (wide) + Activity Stream ─── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Attack timeline — takes 2/3 */}
        <div className="xl:col-span-2">
          <ChartCard
            title="Attack Activity — Last 7 Days"
            icon={Activity}
            className="h-full"
          >
            <Timeline data={dashboard.attack_timeline} height={220} />
          </ChartCard>
        </div>

        {/* Activity Stream — real recent detections */}
        <ChartCard
          title="Activity Stream"
          icon={Wifi}
          action={<span className="chip">LIVE</span>}
          className="h-full"
        >
          {recent.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 gap-2">
              <Shield className="w-8 h-8" style={{ color: 'var(--text-muted)', opacity: 0.4 }} />
              <p className="text-xs text-center" style={{ color: 'var(--text-muted)' }}>
                No threat events yet.<br />Upload a CSV or PCAP to begin analysis.
              </p>
            </div>
          ) : (
            <div className="space-y-0 -mx-1">
              {recent.slice(0, 6).map((ev, i) => (
                <div
                  key={ev.id ?? i}
                  className="stream-item"
                  style={{ animationDelay: `${i * 0.07}s` }}
                >
                  <span
                    className="w-2 h-2 rounded-full flex-shrink-0 mt-0.5"
                    style={{ background: SEV_DOT[ev.severity] ?? '#4ade80' }}
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                      {ev.attack_type}
                    </p>
                    {ev.source_ip && (
                      <p className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
                        {ev.source_ip}
                      </p>
                    )}
                  </div>
                  <span className="text-[10px] font-mono flex-shrink-0" style={{ color: 'var(--text-muted)' }}>
                    {ev.created_at ? format(new Date(ev.created_at), 'HH:mm:ss') : '—'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </ChartCard>

      </div>

      {/* ── Row 3: Attack Distribution + Severity + Top IPs ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-5">

        {/* Attack type distribution — 2/5 */}
        <div className="xl:col-span-2">
          <ChartCard
            title="Attack Distribution"
            icon={BarChart2}
            className="h-full"
          >
            <AttackChart data={dashboard.attack_distribution} />
          </ChartCard>
        </div>

        {/* Severity breakdown — 1/5 */}
        <div className="xl:col-span-1">
          <ChartCard
            title="Severity"
            icon={Target}
            className="h-full"
          >
            <SeverityChart data={dashboard.severity_distribution} />
          </ChartCard>
        </div>


        {/* Top Source IPs — 2/5 */}
        <div className="xl:col-span-2">
          <ChartCard
            title="Top Source IPs"
            icon={Globe}
            action={
              <button
                onClick={() => navigate('/ip-intelligence')}
                className="text-[11px] flex items-center gap-1 transition-colors"
                style={{ color: 'var(--text-muted)' }}
                onMouseEnter={e => e.currentTarget.style.color = '#F3E8BC'}
                onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
              >
                IP Intel <ChevronRight className="w-3 h-3" />
              </button>
            }
            className="h-full"
          >
            <TopIPsChart data={topIPs} />
          </ChartCard>
        </div>
      </div>

      {/* ── Row 4: Recent Threat Detections table ─────── */}
      <div className="glass-card overflow-hidden">
        {/* Card header */}
        <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom: '1px solid rgba(3,83,82,0.12)' }}>
          <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: '#F3E8BC' }}>
            <ShieldAlert className="w-4 h-4" style={{ color: '#F3E8BC' }} />
            Recent Threat Detections
            <span
              className="text-[10px] font-mono px-1.5 py-0.5 rounded"
              style={{ background: 'rgba(248,113,113,0.12)', border: '1px solid rgba(248,113,113,0.25)', color: '#f87171' }}
            >
              {recent.length} shown
            </span>
          </h2>
          <button
            onClick={() => navigate('/attacks')}
            className="text-xs flex items-center gap-1 transition-colors"
            style={{ color: 'var(--text-muted)' }}
            onMouseEnter={e => e.currentTarget.style.color = '#F3E8BC'}
            onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
          >
            View all <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Attack Type</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Result</th>
                <th>Method</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {recent.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-10" style={{ color: 'var(--text-muted)' }}>
                    <div className="flex flex-col items-center gap-2">
                      <Shield className="w-8 h-8" style={{ opacity: 0.3 }} />
                      <span className="text-xs">No detections yet. Upload a CSV or PCAP file to start analysis.</span>
                    </div>
                  </td>
                </tr>
              ) : recent.map(atk => (

                <tr
                  key={atk.id}
                  onClick={() => setSelected(atk)}
                  className={selected?.id === atk.id ? 'selected' : ''}
                >
                  <td className="font-mono text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                    {atk.created_at ? format(new Date(atk.created_at), 'MM/dd HH:mm') : '—'}
                  </td>
                  <td className="font-mono text-xs whitespace-nowrap" style={{ color: '#F3E8BC' }}>
                    {atk.source_ip}
                  </td>
                  <td className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>
                    {atk.attack_type}
                  </td>
                  <td>
                    <RiskBadge severity={atk.severity} />
                  </td>
                  <td>
                    <div className="flex items-center gap-2">
                      <div className="progress-bar w-14">
                        <div
                          className="progress-fill"
                          style={{ width: `${atk.confidence * 100}%`, background: '#035352' }}
                        />
                      </div>
                      <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                        {(atk.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                  </td>
                  <td>
                    <span
                      className="text-[11px] font-mono font-semibold"
                      style={{ color: atk.result === 'POTENTIAL_SUCCESS' ? '#f87171' : '#fbbf24' }}
                    >
                      {atk.result === 'POTENTIAL_SUCCESS' ? '⚡ SUCCESS' : '⚠ ATTEMPT'}
                    </span>
                  </td>
                  <td className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                    {atk.detection_method}
                  </td>
                  <td>
                    <button
                      className="text-xs px-2.5 py-1 rounded-lg transition-all"
                      style={{
                        background: 'rgba(3,83,82,0.12)',
                        border: '1px solid rgba(3,83,82,0.25)',
                        color: '#F3E8BC',
                      }}
                      onClick={e => { e.stopPropagation(); setSelected(atk); }}
                    >
                      View
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div
          className="flex items-center justify-between px-5 py-3"
          style={{ borderTop: '1px solid rgba(3,83,82,0.10)' }}
        >
          <p className="text-[11px] font-mono" style={{ color: 'var(--text-muted)' }}>
            Showing 8 of {dashboard.total_attacks} total detections
          </p>
          <button
            onClick={() => navigate('/attacks')}
            className="btn-primary text-xs px-3 py-1.5"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Explore All Attacks
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>
      </div>

      {/* Threat Detail Drawer */}
      {selected && <ThreatDrawer attack={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
