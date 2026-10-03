import { useState } from 'react';
import { format, parseISO } from 'date-fns';
import {
  FileDown, FileJson, FileText, ShieldAlert, Globe,
  CheckCircle2, AlertTriangle, ChevronDown, ChevronUp, Info,
  Activity
} from 'lucide-react';

import { mockDashboard, mockAttacks, mockIPProfiles } from '../mock/mockData.js';
import ExportButton from '../components/common/ExportButton.jsx';
import RiskBadge    from '../components/common/RiskBadge.jsx';
import StatCard     from '../components/common/StatCard.jsx';
import usePageMeta  from '../hooks/usePageMeta.js';

// ── Collapsible Section ─────────────────────────────────────
function Section({ title, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="glass-card overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-5 py-4 transition-colors"
        style={{ color: 'var(--text-primary)' }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(3,83,82,0.06)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        <span className="text-sm font-semibold" style={{ color: '#F3E8BC' }}>{title}</span>
        {open
          ? <ChevronUp className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          : <ChevronDown className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        }
      </button>
      {open && (
        <div style={{ borderTop: '1px solid rgba(3,83,82,0.15)' }}>
          {children}
        </div>
      )}
    </div>
  );
}

export default function Reports() {
  usePageMeta('Reports', 'URL Tracer Security — Export and review detection reports, attack logs, and IP intelligence data.');
  const successCount = mockAttacks.filter(a => a.result === 'POTENTIAL_SUCCESS').length;
  const critCount    = mockAttacks.filter(a => a.severity === 'CRITICAL').length;
  const ipProfiles   = Object.values(mockIPProfiles);
  const highRiskIPs  = ipProfiles.filter(ip => ['HIGH','CRITICAL'].includes(ip.risk_level));

  return (
    <div className="space-y-5 animate-fade-in">

      {/* ── Page heading ───────────────────── */}
      <div>
        <h1 className="text-base font-bold flex items-center gap-2" style={{ color: '#F3E8BC' }}>
          <FileDown className="w-4 h-4" />
          Reports & Export
        </h1>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Summary statistics and data export for the current analysis session
        </p>
      </div>

      {/* ── Notice ─────────────────────────── */}
      <div className="flex items-center gap-2 text-xs rounded-lg px-4 py-2.5"
           style={{ background: 'rgba(243,232,188,0.05)', border: '1px solid rgba(243,232,188,0.12)' }}>
        <Info className="w-4 h-4 flex-shrink-0" style={{ color: '#F3E8BC' }} />
        <span style={{ color: 'var(--text-muted)' }}>
          Exported data reflects the current analysis session. A metadata header is embedded in every export.
        </span>
      </div>

      {/* ── Export Actions ─────────────────────────────── */}
      <div className="glass-card p-5">
        <h2 className="text-sm font-semibold mb-5 flex items-center gap-2" style={{ color: '#F3E8BC' }}>
          <FileDown className="w-4 h-4" />
          Export Analysis Data
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* CSV export */}
          <div className="rounded-xl p-4 flex items-start gap-4"
               style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.20)' }}>
            <div className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0"
                 style={{ background: 'rgba(3,83,82,0.20)', border: '1px solid rgba(3,83,82,0.35)' }}>
              <FileText className="w-6 h-6" style={{ color: '#F3E8BC' }} />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold mb-0.5" style={{ color: '#F3E8BC' }}>Attack Log — CSV</p>
              <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>
                {mockAttacks.length} records · id, timestamp, source_ip, attack_type, severity, confidence, result, method
              </p>
              <ExportButton type="csv" label="Download CSV" />
            </div>
          </div>

          {/* JSON export */}
          <div className="rounded-xl p-4 flex items-start gap-4"
               style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.20)' }}>
            <div className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0"
                 style={{ background: 'rgba(243,232,188,0.10)', border: '1px solid rgba(243,232,188,0.20)' }}>
              <FileJson className="w-6 h-6" style={{ color: '#F3E8BC' }} />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold mb-0.5" style={{ color: '#F3E8BC' }}>Full Analysis — JSON</p>
              <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>
                Attacks + IP profiles + dashboard summary + metadata + disclaimer
              </p>
              <ExportButton type="json" label="Download JSON" />
            </div>
          </div>
        </div>
      </div>

      {/* ── Summary Stats ─────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Attacks"       value={mockAttacks.length}  icon={ShieldAlert}   color="red"    />
        <StatCard label="Potential Successes" value={successCount}        icon={CheckCircle2}  color="orange" />
        <StatCard label="Critical Severity"   value={critCount}           icon={AlertTriangle} color="red"    />
        <StatCard label="IPs Tracked"         value={ipProfiles.length}   icon={Globe}         color="teal"   />
      </div>

      {/* ── Attack Log Preview ─────────────────────────── */}
      <Section title={`Attack Log Preview (${mockAttacks.length} records)`} defaultOpen>
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Attack Type</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {mockAttacks.slice(0, 10).map(atk => (
                <tr key={atk.id}>
                  <td className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{atk.id}</td>
                  <td className="font-mono text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                    {format(parseISO(atk.timestamp), 'MM/dd HH:mm')}
                  </td>
                  <td className="font-mono text-xs whitespace-nowrap" style={{ color: '#F3E8BC' }}>{atk.source_ip}</td>
                  <td className="whitespace-nowrap" style={{ color: 'var(--text-primary)' }}>{atk.attack_type}</td>
                  <td><RiskBadge severity={atk.severity} /></td>
                  <td className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>
                    {(atk.confidence * 100).toFixed(0)}%
                  </td>
                  <td>
                    <span className="text-xs font-mono"
                          style={{ color: atk.result === 'POTENTIAL_SUCCESS' ? '#f87171' : '#fbbf24' }}>
                      {atk.result === 'POTENTIAL_SUCCESS' ? '⚡ SUCCESS' : '⚠ ATTEMPT'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="text-xs font-mono text-center py-3"
             style={{ color: 'var(--text-muted)', borderTop: '1px solid rgba(3,83,82,0.12)' }}>
            Showing 10 of {mockAttacks.length} records — download CSV for full dataset
          </p>
        </div>
      </Section>

      {/* ── IP Risk Profiles ───────────────────────────── */}
      <Section title={`IP Risk Profiles (${ipProfiles.length} IPs)`}>
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Risk Score</th>
                <th>Risk Level</th>
                <th>Requests</th>
                <th>Attacks</th>
                <th>Attack Types</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {ipProfiles.map(ip => (
                <tr key={ip.ip}>
                  <td className="font-mono text-xs" style={{ color: '#F3E8BC' }}>{ip.ip}</td>
                  <td>
                    <div className="flex items-center gap-2">
                      <div className="progress-bar w-16">
                        <div
                          className="progress-fill"
                          style={{
                            width: `${ip.risk_score}%`,
                            background: ip.risk_score >= 85 ? '#f87171' : ip.risk_score >= 65 ? '#fb923c' : '#fbbf24',
                          }}
                        />
                      </div>
                      <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{ip.risk_score}</span>
                    </div>
                  </td>
                  <td><RiskBadge severity={ip.risk_level} /></td>
                  <td className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{ip.total_requests}</td>
                  <td className="font-mono text-xs" style={{ color: 'var(--text-muted)' }}>{ip.attack_count}</td>
                  <td>
                    <div className="flex flex-wrap gap-1">
                      {ip.attack_types.slice(0, 2).map(t => (
                        <span key={t} className="chip text-[10px]">{t}</span>
                      ))}
                      {ip.attack_types.length > 2 && (
                        <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
                          +{ip.attack_types.length - 2}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="font-mono text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                    {format(parseISO(ip.last_seen), 'MM/dd HH:mm')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      {/* ── JSON Preview ───────────────────────────────── */}
      <Section title="JSON Export Preview">
        <div className="p-5">
          <pre
            className="text-xs font-mono overflow-x-auto leading-relaxed max-h-72 p-4 rounded-xl"
            style={{
              background: 'rgba(3,83,82,0.06)',
              border: '1px solid rgba(3,83,82,0.18)',
              color: '#F3E8BC',
            }}
          >
{`{
  "metadata": {
    "exported_at": "${new Date().toISOString()}",
    "data_type": "LIVE_DATA",
    "total_attacks": ${mockAttacks.length},
    "disclaimer": "Exported from URL Tracer Security platform. Handle in accordance with your organisation's data policy."
  },
  "attacks": [ ... ${mockAttacks.length} records ... ],
  "ip_profiles": [ ... ${ipProfiles.length} profiles ... ],
  "dashboard_summary": {
    "total_requests": ${mockDashboard.total_requests},
    "total_attacks":  ${mockDashboard.total_attacks},
    "high_risk_ips":  ${mockDashboard.high_risk_ips},
    "potential_successes": ${mockDashboard.potential_successes}
  }
}`}
          </pre>
        </div>
      </Section>
    </div>
  );
}
