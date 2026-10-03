import { useState, useEffect, useCallback } from 'react';
import { format, parseISO } from 'date-fns';
import {
  ChevronLeft, ChevronRight, X, Activity, Info,
  ShieldAlert, Clock, Shield, AlertTriangle, Globe, Zap
} from 'lucide-react';
import usePageMeta from '../hooks/usePageMeta.js';

import { getAttacks } from '../api/apiService.js';
import FilterBar      from '../components/common/FilterBar.jsx';
import RiskBadge      from '../components/common/RiskBadge.jsx';
import LoadingSpinner from '../components/common/LoadingSpinner.jsx';
import EmptyState     from '../components/common/EmptyState.jsx';
import ExportButton   from '../components/common/ExportButton.jsx';

const PAGE_SIZE = 12;

// ── Threat Detail Drawer ────────────────────────────────────
function AttackDetail({ attack, onClose }) {
  if (!attack) return null;

  const riskColor =
    attack.severity === 'CRITICAL' ? '#f87171' :
    attack.severity === 'HIGH'     ? '#fb923c' :
    attack.severity === 'MEDIUM'   ? '#fbbf24' : '#4ade80';

  const circumference = 2 * Math.PI * 40;
  const confidence = attack.confidence ?? 0.9;
  const offset = circumference * (1 - confidence);

  return (
    <>
      <div
        className="fixed inset-0 z-50"
        style={{ background: 'rgba(2,8,8,0.7)', backdropFilter: 'blur(4px)' }}
        onClick={onClose}
      />
      <aside className="drawer z-50">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 flex-shrink-0"
             style={{ borderBottom: '1px solid rgba(3,83,82,0.2)' }}>
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
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {/* Confidence gauge */}
          <div className="text-center py-3">
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
                <span className="text-[9px]" style={{ color: 'var(--text-muted)' }}>%</span>
              </div>
            </div>
            <h3 className="text-xl font-bold" style={{ color: '#F3E8BC' }}>{attack.attack_type}</h3>
            <p className="text-sm mt-1" style={{ color: riskColor }}>● {attack.severity}</p>
          </div>

          {/* Fields */}
          <div className="grid grid-cols-2 gap-3">
            {[
              { label: 'Source IP',   value: attack.source_ip, accent: true },
              { label: 'Timestamp',   value: format(parseISO(attack.timestamp), 'MM/dd HH:mm:ss'), mono: true },
              { label: 'Method',      value: attack.detection_method },
              { label: 'Result',
                value: attack.result === 'POTENTIAL_SUCCESS' ? '⚡ Potential Success' : '⚠ Attempt',
                color: attack.result === 'POTENTIAL_SUCCESS' ? '#f87171' : '#fbbf24' },
              { label: 'ML Confidence', value: `${(confidence * 100).toFixed(1)}%`, mono: true },
              { label: 'Severity',    custom: <RiskBadge severity={attack.severity} /> },
            ].map(({ label, value, custom, mono, accent, color }) => (
              <div key={label} className="rounded-xl p-3"
                   style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.15)' }}>
                <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>{label}</p>
                {custom ?? (
                  <p className={`text-sm font-medium ${mono ? 'font-mono' : ''}`}
                     style={{ color: accent ? '#F3E8BC' : color ?? 'var(--text-primary)' }}>
                    {value}
                  </p>
                )}
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
          <div className="rounded-xl p-3" style={{ background: 'rgba(180,30,30,0.08)', border: '1px solid rgba(180,30,30,0.2)' }}>
            <p className="text-[10px] uppercase tracking-wider mb-1.5" style={{ color: 'var(--text-muted)' }}>Payload / Indicator</p>
            <p className="text-xs font-mono break-all leading-relaxed" style={{ color: '#f87171' }}>
              {attack.payload}
            </p>
          </div>

          {/* Confidence bar */}
          <div className="rounded-xl p-3" style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.15)' }}>
            <div className="flex items-center justify-between mb-2">
              <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>ML Confidence Score</p>
              <p className="text-xs font-mono font-bold" style={{ color: '#F3E8BC' }}>{(confidence * 100).toFixed(1)}%</p>
            </div>
            <div className="progress-bar h-2">
              <div
                className="progress-fill"
                style={{
                  width: `${confidence * 100}%`,
                  background: confidence >= 0.9 ? '#f87171' : confidence >= 0.75 ? '#fb923c' : '#fbbf24',
                }}
              />
            </div>
          </div>

          {/* Detected indicators */}
          <div className="rounded-xl p-4" style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.18)' }}>
            <p className="text-xs font-semibold mb-3" style={{ color: '#F3E8BC' }}>Recommended Action</p>
            <div className="flex items-center gap-2 text-sm font-semibold" style={{ color: '#f87171' }}>
              <Shield className="w-4 h-4" />
              Block IP Address
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 flex-shrink-0" style={{ borderTop: '1px solid rgba(3,83,82,0.2)' }}>
          <button className="btn-primary w-full justify-center">
            <Shield className="w-4 h-4" />
            Block IP Address
          </button>
        </div>
      </aside>
    </>
  );
}

// ── Main ───────────────────────────────────────────────────
export default function AttackExplorer() {
  usePageMeta('Attack Explorer', 'URL Tracer Security — Browse, filter and inspect all detected URL-based cyberattacks.');
  const [attacks, setAttacks]   = useState([]);
  const [loading, setLoading]   = useState(true);
  const [selected, setSelected] = useState(null);
  const [page, setPage]         = useState(1);
  const [filters, setFilters]   = useState({
    search: '', attack_type: 'ALL', severity: 'ALL', result: 'ALL', source_ip: ''
  });

  const fetchAttacks = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getAttacks(filters);
      setAttacks(data);
      setPage(1);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => { fetchAttacks(); }, [fetchAttacks]);

  const totalPages = Math.ceil(attacks.length / PAGE_SIZE);
  const paged      = attacks.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  return (
    <div className="space-y-5 animate-fade-in">

      {/* ── Page heading ──────────────────────── */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-base font-bold flex items-center gap-2" style={{ color: '#F3E8BC' }}>
            <ShieldAlert className="w-4 h-4" />
            Attack Explorer
          </h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Browse, filter and inspect all detected URL-based cyberattacks
          </p>
        </div>
        <div className="flex items-center gap-2">
          <ExportButton type="csv" />
          <ExportButton type="json" />
        </div>
      </div>

      {/* ── Filters ────────────────────────────── */}
      <FilterBar filters={filters} onFilter={setFilters} />

      {/* ── Results summary + Table ───────── */}
      {/* Results summary strip */}
      {!loading && attacks.length > 0 && (
        <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
          <span>
            Showing <strong style={{ color: '#F3E8BC' }}>{paged.length}</strong> of{' '}
            <strong style={{ color: '#F3E8BC' }}>{attacks.length}</strong> results
          </span>
          {(filters.attack_type !== 'ALL' || filters.severity !== 'ALL' || filters.result !== 'ALL' || filters.search || filters.source_ip) && (
            <span
              className="px-2 py-0.5 rounded-md font-mono"
              style={{ background: 'rgba(243,232,188,0.08)', border: '1px solid rgba(243,232,188,0.15)', color: '#F3E8BC' }}
            >
              Filtered
            </span>
          )}
        </div>
      )}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <LoadingSpinner message="Fetching attacks..." />
        ) : attacks.length === 0 ? (
          <EmptyState title="No attacks found" message="Try adjusting your filters to see results." icon="search" />
        ) : (
          <>
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
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {paged.map(atk => (
                    <tr
                      key={atk.id}
                      onClick={() => setSelected(atk)}
                      className={selected?.id === atk.id ? 'selected' : ''}
                    >
                      <td className="font-mono text-xs whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {format(parseISO(atk.timestamp), 'MM/dd HH:mm:ss')}
                      </td>
                      <td className="font-mono text-xs whitespace-nowrap" style={{ color: '#F3E8BC' }}>
                        {atk.source_ip}
                      </td>
                      <td style={{ color: 'var(--text-primary)' }}>{atk.attack_type}</td>
                      <td><RiskBadge severity={atk.severity} /></td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div className="progress-bar w-14">
                            <div className="progress-fill" style={{ width: `${atk.confidence * 100}%`, background: '#035352' }} />
                          </div>
                          <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                            {(atk.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className="text-xs font-mono font-semibold"
                              style={{ color: atk.result === 'POTENTIAL_SUCCESS' ? '#f87171' : '#fbbf24' }}>
                          {atk.result === 'POTENTIAL_SUCCESS' ? '⚡ SUCCESS' : '⚠ ATTEMPT'}
                        </span>
                      </td>
                      <td className="text-xs" style={{ color: 'var(--text-muted)' }}>{atk.detection_method}</td>
                      <td>
                        <button
                          className="text-xs px-2.5 py-1 rounded-lg transition-all"
                          style={{ background: 'rgba(3,83,82,0.12)', border: '1px solid rgba(3,83,82,0.25)', color: '#F3E8BC' }}
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

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-5 py-3"
                   style={{ borderTop: '1px solid rgba(3,83,82,0.12)' }}>
                <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                  Page {page} of {totalPages} · {attacks.length} records
                </span>
                <div className="flex items-center gap-1">
                  <button
                    disabled={page === 1}
                    onClick={() => setPage(p => p - 1)}
                    className="btn-secondary px-2 py-1.5 disabled:opacity-40"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => i + 1).map(p => (
                    <button
                      key={p}
                      onClick={() => setPage(p)}
                      className="px-3 py-1.5 rounded-lg text-xs font-mono transition-colors"
                      style={{
                        background: p === page ? '#035352' : 'rgba(3,83,82,0.08)',
                        color: p === page ? '#F3E8BC' : 'var(--text-muted)',
                        border: `1px solid ${p === page ? 'rgba(3,83,82,0.5)' : 'rgba(3,83,82,0.15)'}`,
                      }}
                    >
                      {p}
                    </button>
                  ))}
                  <button
                    disabled={page === totalPages}
                    onClick={() => setPage(p => p + 1)}
                    className="btn-secondary px-2 py-1.5 disabled:opacity-40"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Detail drawer */}
      {selected && <AttackDetail attack={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
