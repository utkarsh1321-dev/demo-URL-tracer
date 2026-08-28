// src/pages/URLAnalysis.jsx
// Phase 3: URL analysis page — submit a URL, see full analysis result.

import { useState, useEffect, useCallback } from 'react';
import {
  Search, Shield, ShieldAlert, ShieldCheck, ShieldX,
  ChevronDown, ChevronUp, Clock, Trash2, AlertCircle,
  CheckCircle2, Info, Zap,
} from 'lucide-react';
import { analyzeURL, getAnalysisHistory, deleteAnalysis } from '../api/apiService';

// ─── Risk level helpers ───────────────────────────────────────────────────────

const RISK_CONFIG = {
  CRITICAL: { color: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.25)', icon: ShieldX    },
  HIGH:     { color: '#f97316', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.25)', icon: ShieldAlert },
  MEDIUM:   { color: '#eab308', bg: 'rgba(234,179,8,0.08)',  border: 'rgba(234,179,8,0.25)',  icon: ShieldAlert },
  LOW:      { color: '#22c55e', bg: 'rgba(34,197,94,0.08)',  border: 'rgba(34,197,94,0.25)',  icon: ShieldCheck },
};

const SEVERITY_COLOR = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
};

function RiskBadge({ level }) {
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.LOW;
  const Icon = cfg.icon;
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold"
      style={{ background: cfg.bg, border: `1px solid ${cfg.border}`, color: cfg.color }}
    >
      <Icon className="w-3.5 h-3.5" />
      {level}
    </span>
  );
}

function ScoreRing({ score, level }) {
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.LOW;
  const r = 36;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;

  return (
    <div className="relative flex items-center justify-center w-24 h-24">
      <svg width="96" height="96" className="-rotate-90">
        <circle cx="48" cy="48" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
        <circle
          cx="48" cy="48" r={r} fill="none"
          stroke={cfg.color} strokeWidth="8"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.6s ease' }}
        />
      </svg>
      <div className="absolute text-center">
        <p className="text-2xl font-bold" style={{ color: cfg.color }}>{score}</p>
        <p className="text-[9px]" style={{ color: 'var(--text-muted)' }}>/ 100</p>
      </div>
    </div>
  );
}


// ─── Main component ───────────────────────────────────────────────────────────

export default function URLAnalysis() {
  const [url, setUrl]           = useState('');
  const [busy, setBusy]         = useState(false);
  const [result, setResult]     = useState(null);
  const [error, setError]       = useState('');
  const [history, setHistory]   = useState([]);
  const [histLoading, setHistLoading] = useState(true);
  const [expandedFlags, setExpandedFlags] = useState(false);
  const [expandedFeatures, setExpandedFeatures] = useState(false);

  // Load history on mount
  const loadHistory = useCallback(async () => {
    setHistLoading(true);
    try {
      const data = await getAnalysisHistory({ pageSize: 10 });
      setHistory(data.items || []);
    } catch (_) {
      // History unavailable — non-fatal
    } finally {
      setHistLoading(false);
    }
  }, []);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  async function handleAnalyze(e) {
    e.preventDefault();
    if (!url.trim()) return;
    setError('');
    setResult(null);
    setBusy(true);
    try {
      const data = await analyzeURL(url.trim());
      setResult(data);
      loadHistory(); // refresh history
    } catch (err) {
      setError(err?.message ?? 'Analysis failed. Please try again.');
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete(id) {
    try {
      await deleteAnalysis(id);
      setHistory(h => h.filter(r => r.id !== id));
      if (result?.id === id) setResult(null);
    } catch (_) {}
  }

  function fillExample(exUrl) {
    setUrl(exUrl);
    setResult(null);
    setError('');
  }

  const EXAMPLES = [
    { label: 'Benign',   url: 'https://www.github.com/utkarsh1321-dev' },
    { label: 'Phishing', url: 'http://secure-paypal-login.xyz/verify?user=admin&redirect=http://evil.com' },
    { label: 'Suspicious', url: 'http://192.168.1.1/admin/login.php?next=/dashboard' },
  ];

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">

      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
          URL Analysis
        </h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
          Static phishing &amp; threat detection — no URL is visited
        </p>
      </div>

      {/* Input form */}
      <div className="glass-card p-5">
        <form onSubmit={handleAnalyze} className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-muted)' }} />
            <input
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://example.com/path?param=value"
              className="w-full pl-9 pr-4 py-2.5 rounded-lg text-sm outline-none"
              style={{
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(255,255,255,0.08)',
                color: 'var(--text-primary)',
              }}
              onFocus={e => (e.target.style.border = '1px solid rgba(3,83,82,0.6)')}
              onBlur={e  => (e.target.style.border = '1px solid rgba(255,255,255,0.08)')}
            />
          </div>
          <button
            type="submit"
            disabled={busy || !url.trim()}
            className="px-5 py-2.5 rounded-lg text-sm font-semibold transition-all flex items-center gap-2"
            style={{
              background: busy || !url.trim() ? 'rgba(3,83,82,0.3)' : 'rgba(3,83,82,0.8)',
              border: '1px solid rgba(3,83,82,0.6)',
              color: '#F3E8BC',
              cursor: busy || !url.trim() ? 'not-allowed' : 'pointer',
            }}
          >
            {busy ? (
              <>
                <span className="w-3.5 h-3.5 rounded-full border border-t-transparent animate-spin"
                      style={{ borderColor: '#F3E8BC', borderTopColor: 'transparent' }} />
                Analysing…
              </>
            ) : (
              <><Zap className="w-4 h-4" /> Analyse</>
            )}
          </button>
        </form>

        {/* Example URLs */}
        <div className="flex items-center gap-2 mt-3">
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Try:</span>
          {EXAMPLES.map(ex => (
            <button
              key={ex.label}
              onClick={() => fillExample(ex.url)}
              className="text-xs px-2 py-0.5 rounded"
              style={{
                background: 'rgba(255,255,255,0.05)',
                border: '1px solid rgba(255,255,255,0.1)',
                color: 'var(--text-secondary)',
              }}
            >
              {ex.label}
            </button>
          ))}
        </div>

        {/* Error */}
        {error && (
          <div className="flex items-start gap-2 mt-3 rounded-lg px-3 py-2.5 text-xs"
               style={{ background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)' }}>
            <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-red-400" />
            <span style={{ color: '#f87171' }}>{error}</span>
          </div>
        )}
      </div>

      {/* Analysis result */}
      {result && (
        <div className="glass-card p-6 space-y-5">
          {/* Summary row */}
          <div className="flex items-start gap-6">
            <ScoreRing score={result.risk_score} level={result.risk_level} />
            <div className="flex-1 space-y-2">
              <div className="flex items-center gap-3">
                <RiskBadge level={result.risk_level} />
                <span className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
                  {result.prediction}
                </span>
              </div>
              <p className="text-xs font-mono truncate max-w-lg" style={{ color: 'var(--text-muted)' }}>
                {result.url}
              </p>
              <div className="flex gap-4 text-xs" style={{ color: 'var(--text-muted)' }}>
                <span>Confidence: <strong style={{ color: 'var(--text-secondary)' }}>{(result.confidence * 100).toFixed(0)}%</strong></span>
                <span>Rules triggered: <strong style={{ color: 'var(--text-secondary)' }}>{result.rule_flags.length}</strong></span>
                <span>Analysed in: <strong style={{ color: 'var(--text-secondary)' }}>{result.analysis_time_ms.toFixed(1)} ms</strong></span>
                <span>Model: <strong style={{ color: 'var(--text-secondary)' }}>{result.model_version}</strong></span>
              </div>
            </div>
          </div>

          {/* Rule flags */}
          {result.rule_flags.length > 0 && (
            <div>
              <button
                onClick={() => setExpandedFlags(v => !v)}
                className="flex items-center gap-2 text-sm font-semibold w-full text-left py-1"
                style={{ color: 'var(--text-secondary)' }}
              >
                <ShieldAlert className="w-4 h-4" />
                {result.rule_flags.length} Rule{result.rule_flags.length !== 1 ? 's' : ''} Triggered
                {expandedFlags ? <ChevronUp className="w-4 h-4 ml-auto" /> : <ChevronDown className="w-4 h-4 ml-auto" />}
              </button>
              {expandedFlags && (
                <div className="mt-2 space-y-2">
                  {result.rule_flags.map(flag => (
                    <div
                      key={flag.rule_id}
                      className="rounded-lg px-3 py-2.5"
                      style={{
                        background: `${SEVERITY_COLOR[flag.severity]}08`,
                        border: `1px solid ${SEVERITY_COLOR[flag.severity]}25`,
                      }}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                              style={{ background: `${SEVERITY_COLOR[flag.severity]}15`, color: SEVERITY_COLOR[flag.severity] }}>
                          {flag.severity}
                        </span>
                        <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>
                          {flag.rule_id}
                        </span>
                        {flag.matched_value && (
                          <span className="text-[10px] font-mono ml-auto" style={{ color: 'var(--text-muted)' }}>
                            {flag.matched_value}
                          </span>
                        )}
                      </div>
                      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{flag.description}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {result.rule_flags.length === 0 && (
            <div className="flex items-center gap-2 text-sm"
                 style={{ color: '#22c55e' }}>
              <CheckCircle2 className="w-4 h-4" />
              No suspicious patterns detected
            </div>
          )}

          {/* Feature breakdown */}
          <div>
            <button
              onClick={() => setExpandedFeatures(v => !v)}
              className="flex items-center gap-2 text-sm font-semibold w-full text-left py-1"
              style={{ color: 'var(--text-secondary)' }}
            >
              <Info className="w-4 h-4" />
              Feature Breakdown ({Object.keys(result.features).length} features)
              {expandedFeatures ? <ChevronUp className="w-4 h-4 ml-auto" /> : <ChevronDown className="w-4 h-4 ml-auto" />}
            </button>
            {expandedFeatures && (
              <div className="mt-2 grid grid-cols-2 sm:grid-cols-3 gap-1.5">
                {Object.entries(result.features).map(([key, val]) => (
                  <div key={key} className="flex justify-between items-center px-2.5 py-1.5 rounded"
                       style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{key}</span>
                    <span className="text-[10px] font-mono font-semibold" style={{
                      color: val === true ? '#22c55e' : val === false ? 'var(--text-muted)' : 'var(--text-secondary)'
                    }}>
                      {typeof val === 'boolean' ? (val ? 'yes' : 'no') : String(val)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* History */}
      <div className="glass-card p-5">
        <h2 className="text-sm font-semibold mb-3 flex items-center gap-2" style={{ color: 'var(--text-secondary)' }}>
          <Clock className="w-4 h-4" />
          Recent Analyses
        </h2>
        {histLoading ? (
          <p className="text-xs text-center py-4" style={{ color: 'var(--text-muted)' }}>Loading…</p>
        ) : history.length === 0 ? (
          <p className="text-xs text-center py-4" style={{ color: 'var(--text-muted)' }}>
            No analyses yet. Submit a URL above.
          </p>
        ) : (
          <div className="space-y-1.5">
            {history.map(item => (
              <div key={item.id}
                   className="flex items-center gap-3 px-3 py-2 rounded-lg group"
                   style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)' }}>
                <RiskBadge level={item.risk_level} />
                <span className="text-xs truncate flex-1 font-mono" style={{ color: 'var(--text-muted)' }}>
                  {item.url}
                </span>
                <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
                  {item.risk_score}/100
                </span>
                <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
                  {item.created_at ? new Date(item.created_at).toLocaleTimeString() : ''}
                </span>
                <button
                  onClick={() => handleDelete(item.id)}
                  className="opacity-0 group-hover:opacity-100 transition-opacity"
                  title="Delete"
                >
                  <Trash2 className="w-3.5 h-3.5" style={{ color: '#f87171' }} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
