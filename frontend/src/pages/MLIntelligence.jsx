import { useState, useEffect } from 'react';
import {
  Brain, Cpu, CheckCircle2, XCircle, AlertTriangle, RefreshCw,
  BarChart3, Layers, Zap, Info, ChevronRight, Activity
} from 'lucide-react';
import { format, parseISO } from 'date-fns';
import { getMLStatus, predictML, getMLMetrics } from '../api/apiService.js';
import usePageMeta from '../hooks/usePageMeta.js';
import LoadingSpinner from '../components/common/LoadingSpinner.jsx';

// ── Metric Card ─────────────────────────────────────────────
function MetricCard({ label, value, color = 'teal', unit = '%' }) {
  const pct = unit === '%' ? (value * 100).toFixed(1) : value;
  const colors = {
    teal:   { text: '#F3E8BC', bg: 'rgba(3,83,82,0.15)',    border: 'rgba(3,83,82,0.30)' },
    green:  { text: '#4ade80', bg: 'rgba(20,120,60,0.12)',  border: 'rgba(20,120,60,0.25)' },
    orange: { text: '#fb923c', bg: 'rgba(180,90,15,0.12)',  border: 'rgba(180,90,15,0.25)' },
    purple: { text: '#c084fc', bg: 'rgba(120,40,180,0.12)', border: 'rgba(120,40,180,0.25)' },
  };
  const c = colors[color] ?? colors.teal;

  return (
    <div
      className="rounded-xl p-4 flex flex-col gap-1"
      style={{ background: c.bg, border: `1px solid ${c.border}` }}
    >
      <span className="text-xs font-mono uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{label}</span>
      <span className="text-3xl font-bold num-display" style={{ color: c.text }}>
        {pct}{unit}
      </span>
    </div>
  );
}

// ── Confidence Bar ──────────────────────────────────────────
function ConfidenceBar({ value, attack }) {
  const pct = Math.round(value * 100);
  const color = pct >= 85 ? '#f87171' : pct >= 70 ? '#fb923c' : pct >= 55 ? '#fbbf24' : 'var(--text-muted)';
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs font-mono w-40 truncate" style={{ color: 'var(--text-secondary)' }}>{attack}</span>
      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'rgba(3,83,82,0.12)' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, background: color }} />
      </div>
      <span className="text-xs font-mono w-10 text-right" style={{ color: 'var(--text-muted)' }}>{pct}%</span>
    </div>
  );
}

// Example URLs for the interactive ML prediction tester.
// These are preset inputs to help users test the classifier —
// they are NOT real attack data displayed as statistics.
const EXAMPLE_PAYLOADS = [
  { label: 'SQL Injection',       url: "/search?id=1' UNION SELECT username,password FROM users--", method: 'GET'  },
  { label: 'XSS',                 url: "/comment?text=<script>alert(document.cookie)</script>",     method: 'POST' },
  { label: 'Directory Traversal', url: "/download?file=../../etc/passwd",                            method: 'GET'  },
  { label: 'Command Injection',   url: "/ping?host=127.0.0.1;cat /etc/passwd",                      method: 'GET'  },
  { label: 'SSRF',                url: "/fetch?url=http://169.254.169.254/latest/meta-data/",        method: 'GET'  },
  { label: 'Normal Request',      url: "/api/v1/products?category=electronics&page=2",               method: 'GET'  },
];


export default function MLIntelligence() {
  usePageMeta('ML Intelligence', 'URL Tracer Security — Machine-learning attack classification engine and URL predictor.');
  const [status,  setStatus]  = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);

  const [customUrl,    setCustomUrl]    = useState('');
  const [customMethod, setCustomMethod] = useState('GET');
  const [predicting,   setPredicting]   = useState(false);
  const [prediction,   setPrediction]   = useState(null);
  const [history,      setHistory]      = useState([]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [s, m] = await Promise.all([getMLStatus(), getMLMetrics()]);
      setStatus(s);
      setMetrics(m);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadData(); }, []);

  const runPredict = async (url = customUrl, method = customMethod) => {
    if (!url.trim()) return;
    setPredicting(true);
    setPrediction(null);
    try {
      const result = await predictML({ url, method });
      setPrediction(result);
      setHistory(prev => [{ url, method, result, ts: new Date().toISOString() }, ...prev].slice(0, 8));
    } catch (err) {
      console.error(err);
    } finally {
      setPredicting(false);
    }
  };

  if (loading) return <LoadingSpinner message="Loading ML Intelligence..." />;

  const isAvailable = status?.ml_available;

  const predictionIsNormal = prediction?.prediction === 'Normal' || prediction?.prediction === 'Benign';
  const predictionIsLow    = prediction?.prediction === 'LOW_CONFIDENCE';
  const predColor = predictionIsNormal ? '#4ade80' : predictionIsLow ? '#fbbf24' : '#f87171';
  const predBg    = predictionIsNormal ? 'rgba(20,120,60,0.10)' : predictionIsLow ? 'rgba(160,130,10,0.10)' : 'rgba(180,30,30,0.10)';
  const predBorder= predictionIsNormal ? 'rgba(20,120,60,0.25)' : predictionIsLow ? 'rgba(160,130,10,0.25)' : 'rgba(180,30,30,0.25)';

  return (
    <div className="space-y-6 animate-fade-in">

      {/* ── Header ────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold flex items-center gap-2" style={{ color: '#F3E8BC' }}>
            <Brain className="w-5 h-5" style={{ color: '#F3E8BC' }} />
            ML Intelligence
            <span className="text-[10px] font-mono rounded px-2 py-0.5 ml-1"
                  style={{ background: 'rgba(243,232,188,0.10)', border: '1px solid rgba(243,232,188,0.20)', color: '#F3E8BC' }}>
              PROTOTYPE
            </span>
          </h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Random Forest classifier · 13 attack classes · Synthetic training data
          </p>
        </div>
        <button onClick={loadData} className="btn-secondary text-xs gap-1.5 px-3 py-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {/* ── Disclaimer ────────────────────────────────── */}
      <div className="flex items-start gap-2 text-xs rounded-lg px-4 py-3"
           style={{ background: 'rgba(243,232,188,0.05)', border: '1px solid rgba(243,232,188,0.15)' }}>
        <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" style={{ color: '#F3E8BC' }} />
        <span style={{ color: 'var(--text-muted)' }}>
          <strong style={{ color: '#F3E8BC' }}>Prototype Prediction</strong> — This model is trained exclusively on synthetic data.
          Outputs are for demonstration only and are <strong style={{ color: '#F3E8BC' }}>not production-ready</strong>.
        </span>
      </div>

      {/* ── Model Status ──────────────────────────────── */}
      <div className="glass-card p-5">
        <h2 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: '#F3E8BC' }}>
          <Cpu className="w-4 h-4" />
          Model Status
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-wider font-mono" style={{ color: 'var(--text-muted)' }}>Status</span>
            <div className="flex items-center gap-1.5 text-sm font-semibold"
                 style={{ color: isAvailable ? '#4ade80' : '#f87171' }}>
              {isAvailable
                ? <><CheckCircle2 className="w-4 h-4" /> Active</>
                : <><XCircle className="w-4 h-4" /> Not Trained</>}
            </div>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-wider font-mono" style={{ color: 'var(--text-muted)' }}>Algorithm</span>
            <span className="text-sm font-mono" style={{ color: '#F3E8BC' }}>{status?.model_type ?? '—'}</span>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-wider font-mono" style={{ color: 'var(--text-muted)' }}>Estimators</span>
            <span className="text-sm font-mono" style={{ color: 'var(--text-primary)' }}>{status?.n_estimators ?? '—'}</span>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-[10px] uppercase tracking-wider font-mono" style={{ color: 'var(--text-muted)' }}>Classes</span>
            <span className="text-sm font-mono" style={{ color: 'var(--text-primary)' }}>{status?.n_classes ?? '—'}</span>
          </div>
        </div>

        {status?.classes && (
          <div className="mt-4 pt-4" style={{ borderTop: '1px solid rgba(3,83,82,0.15)' }}>
            <p className="text-[10px] uppercase tracking-wider font-mono mb-2" style={{ color: 'var(--text-muted)' }}>
              Detected Attack Classes
            </p>
            <div className="flex flex-wrap gap-1.5">
              {status.classes.map(cls => (
                <span key={cls} className="chip">{cls}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Evaluation Metrics ─────────────────────────── */}
      {metrics && (
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: '#F3E8BC' }}>
              <BarChart3 className="w-4 h-4" />
              Evaluation Metrics
              <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
                — Test set · {metrics.n_test_samples} samples
              </span>
            </h2>
            {metrics.trained_at && (
              <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
                Trained {format(parseISO(metrics.trained_at), 'MMM dd HH:mm')}
              </span>
            )}
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-5">
            <MetricCard label="Accuracy"  value={metrics.accuracy}  color="teal"   />
            <MetricCard label="Precision" value={metrics.precision} color="green"  />
            <MetricCard label="Recall"    value={metrics.recall}    color="orange" />
            <MetricCard label="F1 Score"  value={metrics.f1}        color="purple" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Dataset split */}
            <div>
              <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-secondary)' }}>Dataset Split</p>
              <div className="space-y-2">
                {[
                  { label: 'Training samples', value: metrics.train_size, total: metrics.train_size + metrics.test_size, color: '#035352' },
                  { label: 'Test samples',     value: metrics.test_size,  total: metrics.train_size + metrics.test_size, color: '#F3E8BC' },
                ].map(({ label, value, total, color }) => (
                  <div key={label} className="flex items-center gap-3">
                    <span className="text-xs w-36" style={{ color: 'var(--text-secondary)' }}>{label}</span>
                    <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ background: 'rgba(3,83,82,0.12)' }}>
                      <div className="h-full rounded-full" style={{ width: `${(value / total) * 100}%`, background: color }} />
                    </div>
                    <span className="text-xs font-mono w-8 text-right" style={{ color: 'var(--text-muted)' }}>{value}</span>
                  </div>
                ))}
              </div>
              <p className="text-[10px] font-mono mt-3" style={{ color: 'var(--text-muted)' }}>
                80/20 stratified train/test split · seed=42
              </p>
            </div>

            {/* Features */}
            <div>
              <p className="text-xs font-semibold mb-3" style={{ color: 'var(--text-secondary)' }}>
                Extracted Features ({metrics.features?.length ?? 13})
              </p>
              <div className="flex flex-wrap gap-1.5">
                {(metrics.features || []).map(f => (
                  <span key={f} className="chip" style={{ color: '#F3E8BC', borderColor: 'rgba(3,83,82,0.30)' }}>{f}</span>
                ))}
              </div>
            </div>
          </div>

          <p className="mt-4 text-[10px] font-mono pt-3" style={{ color: 'var(--text-muted)', borderTop: '1px solid rgba(3,83,82,0.12)' }}>
            ⚠ {metrics.disclaimer}
          </p>
        </div>
      )}

      {/* ── Live Predictor ─────────────────────────────── */}
      <div className="glass-card p-5">
        <h2 className="text-sm font-semibold mb-1 flex items-center gap-2" style={{ color: '#F3E8BC' }}>
          <Zap className="w-4 h-4" style={{ color: '#F3E8BC' }} />
          Live Predictor
          <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>— Prototype Prediction</span>
        </h2>
        <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
          Enter any URL to get a Random Forest classification. Try the preset payloads below.
        </p>

        {/* Presets */}
        <div className="flex flex-wrap gap-2 mb-4">
          {EXAMPLE_PAYLOADS.map(p => (
            <button
              key={p.label}
              onClick={() => { setCustomUrl(p.url); setCustomMethod(p.method); runPredict(p.url, p.method); }}
              className="text-[11px] px-2.5 py-1 rounded-lg transition-all"
              style={{
                background: 'rgba(3,83,82,0.10)',
                border: '1px solid rgba(3,83,82,0.25)',
                color: 'var(--text-secondary)',
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(243,232,188,0.30)'; e.currentTarget.style.color = '#F3E8BC'; }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(3,83,82,0.25)'; e.currentTarget.style.color = 'var(--text-secondary)'; }}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Custom input */}
        <div className="flex gap-2 mb-4">
          <select
            value={customMethod}
            onChange={e => setCustomMethod(e.target.value)}
            className="rounded-lg px-3 py-2 text-xs outline-none"
            style={{
              background: 'rgba(3,83,82,0.10)',
              border: '1px solid rgba(3,83,82,0.25)',
              color: '#F3E8BC',
            }}
          >
            {['GET','POST','PUT','DELETE','PATCH'].map(m => <option key={m} style={{ background: '#030e0e' }}>{m}</option>)}
          </select>
          <input
            type="text"
            value={customUrl}
            onChange={e => setCustomUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && runPredict()}
            placeholder="/api/endpoint?param=value"
            className="cyber-input flex-1 font-mono text-xs"
          />
          <button
            onClick={() => runPredict()}
            disabled={predicting || !customUrl.trim()}
            className="btn-primary text-xs disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {predicting ? 'Analyzing…' : 'Analyze'}
          </button>
        </div>

        {/* Prediction result */}
        {prediction && (
          <div
            className="rounded-xl border p-4 mb-4"
            style={{ background: predBg, border: `1px solid ${predBorder}` }}
          >
            <div className="flex items-center justify-between mb-3">
              <div>
                <p className="text-[10px] font-mono uppercase" style={{ color: 'var(--text-muted)' }}>Prediction</p>
                <p className="text-xl font-bold mt-0.5" style={{ color: predColor }}>{prediction.prediction}</p>
              </div>
              <div className="text-right">
                <p className="text-[10px] font-mono uppercase" style={{ color: 'var(--text-muted)' }}>Confidence</p>
                <p className="text-xl font-bold mt-0.5 num-display" style={{ color: '#F3E8BC' }}>
                  {(prediction.confidence * 100).toFixed(1)}%
                </p>
              </div>
            </div>
            <div className="h-2 rounded-full overflow-hidden" style={{ background: 'rgba(3,83,82,0.12)' }}>
              <div
                className="h-full rounded-full transition-all"
                style={{ width: `${prediction.confidence * 100}%`, background: predColor }}
              />
            </div>
            <div className="flex items-center justify-between mt-2">
              <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
                Model: {prediction.model} · {prediction.label}
              </span>
              <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
                threshold ≥ {status?.confidence_threshold ?? 0.55}
              </span>
            </div>
          </div>
        )}

        {/* History */}
        {history.length > 0 && (
          <div>
            <p className="text-xs font-semibold mb-2 flex items-center gap-1.5" style={{ color: 'var(--text-secondary)' }}>
              <Activity className="w-3.5 h-3.5" /> Recent Predictions
            </p>
            <div className="space-y-1.5">
              {history.map((h, i) => {
                const isNorm = h.result.prediction === 'Normal' || h.result.prediction === 'Benign';
                return (
                  <div
                    key={i}
                    className="flex items-center gap-3 px-3 py-2 rounded-lg"
                    style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.15)' }}
                  >
                    <span
                      className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded"
                      style={{
                        background: isNorm ? 'rgba(20,120,60,0.2)' : 'rgba(180,30,30,0.2)',
                        color: isNorm ? '#4ade80' : '#f87171',
                      }}
                    >
                      {h.result.prediction}
                    </span>
                    <span className="text-[11px] font-mono truncate flex-1" style={{ color: 'var(--text-muted)' }}>{h.url}</span>
                    <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
                      {(h.result.confidence * 100).toFixed(0)}%
                    </span>
                    <ChevronRight className="w-3 h-3" style={{ color: 'var(--text-muted)' }} />
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* ── Pipeline Diagram ───────────────────────────── */}
      <div className="glass-card p-5">
        <h2 className="text-sm font-semibold mb-4 flex items-center gap-2" style={{ color: '#F3E8BC' }}>
          <Layers className="w-4 h-4" />
          ML Pipeline
        </h2>
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          {[
            'Synthetic Dataset',
            'Clean & Normalize',
            'Feature Extraction (13)',
            '80/20 Train Split',
            'Random Forest (150 trees)',
            'Prediction',
            'Confidence Score',
          ].map((step, i, arr) => (
            <div key={step} className="flex items-center gap-2">
              <div
                className="px-3 py-1.5 rounded-lg"
                style={{ background: 'rgba(3,83,82,0.10)', border: '1px solid rgba(3,83,82,0.25)', color: 'var(--text-secondary)' }}
              >
                {step}
              </div>
              {i < arr.length - 1 && (
                <ChevronRight className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
              )}
            </div>
          ))}
        </div>
        <div className="mt-4 flex items-start gap-2 text-[11px]" style={{ color: 'var(--text-muted)' }}>
          <Info className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" style={{ color: '#F3E8BC' }} />
          <span>
            Rule-based detectors run first. ML supplements detections missed by rules.
            If confidence &lt; {status?.confidence_threshold ?? 0.55}, output is marked <strong style={{ color: '#F3E8BC' }}>LOW_CONFIDENCE</strong>.
          </span>
        </div>
      </div>
    </div>
  );
}
