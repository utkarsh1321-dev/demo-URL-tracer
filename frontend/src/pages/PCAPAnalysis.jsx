import { useState, useEffect } from 'react';
import { format } from 'date-fns';
import {
  Upload, Play, CheckCircle2, Circle, Loader2,
  FileSearch, Wifi, Shield, AlertTriangle, Globe,
  Clock, ChevronDown, ChevronUp, Trash2, History
} from 'lucide-react';

import { uploadPCAP, getPCAPHistory, deletePCAPAnalysis } from '../api/apiService.js';
import usePageMeta from '../hooks/usePageMeta.js';
import RiskBadge  from '../components/common/RiskBadge.jsx';\nimport FileUpload from '../components/common/FileUpload.jsx';

// ── Processing stages ───────────────────────────────────────
const STAGES = [
  { id: 'upload',   label: 'File Received',            icon: Upload },
  { id: 'parse',    label: 'Parsing PCAP packets',     icon: FileSearch },
  { id: 'extract',  label: 'Extracting HTTP requests', icon: Wifi },
  { id: 'ml',       label: 'Running ML classifier',    icon: Shield },
  { id: 'complete', label: 'Analysis Complete',         icon: CheckCircle2 },
];

// Minimum ms to show each stage so the pipeline feels real
const STAGE_DELAYS = [400, 600, 700, 800, 0];

// ── Processing Step ─────────────────────────────────────────
function ProcessingStep({ stage, status }) {
  const { label, icon: Icon } = stage;
  return (
    <div className="flex items-center gap-4">
      <div className={`step-icon ${status}`}>
        {status === 'active' ? (
          <Loader2 className="w-4 h-4 animate-spin" />
        ) : status === 'done' ? (
          <CheckCircle2 className="w-4 h-4" />
        ) : (
          <Circle className="w-4 h-4" />
        )}
      </div>
      <span className="text-sm font-medium"
            style={{
              color: status === 'done' ? '#F3E8BC' : status === 'active' ? 'var(--text-primary)' : 'var(--text-muted)'
            }}>
        {label}
      </span>
      {status === 'active' && (
        <span className="text-xs font-mono animate-pulse" style={{ color: 'var(--text-muted)' }}>
          processing...
        </span>
      )}
    </div>
  );
}

// ── Result Stat Card ─────────────────────────────────────────
function ResultCard({ icon: Icon, label, value, accentColor = '#035352' }) {
  return (
    <div className="glass-card-hover p-4 flex items-center gap-4"
         style={{ border: `1px solid ${accentColor}30` }}>
      <div className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0"
           style={{ background: `${accentColor}18` }}>
        <Icon className="w-5 h-5" style={{ color: accentColor }} />
      </div>
      <div>
        <p className="text-xs uppercase tracking-wider mb-0.5" style={{ color: 'var(--text-muted)' }}>{label}</p>
        <p className="text-2xl font-bold num-display" style={{ color: '#F3E8BC' }}>{(value ?? 0).toLocaleString()}</p>
      </div>
    </div>
  );
}

// ── History Row ──────────────────────────────────────────────
function HistoryRow({ item, onDelete }) {
  const [expanded, setExpanded] = useState(false);
  const riskColor = item.high_risk_urls > 0 ? '#f87171'
    : item.suspicious_urls > 0 ? '#fbbf24' : '#4ade80';

  return (
    <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(3,83,82,0.18)' }}>
      {/* Summary row */}
      <div
        className="flex items-center gap-4 px-4 py-3 cursor-pointer"
        style={{ background: 'rgba(3,83,82,0.06)' }}
        onClick={() => setExpanded(e => !e)}
      >
        <FileSearch className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium truncate" style={{ color: '#F3E8BC' }}>{item.filename}</p>
          <p className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
            {item.packets_analyzed.toLocaleString()} pkts · {item.urls_extracted} URLs · {item.processing_time_ms.toFixed(0)}ms
          </p>
        </div>
        <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded flex-shrink-0"
          style={{ color: riskColor, background: `${riskColor}15`, border: `1px solid ${riskColor}30` }}>
          {item.high_risk_urls} HIGH
        </span>
        <span className="text-[10px] font-mono flex-shrink-0" style={{ color: 'var(--text-muted)' }}>
          {item.created_at ? format(new Date(item.created_at), 'MM/dd HH:mm') : '—'}
        </span>
        <button
          onClick={e => { e.stopPropagation(); onDelete(item.id); }}
          className="p-1 rounded flex-shrink-0"
          style={{ color: 'var(--text-muted)' }}
          title="Delete"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
        {expanded ? <ChevronUp className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
                  : <ChevronDown className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />}
      </div>

      {/* Expanded stats */}
      {expanded && (
        <div className="px-4 py-3 grid grid-cols-3 gap-3 text-center" style={{ borderTop: '1px solid rgba(3,83,82,0.12)' }}>
          {[
            { l: 'Packets',    v: item.packets_analyzed },
            { l: 'HTTP Req',   v: item.http_requests },
            { l: 'URLs',       v: item.urls_extracted },
            { l: 'Unique IPs', v: item.unique_ips },
            { l: 'Suspicious', v: item.suspicious_urls, c: '#fbbf24' },
            { l: 'High Risk',  v: item.high_risk_urls,  c: '#f87171' },
          ].map(({ l, v, c }) => (
            <div key={l}>
              <p className="text-[10px] uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>{l}</p>
              <p className="text-lg font-bold num-display" style={{ color: c ?? '#F3E8BC' }}>{v}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main Component ───────────────────────────────────────────
export default function PCAPAnalysis() {
  usePageMeta('PCAP Analysis', 'URL Tracer Security — Upload PCAP files for automated HTTP extraction and URL threat detection.');
  const [file, setFile]             = useState(null);
  const [processing, setProcessing] = useState(false);
  const [stageIdx, setStageIdx]     = useState(-1);
  const [result, setResult]         = useState(null);
  const [error, setError]           = useState('');
  const [history, setHistory]       = useState([]);
  const [historyLoading, setHistoryLoading] = useState(true);

  const loadHistory = async () => {
    try {
      const resp = await getPCAPHistory({ pageSize: 10 });
      setHistory(resp.items ?? []);
    } catch {
      // non-fatal
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => { loadHistory(); }, []);

  const runAnalysis = async (pcapFile) => {
    setProcessing(true);
    setResult(null);
    setError('');
    setStageIdx(0);

    // Animate stages while the real upload is happening concurrently
    const animateStages = async () => {
      for (let i = 0; i < STAGES.length - 1; i++) {
        setStageIdx(i);
        await new Promise(r => setTimeout(r, STAGE_DELAYS[i]));
      }
    };

    try {
      const [data] = await Promise.all([
        uploadPCAP(pcapFile),
        animateStages(),
      ]);
      setStageIdx(STAGES.length - 1);   // Complete
      await new Promise(r => setTimeout(r, 300));
      setResult(data);
      loadHistory();
    } catch (err) {
      const msg = err?.message?.includes('413') ? 'File too large. Maximum 50 MB.'
        : err?.message?.includes('422') ? 'Invalid PCAP file. Please upload a valid .pcap or .pcapng capture.'
        : 'Analysis failed. Please try again.';
      setError(msg);
      setStageIdx(-1);
    } finally {
      setProcessing(false);
    }
  };

  const handleDelete = async (id) => {
    try {
      await deletePCAPAnalysis(id);
      setHistory(h => h.filter(item => item.id !== id));
    } catch {
      // non-fatal
    }
  };

  const RISK_COLOR = s => s === 'CRITICAL' ? '#f87171' : s === 'HIGH' ? '#fb923c'
    : s === 'MEDIUM' ? '#fbbf24' : '#4ade80';

  return (
    <div className="space-y-5 animate-fade-in">

      {/* ── Page heading ───────────────────── */}
      <div>
        <h1 className="text-base font-bold flex items-center gap-2" style={{ color: '#F3E8BC' }}>
          <FileSearch className="w-4 h-4" />
          PCAP Analysis
        </h1>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
          Upload a PCAP capture to extract HTTP requests, analyse each URL through the ML engine, and detect threats
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* ── Upload panel ──────────────────────────── */}
        <div className="glass-card p-5 space-y-4">
          <h2 className="text-sm font-semibold flex items-center gap-2" style={{ color: '#F3E8BC' }}>
            <Upload className="w-4 h-4" />
            Upload PCAP File
          </h2>

          <FileUpload
            onFile={(f) => { setFile(f); }}
            accept=".pcap,.cap,.pcapng"
            label="Drop PCAP file here"
            hint="Supports .pcap, .cap, .pcapng — max 50 MB"
          />

          <button
            onClick={() => file && runAnalysis(file)}
            disabled={!file || processing}
            className="btn-primary w-full justify-center disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {processing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {processing ? 'Analysing...' : 'Analyse PCAP'}
          </button>

          {/* File info */}
          {file && (
            <div className="rounded-xl px-4 py-3 flex items-center gap-3"
                 style={{ background: 'rgba(3,83,82,0.10)', border: '1px solid rgba(3,83,82,0.22)' }}>
              <FileSearch className="w-4 h-4 flex-shrink-0" style={{ color: '#F3E8BC' }} />
              <div className="min-w-0">
                <p className="text-xs font-medium truncate" style={{ color: '#F3E8BC' }}>{file.name}</p>
                <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
                  {(file.size / 1024).toFixed(1)} KB
                </p>
              </div>
            </div>
          )}
        </div>

        {/* ── Processing pipeline ───────────────────── */}
        <div className="glass-card p-5">
          <h2 className="text-sm font-semibold mb-6 flex items-center gap-2" style={{ color: '#F3E8BC' }}>
            <Shield className="w-4 h-4" />
            Processing Pipeline
          </h2>
          <div className="space-y-5">
            {STAGES.map((stage, i) => {
              const status = i < stageIdx ? 'done' : i === stageIdx ? 'active' : 'pending';
              return <ProcessingStep key={stage.id} stage={stage} status={status} />;
            })}
          </div>

          {stageIdx === STAGES.length - 1 && !processing && result && (
            <div className="mt-5 flex items-center gap-2 text-xs rounded-lg p-3"
                 style={{ background: 'rgba(3,83,82,0.12)', border: '1px solid rgba(3,83,82,0.30)' }}>
              <CheckCircle2 className="w-4 h-4" style={{ color: '#F3E8BC' }} />
              <span style={{ color: '#F3E8BC' }}>
                Analysis complete — {result.processing_time_ms?.toFixed(0)}ms
              </span>
            </div>
          )}

          {error && (
            <div className="mt-5 flex items-center gap-2 text-xs rounded-lg p-3"
                 style={{ background: 'rgba(180,30,30,0.10)', border: '1px solid rgba(180,30,30,0.25)' }}>
              <AlertTriangle className="w-4 h-4" style={{ color: '#f87171' }} />
              <span style={{ color: '#f87171' }}>{error}</span>
            </div>
          )}

          {stageIdx === -1 && !error && (
            <p className="text-xs font-mono text-center mt-6" style={{ color: 'var(--text-muted)' }}>
              Upload a PCAP file to begin
            </p>
          )}
        </div>
      </div>

      {/* ── Results ────────────────────────────────────── */}
      {result && (
        <div className="space-y-5 animate-fade-in">
          {/* Summary cards */}
          <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
            <ResultCard icon={FileSearch} label="Packets"      value={result.packets_analyzed}  accentColor="#035352" />
            <ResultCard icon={Wifi}       label="HTTP Requests" value={result.http_requests}     accentColor="#04817f" />
            <ResultCard icon={Globe}      label="URLs Found"   value={result.urls_extracted}    accentColor="#F3E8BC" />
            <ResultCard icon={Globe}      label="Unique IPs"   value={result.unique_ips}        accentColor="#a78bfa" />
            <ResultCard icon={AlertTriangle} label="Suspicious" value={result.suspicious_urls}  accentColor="#fbbf24" />
            <ResultCard icon={Shield}     label="High Risk"    value={result.high_risk_urls}    accentColor="#f87171" />
          </div>

          {/* Per-URL results table */}
          {(result.records ?? []).length > 0 && (
            <div className="glass-card overflow-hidden">
              <div className="section-header">
                <h3 className="section-title flex items-center gap-2">
                  <Shield className="w-4 h-4" style={{ color: '#F3E8BC' }} />
                  URL Analysis Results
                  <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                    ({result.records.length} shown)
                  </span>
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Source IP</th>
                      <th>URL</th>
                      <th>Method</th>
                      <th>Prediction</th>
                      <th>Risk Score</th>
                      <th>Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.records.slice(0, 50).map((rec, i) => (
                      <tr key={i}>
                        <td className="font-mono text-xs whitespace-nowrap" style={{ color: '#F3E8BC' }}>
                          {rec.source_ip || '—'}
                        </td>
                        <td className="font-mono text-xs max-w-[200px] truncate" style={{ color: 'var(--text-secondary)' }}
                          title={rec.url}>
                          {rec.url?.replace(/^https?:\/\//, '').slice(0, 45)}{(rec.url?.length ?? 0) > 45 ? '…' : ''}
                        </td>
                        <td className="text-[11px] font-mono" style={{ color: 'var(--text-muted)' }}>
                          {rec.method || '—'}
                        </td>
                        <td>
                          <span
                            className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded"
                            style={{
                              color: rec.prediction === 'PHISHING' || rec.prediction === 'MALWARE'
                                ? '#f87171' : '#4ade80',
                              background: rec.prediction === 'PHISHING' || rec.prediction === 'MALWARE'
                                ? 'rgba(248,113,113,0.1)' : 'rgba(74,222,128,0.1)',
                              border: `1px solid ${rec.prediction === 'PHISHING' || rec.prediction === 'MALWARE'
                                ? 'rgba(248,113,113,0.25)' : 'rgba(74,222,128,0.25)'}`,
                            }}
                          >
                            {rec.prediction || 'UNKNOWN'}
                          </span>
                        </td>
                        <td>
                          <div className="flex items-center gap-2">
                            <div className="progress-bar w-12">
                              <div
                                className="progress-fill"
                                style={{
                                  width: `${rec.risk_score ?? 0}%`,
                                  background: RISK_COLOR(rec.risk_level),
                                }}
                              />
                            </div>
                            <span className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                              {rec.risk_score ?? 0}
                            </span>
                          </div>
                        </td>
                        <td className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                          {Math.round((rec.confidence ?? 0) * 100)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── History ────────────────────────────────────── */}
      <div className="glass-card overflow-hidden">
        <div className="section-header">
          <h3 className="section-title flex items-center gap-2">
            <History className="w-4 h-4" style={{ color: '#F3E8BC' }} />
            PCAP Analysis History
          </h3>
        </div>
        <div className="p-4 space-y-2">
          {historyLoading ? (
            <p className="text-xs text-center py-6" style={{ color: 'var(--text-muted)' }}>
              Loading history...
            </p>
          ) : history.length === 0 ? (
            <div className="flex flex-col items-center gap-2 py-8">
              <FileSearch className="w-8 h-8" style={{ color: 'var(--text-muted)', opacity: 0.35 }} />
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>No PCAP analyses yet.</p>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Upload a .pcap file to begin.
              </p>
            </div>
          ) : (
            history.map(item => (
              <HistoryRow key={item.id} item={item} onDelete={handleDelete} />
            ))
          )}
        </div>
      </div>

    </div>
  );
}
