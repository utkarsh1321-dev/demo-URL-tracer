import { Download, Loader2 } from 'lucide-react';
import { useState } from 'react';
import { exportCSV, exportJSON } from '../../api/apiService.js';

function downloadBlob(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/**
 * @param {'csv'|'json'} type
 * @param {string}       [label]
 * @param {string}       [className]
 */
export default function ExportButton({ type, label, className = '' }) {
  const [loading, setLoading] = useState(false);

  const handleExport = async () => {
    setLoading(true);
    try {
      if (type === 'csv') {
        const csv = await exportCSV();
        downloadBlob(csv, 'URL_Tracer_attacks.csv', 'text/csv');
      } else {
        const json = await exportJSON();
        downloadBlob(JSON.stringify(json, null, 2), 'URL_Tracer_analysis.json', 'application/json');
      }
    } catch (err) {
      console.error('Export failed:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleExport}
      disabled={loading}
      className={`btn-secondary disabled:opacity-60 disabled:cursor-not-allowed ${className}`}
    >
      {loading ? (
        <Loader2 className="w-4 h-4 animate-spin" />
      ) : (
        <Download className="w-4 h-4" />
      )}
      {label ?? (type === 'csv' ? 'Export CSV' : 'Export JSON')}
    </button>
  );
}
