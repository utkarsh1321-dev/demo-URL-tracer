import { useRef, useState } from 'react';
import { Upload, File, X, AlertCircle } from 'lucide-react';

/**
 * @param {Function} onFile  - called with File object when selected
 * @param {string}   accept  - file accept string e.g. '.pcap,.cap'
 * @param {string}   label
 * @param {string}   hint
 */
export default function FileUpload({ onFile, accept = '.pcap,.cap', label = 'Upload File', hint = '' }) {
  const inputRef  = useRef(null);
  const [dragOver, setDragOver] = useState(false);
  const [selected, setSelected] = useState(null);
  const [error, setError]       = useState('');

  const validateAndSet = (file) => {
    setError('');
    if (!file) return;
    const ext = '.' + file.name.split('.').pop().toLowerCase();
    const allowed = accept.split(',').map(s => s.trim().toLowerCase());
    if (!allowed.includes(ext)) {
      setError(`Invalid file type. Allowed: ${accept}`);
      return;
    }
    setSelected(file);
    onFile(file);
  };

  const onDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    validateAndSet(e.dataTransfer.files[0]);
  };

  const clear = (e) => {
    e.stopPropagation();
    setSelected(null);
    setError('');
    if (inputRef.current) inputRef.current.value = '';
  };

  return (
    <div>
      <div
        className={`upload-zone ${dragOver ? 'drag-over' : ''}`}
        style={selected ? {
          borderColor: 'rgba(3,83,82,0.55)',
          background: 'rgba(3,83,82,0.10)',
        } : undefined}
        onClick={() => !selected && inputRef.current?.click()}
        onDragOver={e => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
      >
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          className="hidden"
          onChange={e => validateAndSet(e.target.files[0])}
        />

        {selected ? (
          <div className="flex flex-col items-center gap-3">
            <div
              className="w-14 h-14 rounded-xl flex items-center justify-center"
              style={{ background: 'rgba(3,83,82,0.20)', border: '1px solid rgba(3,83,82,0.40)' }}
            >
              <File className="w-7 h-7" style={{ color: '#F3E8BC' }} />
            </div>
            <div className="text-center">
              <p className="text-sm font-semibold" style={{ color: '#F3E8BC' }}>{selected.name}</p>
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
                {selected.size > 0 ? `${(selected.size / 1024).toFixed(1)} KB` : 'File'}
              </p>
            </div>
            <button onClick={clear} className="btn-secondary text-xs gap-1.5 px-3 py-1.5">
              <X className="w-3.5 h-3.5" />
              Remove
            </button>
          </div>
        ) : (
          <>
            <div
              className="w-14 h-14 rounded-xl flex items-center justify-center"
              style={{ background: 'rgba(3,83,82,0.10)', border: '1px solid rgba(3,83,82,0.25)' }}
            >
              <Upload className="w-7 h-7" style={{ color: 'var(--text-muted)' }} />
            </div>
            <div className="text-center">
              <p className="text-base font-semibold" style={{ color: 'var(--text-secondary)' }}>{label}</p>
              <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
                Drag &amp; drop or{' '}
                <span style={{ color: '#F3E8BC', textDecoration: 'underline', textUnderlineOffset: 2 }}>
                  browse
                </span>
              </p>
              {hint && <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>{hint}</p>}
              <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>Accepted: {accept}</p>
            </div>
          </>
        )}
      </div>

      {error && (
        <div className="mt-2 flex items-center gap-2 text-xs" style={{ color: '#f87171' }}>
          <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
          {error}
        </div>
      )}
    </div>
  );
}
