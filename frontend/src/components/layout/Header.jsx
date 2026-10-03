import { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { AlertTriangle, Bell, Clock, Menu, Search, Shield, Activity } from 'lucide-react';
import { format } from 'date-fns';

const PAGE_META = {
  '/':                { title: 'Dashboard',       subtitle: 'Real-time threat overview & attack intelligence' },
  '/attacks':         { title: 'Attack Explorer', subtitle: 'Browse, filter and inspect detected attacks' },
  '/ip-intelligence': { title: 'IP Intelligence', subtitle: 'Search and analyse IP risk profiles' },
  '/pcap':            { title: 'PCAP Analysis',   subtitle: 'Upload and process packet capture files' },
  '/reports':         { title: 'Reports',         subtitle: 'Export and review analysis data' },
  '/ml':              { title: 'ML Intelligence', subtitle: 'Machine-learning attack classification engine' },
};

export default function Header({ onMenuClick }) {
  const { pathname } = useLocation();
  const info = PAGE_META[pathname] ?? { title: 'URL Tracer Security', subtitle: 'Advanced threat intelligence platform' };
  const [now, setNow] = useState(new Date());

  // Tick clock every second
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <header
      className="sticky top-0 z-20 flex items-center justify-between px-4 md:px-6 py-3"
      style={{
        background: 'rgba(3, 10, 10, 0.85)',
        backdropFilter: 'blur(20px)',
        borderBottom: '1px solid rgba(3,83,82,0.18)',
        boxShadow: '0 1px 24px rgba(0,0,0,0.4)',
      }}
    >
      {/* ── Left: hamburger (mobile) + Page identity ─ */}
      <div className="flex items-center gap-3 min-w-0">
        {/* Mobile hamburger */}
        <button
          id="mobile-menu-btn"
          onClick={onMenuClick}
          aria-label="Open navigation menu"
          className="md:hidden flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center transition-all"
          style={{ background: 'rgba(3,83,82,0.12)', border: '1px solid rgba(3,83,82,0.25)' }}
        >
          <Menu className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
        </button>

        {/* Page title */}
        <div className="min-w-0">
          <h1 className="text-base md:text-lg font-bold truncate" style={{ color: 'var(--text-primary)' }}>
            {info.title}
          </h1>
          <p className="text-xs truncate hidden sm:block" style={{ color: 'var(--text-muted)' }}>
            {info.subtitle}
          </p>
        </div>
      </div>

      {/* ── Right controls ─────────────────────────── */}
      <div className="flex items-center gap-2 md:gap-3 flex-shrink-0">

        {/* System status */}
        <div
          className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg"
          style={{ background: 'rgba(3,83,82,0.08)', border: '1px solid rgba(3,83,82,0.20)' }}
        >
          <span className="live-dot" />
          <span className="text-xs font-medium" style={{ color: '#4ade80' }}>System Operational</span>
        </div>
        {/* Clock */}
        <div
          className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono"
          style={{
            background: 'rgba(3,83,82,0.08)',
            border: '1px solid rgba(3,83,82,0.20)',
            color: 'var(--text-secondary)',
          }}
        >
          <Clock className="w-3.5 h-3.5" />
          {format(now, 'dd MMM HH:mm:ss')}
        </div>

        {/* Notification bell */}
        <button
          aria-label="Notifications"
          className="relative w-9 h-9 rounded-lg flex items-center justify-center transition-all hover:border-opacity-60"
          style={{
            background: 'rgba(3,83,82,0.08)',
            border: '1px solid rgba(3,83,82,0.22)',
          }}
        >
          <Bell className="w-4 h-4" style={{ color: 'var(--text-secondary)' }} />
          <span
            className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full"
            style={{ background: '#f87171', boxShadow: '0 0 6px rgba(248,113,113,0.6)' }}
          />
        </button>

        {/* Avatar */}
        <div
          className="w-9 h-9 rounded-full flex items-center justify-center flex-shrink-0 text-xs font-bold"
          style={{
            background: 'linear-gradient(135deg, rgba(3,83,82,0.7), rgba(3,83,82,0.4))',
            border: '1px solid rgba(3,83,82,0.5)',
            color: '#F3E8BC',
          }}
        >
          NT
        </div>
      </div>
    </header>
  );
}
