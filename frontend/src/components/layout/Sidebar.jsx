import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, ShieldAlert, Globe, FileSearch,
  FileBarChart2, Brain, Mail, Lock, Shield,
  Activity, Wifi, LogOut,
} from 'lucide-react';
import { useAuth } from '../../auth/AuthContext';

const NAV_ITEMS = [
  { to: '/',                label: 'Dashboard',       icon: LayoutDashboard },
  { to: '/attacks',         label: 'Attack Explorer', icon: ShieldAlert },
  { to: '/ip-intelligence', label: 'IP Intelligence', icon: Globe },
  { to: '/pcap',            label: 'PCAP Analysis',   icon: FileSearch },
  { to: '/ml',              label: 'ML Intelligence', icon: Brain },
  { to: '/reports',         label: 'Reports',         icon: FileBarChart2 },
];

const INFO_ITEMS = [
  { to: '/contact', label: 'Contact Us',     icon: Mail },
  { to: '/privacy', label: 'Privacy Policy', icon: Lock },
];

export default function Sidebar() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const userEmail = user?.email ?? '';

  async function handleSignOut() {
    try { await signOut(); } catch (_) {}
    navigate('/login', { replace: true });
  }

  return (
    <aside className="flex flex-col w-64 min-h-screen flex-shrink-0 glass-strong relative z-10">

      {/* Top shimmer line */}
      <div className="absolute top-0 left-0 right-0 h-px"
           style={{ background: 'linear-gradient(90deg, transparent, rgba(243,232,188,0.25), transparent)' }} />

      {/* ── Logo / Brand ─────────────────────────────── */}
      <div className="flex items-center gap-3 px-5 py-6" style={{ borderBottom: '1px solid rgba(3,83,82,0.18)' }}>
        {/* Shield Icon */}
        <div className="relative flex-shrink-0">
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center animate-glow-pulse"
            style={{
              background: 'linear-gradient(135deg, rgba(3,83,82,0.6) 0%, rgba(3,83,82,0.3) 100%)',
              border: '1px solid rgba(3,83,82,0.6)',
            }}
          >
            <Shield className="w-5 h-5" style={{ color: '#F3E8BC' }} />
          </div>
          {/* Live pulse dot */}
          <span
            className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full animate-pulse-slow"
            style={{ background: '#4ade80', boxShadow: '0 0 6px rgba(74,222,128,0.6)' }}
          />
        </div>

        <div className="min-w-0">
          <span className="text-base font-bold tracking-tight truncate block" style={{ color: '#F3E8BC' }}>
            URL Tracer
          </span>
          <p className="text-[10px] font-mono tracking-widest uppercase" style={{ color: 'var(--text-muted)' }}>
            Security Platform
          </p>
        </div>
      </div>

      {/* ── Main Navigation ──────────────────────────── */}
      <nav className="flex-1 px-3 py-5 space-y-1 overflow-y-auto" aria-label="Main navigation">
        <p className="px-3 mb-3 text-[10px] font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
          Navigation
        </p>

        {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
          >
            <Icon className="w-4 h-4 flex-shrink-0" />
            <span>{label}</span>
          </NavLink>
        ))}

        {/* ── Divider ── */}
        <div className="pt-4 pb-1">
          <p className="px-3 mb-3 text-[10px] font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
            Info
          </p>
          {INFO_ITEMS.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span>{label}</span>
            </NavLink>
          ))}
        </div>
      </nav>

      {/* ── System Status Footer ─────────────────────── */}
      <div className="px-4 py-5 flex-shrink-0" style={{ borderTop: '1px solid rgba(3,83,82,0.18)' }}>
        {/* Demo mode chip */}
        <div
          className="rounded-xl p-3 mb-3"
          style={{ background: 'rgba(243,232,188,0.05)', border: '1px solid rgba(243,232,188,0.12)' }}
        >
          <p className="text-xs font-semibold mb-0.5" style={{ color: '#F3E8BC' }}>
            ⚡ Demo Mode
          </p>
          <p className="text-[10px] leading-relaxed" style={{ color: 'var(--text-muted)' }}>
            All data is synthetic &amp; simulated. Not real intelligence.
          </p>
        </div>

        {/* User info + sign out */}
        <div className="space-y-2">
          <div className="flex items-center gap-2 min-w-0">
            <Wifi className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--teal-primary)' }} />
            <span className="text-[10px] font-mono truncate" style={{ color: 'var(--text-muted)' }}>
              {userEmail || 'Connected'}
            </span>
            <span
              className="w-1.5 h-1.5 rounded-full flex-shrink-0 ml-auto animate-pulse-slow"
              style={{ background: '#4ade80' }}
            />
          </div>
          <button
            onClick={handleSignOut}
            className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg text-xs transition-all hover:opacity-80"
            style={{
              background: 'rgba(248,113,113,0.06)',
              border: '1px solid rgba(248,113,113,0.15)',
              color: '#f87171',
            }}
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign out
          </button>
        </div>
      </div>
    </aside>
  );
}
