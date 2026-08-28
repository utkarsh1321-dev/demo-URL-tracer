// src/pages/Login.jsx
// Full-screen login + signup page.
// Design matches the existing dark teal glass-card aesthetic.

import { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import { Shield, Mail, Lock, Eye, EyeOff, AlertCircle, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../auth/AuthContext';

export default function Login() {
  const { user, signIn, signUp, resetPassword, loading } = useAuth();
  const navigate = useNavigate();

  const [mode, setMode]         = useState('login');   // 'login' | 'signup' | 'reset'
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm]   = useState('');
  const [showPw, setShowPw]     = useState(false);
  const [busy, setBusy]         = useState(false);
  const [error, setError]       = useState('');
  const [success, setSuccess]   = useState('');

  // Already logged in → go to dashboard
  if (!loading && user) return <Navigate to="/" replace />;

  function clearMessages() { setError(''); setSuccess(''); }

  async function handleSubmit(e) {
    e.preventDefault();
    clearMessages();

    if (mode === 'signup' && password !== confirm) {
      setError('Passwords do not match.');
      return;
    }
    if (mode === 'signup' && password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }

    setBusy(true);
    try {
      if (mode === 'login') {
        await signIn(email, password);
        navigate('/', { replace: true });
      } else if (mode === 'signup') {
        await signUp(email, password);
        setSuccess('Account created! Check your email for a confirmation link, then log in.');
        setMode('login');
      } else {
        await resetPassword(email);
        setSuccess('Password reset email sent. Check your inbox.');
      }
    } catch (err) {
      setError(err?.message ?? 'An error occurred. Please try again.');
    } finally {
      setBusy(false);
    }
  }

  const titles = {
    login:  { heading: 'Sign in',        sub: 'Access your security dashboard' },
    signup: { heading: 'Create account', sub: 'Start analysing threats today'  },
    reset:  { heading: 'Reset password', sub: 'We\'ll send a link to your email' },
  };
  const { heading, sub } = titles[mode];

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{ background: 'var(--bg-primary)' }}
    >
      {/* Background subtle radial */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            'radial-gradient(ellipse 60% 40% at 50% 30%, rgba(3,83,82,0.15) 0%, transparent 70%)',
        }}
      />

      <div className="relative w-full max-w-md">
        {/* Logo + title */}
        <div className="flex flex-col items-center mb-8 gap-3">
          <div
            className="w-12 h-12 rounded-2xl flex items-center justify-center"
            style={{ background: 'rgba(3,83,82,0.25)', border: '1px solid rgba(3,83,82,0.4)' }}
          >
            <Shield className="w-6 h-6" style={{ color: '#035352' }} />
          </div>
          <div className="text-center">
            <h1 className="text-2xl font-bold" style={{ color: '#F3E8BC' }}>URL Tracer</h1>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
              Phishing & Cyber Attack Detection
            </p>
          </div>
        </div>

        {/* Card */}
        <div className="glass-card p-8">
          <h2 className="text-lg font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>
            {heading}
          </h2>
          <p className="text-sm mb-6" style={{ color: 'var(--text-muted)' }}>{sub}</p>

          {/* Error / Success */}
          {error && (
            <div
              className="flex items-start gap-2 rounded-lg px-3 py-2.5 text-xs mb-4"
              style={{ background: 'rgba(248,113,113,0.08)', border: '1px solid rgba(248,113,113,0.2)' }}
            >
              <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-red-400" />
              <span style={{ color: '#f87171' }}>{error}</span>
            </div>
          )}
          {success && (
            <div
              className="flex items-start gap-2 rounded-lg px-3 py-2.5 text-xs mb-4"
              style={{ background: 'rgba(74,222,128,0.08)', border: '1px solid rgba(74,222,128,0.2)' }}
            >
              <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-green-400" />
              <span style={{ color: '#4ade80' }}>{success}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                Email address
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-muted)' }} />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={e => { setEmail(e.target.value); clearMessages(); }}
                  placeholder="you@example.com"
                  className="w-full pl-9 pr-4 py-2.5 rounded-lg text-sm outline-none transition-all"
                  style={{
                    background: 'rgba(255,255,255,0.04)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    color: 'var(--text-primary)',
                  }}
                  onFocus={e => (e.target.style.border = '1px solid rgba(3,83,82,0.6)')}
                  onBlur={e  => (e.target.style.border = '1px solid rgba(255,255,255,0.08)')}
                />
              </div>
            </div>

            {/* Password */}
            {mode !== 'reset' && (
              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                  Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-muted)' }} />
                  <input
                    type={showPw ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={e => { setPassword(e.target.value); clearMessages(); }}
                    placeholder="••••••••"
                    className="w-full pl-9 pr-10 py-2.5 rounded-lg text-sm outline-none transition-all"
                    style={{
                      background: 'rgba(255,255,255,0.04)',
                      border: '1px solid rgba(255,255,255,0.08)',
                      color: 'var(--text-primary)',
                    }}
                    onFocus={e => (e.target.style.border = '1px solid rgba(3,83,82,0.6)')}
                    onBlur={e  => (e.target.style.border = '1px solid rgba(255,255,255,0.08)')}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw(p => !p)}
                    className="absolute right-3 top-1/2 -translate-y-1/2"
                    tabIndex={-1}
                  >
                    {showPw
                      ? <EyeOff className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
                      : <Eye    className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />}
                  </button>
                </div>
              </div>
            )}

            {/* Confirm password (signup only) */}
            {mode === 'signup' && (
              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                  Confirm password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-muted)' }} />
                  <input
                    type={showPw ? 'text' : 'password'}
                    required
                    value={confirm}
                    onChange={e => { setConfirm(e.target.value); clearMessages(); }}
                    placeholder="••••••••"
                    className="w-full pl-9 pr-4 py-2.5 rounded-lg text-sm outline-none transition-all"
                    style={{
                      background: 'rgba(255,255,255,0.04)',
                      border: '1px solid rgba(255,255,255,0.08)',
                      color: 'var(--text-primary)',
                    }}
                    onFocus={e => (e.target.style.border = '1px solid rgba(3,83,82,0.6)')}
                    onBlur={e  => (e.target.style.border = '1px solid rgba(255,255,255,0.08)')}
                  />
                </div>
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={busy}
              className="w-full py-2.5 rounded-lg text-sm font-semibold transition-all mt-2"
              style={{
                background: busy ? 'rgba(3,83,82,0.4)' : 'rgba(3,83,82,0.8)',
                border: '1px solid rgba(3,83,82,0.6)',
                color: '#F3E8BC',
                cursor: busy ? 'not-allowed' : 'pointer',
              }}
            >
              {busy ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-3.5 h-3.5 rounded-full border border-t-transparent animate-spin"
                        style={{ borderColor: '#F3E8BC', borderTopColor: 'transparent' }} />
                  {mode === 'login' ? 'Signing in…' : mode === 'signup' ? 'Creating account…' : 'Sending…'}
                </span>
              ) : (
                mode === 'login' ? 'Sign in' : mode === 'signup' ? 'Create account' : 'Send reset link'
              )}
            </button>
          </form>

          {/* Mode switchers */}
          <div className="mt-5 text-center space-y-2">
            {mode === 'login' && (
              <>
                <button
                  onClick={() => { setMode('reset'); clearMessages(); }}
                  className="text-xs hover:underline block mx-auto"
                  style={{ color: 'var(--text-muted)' }}
                >
                  Forgot password?
                </button>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  No account?{' '}
                  <button
                    onClick={() => { setMode('signup'); clearMessages(); }}
                    className="font-semibold hover:underline"
                    style={{ color: '#F3E8BC' }}
                  >
                    Sign up
                  </button>
                </p>
              </>
            )}
            {mode === 'signup' && (
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Already have an account?{' '}
                <button
                  onClick={() => { setMode('login'); clearMessages(); }}
                  className="font-semibold hover:underline"
                  style={{ color: '#F3E8BC' }}
                >
                  Sign in
                </button>
              </p>
            )}
            {mode === 'reset' && (
              <button
                onClick={() => { setMode('login'); clearMessages(); }}
                className="text-xs hover:underline"
                style={{ color: 'var(--text-muted)' }}
              >
                ← Back to sign in
              </button>
            )}
          </div>
        </div>

        <p className="text-center text-xs mt-4" style={{ color: 'var(--text-muted)', opacity: 0.5 }}>
          URL Tracer — Cybersecurity Research Platform
        </p>
      </div>
    </div>
  );
}
