import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { CheckCircle2, Home, ShieldAlert, ArrowRight } from 'lucide-react';
import usePageMeta from '../hooks/usePageMeta';

const REDIRECT_AFTER = 10;

export default function ThankYou() {
  usePageMeta(
    'Thank You — Enquiry Received',
    'Your enquiry has been received. The URL Tracer Security team will get back to you shortly.'
  );

  const navigate = useNavigate();
  const [countdown, setCountdown] = useState(REDIRECT_AFTER);

  useEffect(() => {
    if (countdown <= 0) { navigate('/'); return; }
    const t = setTimeout(() => setCountdown(c => c - 1), 1000);
    return () => clearTimeout(t);
  }, [countdown, navigate]);

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4"
      style={{ background: 'var(--bg-base)' }}
    >
      <div className="text-center max-w-md mx-auto animate-fade-in">

        {/* Animated check ring */}
        <div className="flex items-center justify-center mb-6">
          <div className="relative">
            <div
              className="w-24 h-24 rounded-full flex items-center justify-center animate-glow-pulse"
              style={{
                background: 'rgba(3,83,82,0.15)',
                border: '2px solid rgba(3,83,82,0.50)',
              }}
            >
              <CheckCircle2 className="w-12 h-12" style={{ color: '#F3E8BC' }} />
            </div>
            {/* Ripple */}
            <div
              className="absolute inset-0 rounded-full animate-ping"
              style={{ border: '2px solid rgba(3,83,82,0.25)' }}
            />
          </div>
        </div>

        <h1 className="text-3xl font-bold mb-3" style={{ color: '#F3E8BC' }}>Thank You!</h1>
        <p className="text-sm leading-relaxed mb-2" style={{ color: 'var(--text-secondary)' }}>
          Your enquiry has been received successfully.
          We'll get back to you as soon as possible.
        </p>
        <p className="text-xs font-mono mb-8" style={{ color: 'var(--text-muted)' }}>
          STATUS: SUBMITTED · NO_REAL_DATA_STORED
        </p>

        {/* Countdown */}
        <div
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono mb-8"
          style={{ background: 'rgba(3,83,82,0.10)', border: '1px solid rgba(3,83,82,0.25)', color: 'var(--text-secondary)' }}
        >
          <span
            className="w-2 h-2 rounded-full animate-pulse-slow"
            style={{ background: '#F3E8BC' }}
          />
          Redirecting to dashboard in {countdown}s…
        </div>

        {/* CTAs */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
          <Link to="/" id="thankyou-home" className="btn-primary px-6 py-2.5">
            <Home className="w-4 h-4" />
            Go to Dashboard
          </Link>
          <Link to="/attacks" id="thankyou-attacks" className="btn-secondary px-6 py-2.5">
            <ShieldAlert className="w-4 h-4" />
            Explore Attacks
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

      </div>
    </div>
  );
}
