import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Send, User, Mail, Building2, MessageSquare, Shield, ChevronRight, Loader2 } from 'lucide-react';
import usePageMeta from '../hooks/usePageMeta';

export default function Contact() {
  usePageMeta(
    'Contact Us',
    'Get in touch with the URL Tracer Security team. Submit an enquiry about our cyber attack detection platform.'
  );

  const navigate = useNavigate();
  const [form, setForm]         = useState({ name: '', email: '', org: '', message: '' });
  const [errors, setErrors]     = useState({});
  const [submitting, setSubmitting] = useState(false);

  const validate = () => {
    const e = {};
    if (!form.name.trim())    e.name    = 'Name is required';
    if (!form.email.trim())   e.email   = 'Email is required';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) e.email = 'Invalid email address';
    if (!form.message.trim()) e.message = 'Message is required';
    return e;
  };

  const handleChange = (e) => {
    setForm(f => ({ ...f, [e.target.name]: e.target.value }));
    if (errors[e.target.name]) setErrors(er => ({ ...er, [e.target.name]: undefined }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const errs = validate();
    if (Object.keys(errs).length) { setErrors(errs); return; }
    setSubmitting(true);
    await new Promise(r => setTimeout(r, 900));
    setSubmitting(false);
    navigate('/thank-you');
  };

  const labelStyle = { color: 'var(--text-muted)', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', display: 'block', marginBottom: 6 };
  const errorStyle = { color: '#f87171', fontSize: 12, marginTop: 4 };

  return (
    <div
      className="min-h-screen flex items-center justify-center px-4 py-12"
      style={{ background: 'var(--bg-base)' }}
    >
      <div className="w-full max-w-lg animate-fade-in">

        {/* Header */}
        <div className="text-center mb-8">
          <div
            className="inline-flex items-center justify-center w-14 h-14 rounded-2xl mb-4 animate-glow-pulse"
            style={{
              background: 'rgba(3,83,82,0.20)',
              border: '1px solid rgba(3,83,82,0.45)',
            }}
          >
            <Shield className="w-7 h-7" style={{ color: '#F3E8BC' }} />
          </div>
          <h1 className="text-2xl font-bold mb-2" style={{ color: '#F3E8BC' }}>Get in Touch</h1>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            Questions or feedback? Reach out and we'll respond shortly.
          </p>
          <nav aria-label="breadcrumb" className="flex items-center justify-center gap-1.5 mt-3 text-xs"
               style={{ color: 'var(--text-muted)' }}>
            <Link
              to="/"
              style={{ color: 'var(--text-muted)', transition: 'color 0.15s' }}
              onMouseEnter={e => e.currentTarget.style.color = '#F3E8BC'}
              onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
            >
              Home
            </Link>
            <ChevronRight className="w-3 h-3" />
            <span style={{ color: 'var(--text-secondary)' }}>Contact</span>
          </nav>
        </div>

        {/* Form card */}
        <div className="glass-card p-6 md:p-8 space-y-5">
          <form onSubmit={handleSubmit} noValidate className="space-y-5">

            {/* Name */}
            <div>
              <label style={labelStyle}>Full Name *</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none"
                      style={{ color: 'var(--text-muted)' }} />
                <input
                  id="contact-name"
                  name="name"
                  type="text"
                  autoComplete="name"
                  value={form.name}
                  onChange={handleChange}
                  placeholder="Your full name"
                  className="cyber-input pl-10"
                  style={errors.name ? { borderColor: '#f87171' } : undefined}
                />
              </div>
              {errors.name && <p style={errorStyle}>{errors.name}</p>}
            </div>

            {/* Email */}
            <div>
              <label style={labelStyle}>Email Address *</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none"
                      style={{ color: 'var(--text-muted)' }} />
                <input
                  id="contact-email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  value={form.email}
                  onChange={handleChange}
                  placeholder="you@organisation.com"
                  className="cyber-input pl-10"
                  style={errors.email ? { borderColor: '#f87171' } : undefined}
                />
              </div>
              {errors.email && <p style={errorStyle}>{errors.email}</p>}
            </div>

            {/* Organisation */}
            <div>
              <label style={labelStyle}>Organisation</label>
              <div className="relative">
                <Building2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 pointer-events-none"
                            style={{ color: 'var(--text-muted)' }} />
                <input
                  id="contact-org"
                  name="org"
                  type="text"
                  autoComplete="organization"
                  value={form.org}
                  onChange={handleChange}
                  placeholder="Company / Institute (optional)"
                  className="cyber-input pl-10"
                />
              </div>
            </div>

            {/* Message */}
            <div>
              <label style={labelStyle}>Message *</label>
              <div className="relative">
                <MessageSquare className="absolute left-3 top-3.5 w-4 h-4 pointer-events-none"
                                style={{ color: 'var(--text-muted)' }} />
                <textarea
                  id="contact-message"
                  name="message"
                  rows={4}
                  value={form.message}
                  onChange={handleChange}
                  placeholder="Tell us about your enquiry..."
                  className="cyber-input pl-10 resize-none"
                  style={errors.message ? { borderColor: '#f87171' } : undefined}
                />
              </div>
              {errors.message && <p style={errorStyle}>{errors.message}</p>}
            </div>

            {/* Submit */}
            <button
              id="contact-submit"
              type="submit"
              disabled={submitting}
              className="w-full btn-primary justify-center py-3 text-base disabled:opacity-60 disabled:cursor-not-allowed"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Sending…
                </>
              ) : (
                <>
                  <Send className="w-4 h-4" />
                  Send Enquiry
                </>
              )}
            </button>
          </form>

          {/* Privacy notice */}
          <p className="text-center text-[11px]" style={{ color: 'var(--text-muted)' }}>
            Your enquiry is handled securely.{' '}
            <Link
              to="/privacy"
              style={{ color: '#F3E8BC', textDecoration: 'underline' }}
              onMouseEnter={e => e.currentTarget.style.opacity = '0.75'}
              onMouseLeave={e => e.currentTarget.style.opacity = '1'}
            >
              Privacy Policy
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
