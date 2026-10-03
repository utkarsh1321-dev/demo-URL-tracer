import { Link } from 'react-router-dom';
import { Shield, ChevronRight, FileText } from 'lucide-react';
import usePageMeta from '../hooks/usePageMeta';

export default function PrivacyPolicy() {
  usePageMeta(
    'Privacy Policy',
    'URL Tracer Security privacy policy. This platform does not collect or store real user data, credentials, or production network data.'
  );

  const sections = [
    {
      title: '1. Overview',
      body: `URL-Tracer is a URL-Based Cyber Attack Detection & IP Intelligence System. 
This application is designed to analyse network traffic patterns and detect malicious URLs. 
No real government data, production network packets, or personal information is processed without explicit authorisation.`,
    },
    {
      title: '2. Data We Collect',
      body: `This platform does NOT collect:
• Real IP addresses or network traffic (without authorisation)
• Personal credentials or authentication data
• Browser history or tracking cookies
• Any personally identifiable information (PII)

The application processes only the data you explicitly provide or upload during a session.`,
    },
    {
      title: '3. Cookies & Local Storage',
      body: `This application does not use tracking cookies. No third-party analytics (Google Analytics, Mixpanel, etc.) 
are embedded. Any state stored in the browser (e.g., session state) is temporary and contains 
no sensitive data.`,
    },
    {
      title: '4. Data Usage Disclaimer',
      body: `All IP addresses in sample analysis views are from RFC 1918 private ranges (10.x.x.x, 172.16.x.x, 192.168.x.x) 
and are used for illustrative purposes. Detection results are produced by the ML classification engine. 
No real victims, attackers, or infrastructure are identified without explicit input.`,
    },
    {
      title: '5. Third-Party Services',
      body: `This application may load fonts from Google Fonts (fonts.googleapis.com). Google's own privacy 
policy governs that interaction. No other third-party services receive any data from this application.`,
    },
    {
      title: '6. Contact & Enquiries',
      body: `If you submit a message through our contact form, it is processed locally within this 
environment only. No data is transmitted to any external server. For questions about this 
platform, use the contact form on the Contact page.`,
    },
    {
      title: '7. Changes to This Policy',
      body: `This privacy policy may be updated as the platform evolves. The last updated date is 
displayed below. Continued use of the application after changes constitutes acceptance of the 
updated policy.`,
    },
  ];

  return (
    <div className="min-h-screen bg-dark-950 px-4 py-12">
      <div className="max-w-3xl mx-auto animate-fade-in">

        {/* Header */}
        <div className="mb-8">
          <nav aria-label="breadcrumb" className="flex items-center gap-1.5 text-xs text-slate-600 mb-4">
            <Link to="/" className="hover:text-cyber-400 transition-colors">Home</Link>
            <ChevronRight className="w-3 h-3" />
            <span className="text-slate-400">Privacy Policy</span>
          </nav>

          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-xl bg-cyber-600/15 border border-cyber-500/30
                            flex items-center justify-center">
              <FileText className="w-5 h-5 text-cyber-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Privacy Policy</h1>
              <p className="text-xs text-slate-500 font-mono mt-0.5">Last updated: August 18, 2026</p>
            </div>
          </div>

          {/* Security notice */}
          <div className="flex items-start gap-3 p-4 rounded-xl bg-amber-500/8 border border-amber-500/20">
            <Shield className="w-4 h-4 text-amber-400 mt-0.5 flex-shrink-0" />
            <p className="text-xs text-amber-300/80 leading-relaxed">
              <span className="font-semibold text-amber-400">Privacy Notice:</span>{' '}
              This application does not collect real IPDR, credentials, government data,
              or user information.
            </p>
          </div>
        </div>

        {/* Sections */}
        <div className="space-y-6">
          {sections.map((s) => (
            <div key={s.title} className="glass-card p-6">
              <h2 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-cyber-400 flex-shrink-0" />
                {s.title}
              </h2>
              <p className="text-sm text-slate-400 leading-relaxed whitespace-pre-line">{s.body}</p>
            </div>
          ))}
        </div>

        {/* Footer links */}
        <div className="mt-10 pt-6 border-t border-dark-700/50 flex flex-wrap items-center gap-4 text-xs text-slate-600">
          <Link to="/" className="hover:text-cyber-400 transition-colors">← Back to Dashboard</Link>
          <Link to="/contact" className="hover:text-cyber-400 transition-colors">Contact Us</Link>
          <span className="ml-auto font-mono">URL-Tracer · Security Platform · v1.0</span>
        </div>
      </div>
    </div>
  );
}
