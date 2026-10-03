import { Link, useLocation } from 'react-router-dom';
import { ChevronRight, Home } from 'lucide-react';

const ROUTE_LABELS = {
  '':                'Home',
  'attacks':         'Attack Explorer',
  'ip-intelligence': 'IP Intelligence',
  'pcap':            'PCAP Analysis',
  'ml':              'ML Intelligence',
  'reports':         'Reports',
  'contact':         'Contact',
  'thank-you':       'Thank You',
  'privacy':         'Privacy Policy',
};

const BASE_URL = 'https://url-tracer.example.com';

export default function Breadcrumbs() {
  const { pathname } = useLocation();

  const segments = pathname.split('/').filter(Boolean);
  const crumbs = [
    { label: 'Home', path: '/' },
    ...segments.map((seg, i) => ({
      label: ROUTE_LABELS[seg] ?? seg,
      path: '/' + segments.slice(0, i + 1).join('/'),
    })),
  ];

  if (crumbs.length <= 1) return null;

  // Inject JSON-LD BreadcrumbList schema
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: crumbs.map((c, i) => ({
      '@type': 'ListItem',
      position: i + 1,
      name: c.label,
      item: `${BASE_URL}${c.path}`,
    })),
  };

  if (typeof document !== 'undefined') {
    let el = document.getElementById('breadcrumb-schema');
    if (!el) {
      el = document.createElement('script');
      el.id = 'breadcrumb-schema';
      el.type = 'application/ld+json';
      document.head.appendChild(el);
    }
    el.textContent = JSON.stringify(schema);
  }

  return (
    <nav
      aria-label="Breadcrumb"
      className="flex items-center gap-1 px-6 py-2 text-xs overflow-x-auto whitespace-nowrap"
      style={{
        color: 'var(--text-muted)',
        borderBottom: '1px solid rgba(3,83,82,0.10)',
        background: 'rgba(3,10,10,0.4)',
      }}
    >
      {crumbs.map((crumb, i) => {
        const isLast = i === crumbs.length - 1;
        return (
          <span key={crumb.path} className="flex items-center gap-1">
            {i === 0 && <Home className="w-3 h-3 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />}
            {isLast ? (
              <span style={{ color: 'var(--text-secondary)' }} aria-current="page">
                {crumb.label}
              </span>
            ) : (
              <Link
                to={crumb.path}
                style={{ color: 'var(--text-muted)', transition: 'color 0.15s' }}
                onMouseEnter={e => e.currentTarget.style.color = '#F3E8BC'}
                onMouseLeave={e => e.currentTarget.style.color = 'var(--text-muted)'}
              >
                {crumb.label}
              </Link>
            )}
            {!isLast && (
              <ChevronRight className="w-3 h-3 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
            )}
          </span>
        );
      })}
    </nav>
  );
}
