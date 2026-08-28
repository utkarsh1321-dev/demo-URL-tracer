import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider }  from './auth/AuthContext';
import PrivateRoute      from './auth/PrivateRoute';
import Layout            from './components/layout/Layout.jsx';
import Login             from './pages/Login.jsx';
import Dashboard         from './pages/Dashboard.jsx';
import AttackExplorer    from './pages/AttackExplorer.jsx';
import IPIntelligence    from './pages/IPIntelligence.jsx';
import PCAPAnalysis      from './pages/PCAPAnalysis.jsx';
import Reports           from './pages/Reports.jsx';
import MLIntelligence    from './pages/MLIntelligence.jsx';
import Contact           from './pages/Contact.jsx';
import ThankYou          from './pages/ThankYou.jsx';
import PrivacyPolicy     from './pages/PrivacyPolicy.jsx';
import NotFound          from './pages/NotFound.jsx';

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* ── Public routes ─────────────────────────────────────────── */}
          <Route path="/login"     element={<Login />} />
          <Route path="/contact"   element={<Contact />} />
          <Route path="/thank-you" element={<ThankYou />} />
          <Route path="/privacy"   element={<PrivacyPolicy />} />

          {/* ── Protected routes (auth required) ──────────────────────── */}
          <Route
            element={
              <PrivateRoute>
                <Layout />
              </PrivateRoute>
            }
          >
            <Route path="/"                element={<Dashboard />} />
            <Route path="/attacks"         element={<AttackExplorer />} />
            <Route path="/ip-intelligence" element={<IPIntelligence />} />
            <Route path="/pcap"            element={<PCAPAnalysis />} />
            <Route path="/reports"         element={<Reports />} />
            <Route path="/ml"              element={<MLIntelligence />} />
          </Route>

          {/* ── 404 ───────────────────────────────────────────────────── */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
