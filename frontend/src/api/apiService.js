// ──────────────────────────────────────────────────────────────────────────────
// Central API Service
// All calls go to the real FastAPI backend with JWT auth header.
//
// Phase 2: Authorization: Bearer {jwt} injected on every protected call.
// Phase 3: URL analysis endpoint will be added here.
// ──────────────────────────────────────────────────────────────────────────────

import { supabase } from '../lib/supabase';

// Backend base URL — set VITE_API_URL in .env.local for local dev
const _BASE = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL}/api`
  : '/api';   // Vite proxy fallback (vite.config.js → target: localhost:8000)

// ─── Auth header ───────────────────────────────────────────────────────────────
async function _authHeader() {
  const { data } = await supabase.auth.getSession();
  const token = data?.session?.access_token;
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// ─── Core HTTP helper ──────────────────────────────────────────────────────────
async function request(path, options = {}) {
  const auth = await _authHeader();
  const res = await fetch(`${_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...auth, ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const msg = res.status === 401
      ? 'Session expired. Please log in again.'
      : res.status === 404
        ? 'Resource not found.'
        : res.status >= 500
          ? 'Server error. Please try again later.'
          : `Request failed (${res.status}).`;
    throw new Error(msg);
  }
  return res.json();
}

// ─── Dashboard ─────────────────────────────────────────────────────────────────
/**
 * GET /api/dashboard
 * Returns aggregate stats for the dashboard.
 */
export async function getDashboard() {
  return request('/dashboard');
}

// ─── Attacks ───────────────────────────────────────────────────────────────────
/**
 * GET /api/attacks
 * Returns paginated list of detections with optional filters.
 * @param {Object} filters - { attack_type, severity, result, source_ip, page, page_size }
 */
export async function getAttacks(filters = {}) {
  const params = new URLSearchParams(
    Object.fromEntries(Object.entries(filters).filter(([, v]) => v != null && v !== ''))
  );
  return request(`/attacks?${params}`);
}

/**
 * GET /api/attacks/:id
 * Returns a single attack by ID.
 */
export async function getAttackById(id) {
  return request(`/attacks/${id}`);
}

// ─── IPs ───────────────────────────────────────────────────────────────────────
/**
 * GET /api/ips
 * Returns list of all tracked IP profiles.
 */
export async function getIPs() {
  return request('/ips');
}

/**
 * GET /api/ips/:ip
 * Returns profile for a specific IP address.
 */
export async function getIPDetail(ip) {
  return request(`/ips/${encodeURIComponent(ip)}`);
}

// ─── Top Source IPs ────────────────────────────────────────────────────────────
/**
 * Derives top attacking IPs from the IP list endpoint.
 */
export async function getTopSourceIPs(limit = 6) {
  const data = await request('/ips');
  const items = Array.isArray(data) ? data : (data.items ?? []);
  return items
    .filter(ip => ip.attack_count > 0)
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, limit);
}

// ─── File Uploads ──────────────────────────────────────────────────────────────
// ─── URL Analysis (Phase 3) ────────────────────────────────────────────────────

/**
 * POST /api/analyze
 * Analyse a single URL for phishing/malicious content.
 * Primary endpoint as of Phase 5.
 */
export async function analyzeURL(url) {
  return request('/analyze', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });
}

/**
 * GET /api/analyze/history
 * Returns the authenticated user's URL analysis history.
 */
export async function getAnalysisHistory({ page = 1, pageSize = 20, riskLevel } = {}) {
  const params = new URLSearchParams({ page, page_size: pageSize });
  if (riskLevel) params.set('risk_level', riskLevel);
  return request(`/analyze/history?${params}`);
}

/**
 * GET /api/analyze/stats
 * Returns URL-analysis-specific dashboard statistics for the authenticated user.
 * Phase 6: Used by Dashboard to show real URL analysis data.
 */
export async function getURLStats() {
  return request('/analyze/stats');
}

/**
 * DELETE /api/analyze/history/:id
 * Delete a specific URL analysis record.
 */
export async function deleteAnalysis(id) {
  return request(`/analyze/history/${id}`, { method: 'DELETE' });
}

// ─── File uploads ─────────────────────────────────────────────────────────────
export async function uploadCSV(file) {
  const auth = await _authHeader();
  const form = new FormData();
  form.append('file', file);
  // No Content-Type header — browser sets multipart/form-data with boundary
  return request('/upload/csv', { method: 'POST', headers: { ...auth }, body: form });
}

/**
 * POST /api/upload/pcap
 * Uploads a PCAP file for analysis.
 */
export async function uploadPCAP(file) {
  const auth = await _authHeader();
  const form = new FormData();
  form.append('file', file);
  return request('/upload/pcap', { method: 'POST', headers: { ...auth }, body: form });
}

// ─── Exports ───────────────────────────────────────────────────────────────────
/**
 * GET /api/export/csv
 * Returns all detections as a CSV string.
 */
export async function exportCSV() {
  const res = await fetch(`${_BASE}/export/csv`);
  if (!res.ok) throw new Error(`Export failed (${res.status}).`);
  return res.text();
}

/**
 * GET /api/export/json
 * Returns full analysis data as JSON.
 */
export async function exportJSON() {
  return request('/export/json');
}

// ─── ML Intelligence ───────────────────────────────────────────────────────────
/**
 * GET /api/ml/status
 * Returns ML model availability and metadata.
 */
export async function getMLStatus() {
  return request('/ml/status');
}

/**
 * POST /api/ml/predict
 * Run a single HTTP request through the classifier.
 */
export async function predictML(requestData) {
  return request('/ml/predict', {
    method: 'POST',
    body: JSON.stringify(requestData),
  });
}

/**
 * GET /api/ml/metrics
 * Returns evaluation metrics from the last training run.
 */
export async function getMLMetrics() {
  return request('/ml/metrics');
}
