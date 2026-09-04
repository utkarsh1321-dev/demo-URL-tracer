/**
 * popup/popup.js
 * URL Tracer Chrome Extension — Popup controller
 *
 * Flow:
 *   1. Query active tab URL via chrome.tabs API
 *   2. Skip non-HTTP/HTTPS URLs (chrome://, about:, file://, etc.)
 *   3. POST to /api/public/analyze — no credentials, IP-rate-limited backend
 *   4. Render result state (safe / suspicious / critical / error)
 *   5. Action buttons: Go Back, Proceed Anyway, Leave Website
 *
 * Security:
 *   - No API keys, tokens, or secrets in this file.
 *   - API URL is the only configurable constant — update for your deployment.
 *   - All DOM manipulation uses textContent / setAttribute (no innerHTML with data).
 *   - Fail-safe: error state never says the site is safe.
 *   - 10-second request timeout prevents hanging UI.
 *   - Rate-limit response handled explicitly (never shown as "safe").
 *
 * CONFIGURE: Update API_BASE to your deployed backend URL.
 */

'use strict';

// ─── CONFIGURE THIS ───────────────────────────────────────────────────────────
const API_BASE = 'https://url-tracer-lsf2.onrender.com/api';
// ─────────────────────────────────────────────────────────────────────────────

const ANALYZE_URL = `${API_BASE}/public/analyze`;
const TIMEOUT_MS  = 10_000;   // 10 seconds

// URL schemes that cannot be analysed
const UNSUPPORTED_SCHEMES = ['chrome:', 'chrome-extension:', 'about:', 'file:', 'data:', 'javascript:', 'edge:'];


// ── Entry point ───────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  // Get current tab
  let tab;
  try {
    const [result] = await chrome.tabs.query({ active: true, currentWindow: true });
    tab = result;
  } catch {
    showState('error', { detail: 'Could not read current tab.' });
    return;
  }

  const rawUrl = tab?.url ?? '';

  // Display URL (truncated, sanitized via textContent — no XSS risk)
  const urlText = document.getElementById('url-text');
  if (urlText) {
    urlText.textContent = truncateUrl(rawUrl, 52);
    urlText.title       = rawUrl;
  }

  // Skip unsupported URL schemes
  if (!rawUrl || UNSUPPORTED_SCHEMES.some(s => rawUrl.startsWith(s))) {
    showState('unsupported');
    return;
  }

  // Only analyse http/https
  if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
    showState('unsupported');
    return;
  }

  // Show loading state and trigger analysis
  showState('loading');
  await analyse(rawUrl, tab.id);
});


// ── Analysis ──────────────────────────────────────────────────────────────────

async function analyse(url, tabId) {
  let data;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const res = await fetch(ANALYZE_URL, {
      method:  'POST',
      headers: {
        'Content-Type':     'application/json',
        'X-Extension-Id':   'url-tracer-phishing-shield',  // Non-secret identifier for logs
      },
      body:   JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timer);

    // Rate limited
    if (res.status === 429) {
      showState('ratelimit');
      return;
    }

    // Any non-ok response is treated as an error (fail-safe)
    if (!res.ok) {
      showState('error', { detail: 'Analysis service returned an error. Do not assume this site is safe.' });
      return;
    }

    data = await res.json();

  } catch (err) {
    if (err.name === 'AbortError') {
      showState('error', { detail: 'Request timed out. Do not assume the website is safe.' });
    } else {
      // Network error (API unavailable, CORS, etc.)
      // FAIL-SAFE: explicitly tell the user we cannot verify safety
      showState('error', { detail: 'Unable to reach the analysis service. Do not assume this website is safe.' });
    }
    return;
  }

  // Render result based on risk_level from backend
  renderResult(data, tabId);
}


// ── Result rendering ──────────────────────────────────────────────────────────

function renderResult(data, tabId) {
  const level      = (data.risk_level ?? 'UNKNOWN').toUpperCase();
  const score      = data.risk_score  ?? 0;
  const confidence = data.confidence  ?? 0;
  const modelVer   = data.model_version ?? '';

  // Update model version footer
  const verEl = document.getElementById('model-version');
  if (verEl && modelVer) verEl.textContent = modelVer;

  if (level === 'LOW') {
    // Safe
    setTextById('score-safe', `Score: ${score}/100`);
    setTextById('conf-safe',  `Confidence: ${pct(confidence)}`);
    showState('safe');

  } else if (level === 'MEDIUM' || level === 'HIGH') {
    // Suspicious — show Go Back / Proceed Anyway
    setTextById('badge-suspicious', level);
    setTextById('score-suspicious', `Score: ${score}/100`);
    setTextById('conf-suspicious',  `Confidence: ${pct(confidence)}`);

    // Wire action buttons
    document.getElementById('btn-back')?.addEventListener('click', () => goBack(tabId));
    document.getElementById('btn-proceed')?.addEventListener('click', () => window.close());
    showState('suspicious');

  } else if (level === 'CRITICAL') {
    // Dangerous — show Leave Website only
    setTextById('score-critical', `Score: ${score}/100`);
    document.getElementById('btn-leave')?.addEventListener('click', () => leaveWebsite(tabId));
    showState('critical');

  } else {
    // Unknown risk level — fail-safe
    showState('error', { detail: 'Unexpected response from analysis service. Do not assume this site is safe.' });
  }
}


// ── Action handlers ───────────────────────────────────────────────────────────

async function goBack(tabId) {
  try {
    await chrome.tabs.goBack(tabId);
    window.close();
  } catch {
    // goBack may fail if there's no history — navigate to new tab
    chrome.tabs.update(tabId, { url: 'chrome://newtab' });
    window.close();
  }
}

async function leaveWebsite(tabId) {
  try {
    chrome.tabs.update(tabId, { url: 'chrome://newtab' });
    window.close();
  } catch {
    window.close();
  }
}


// ── State management ──────────────────────────────────────────────────────────

const STATES = ['loading', 'safe', 'suspicious', 'critical', 'unsupported', 'error', 'ratelimit'];

function showState(name, opts = {}) {
  STATES.forEach(s => {
    const el = document.getElementById(`state-${s}`);
    if (!el) return;
    el.classList.toggle('hidden', s !== name);
  });

  // Optional override for error detail text
  if (name === 'error' && opts.detail) {
    const detailEl = document.getElementById('error-detail');
    if (detailEl) detailEl.textContent = opts.detail;
  }
}


// ── Helpers ───────────────────────────────────────────────────────────────────

function setTextById(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function pct(v) {
  return `${Math.round((v ?? 0) * 100)}%`;
}

function truncateUrl(url, maxLen) {
  if (!url) return '';
  // Remove scheme for display
  const display = url.replace(/^https?:\/\//, '');
  return display.length > maxLen ? display.slice(0, maxLen) + '…' : display;
}
