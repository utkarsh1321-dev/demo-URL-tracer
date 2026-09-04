/**
 * background/service-worker.js
 * URL Tracer — Auto-intercept navigation to dangerous URLs.
 *
 * Flow:
 *   1. User clicks any link → tab starts loading
 *   2. Service worker fires immediately via chrome.tabs.onUpdated
 *   3. POST to /api/public/analyze (8s timeout, fail-open)
 *   4. If risk is HIGH or CRITICAL → redirect tab to warning page
 *      BEFORE the user can interact with the phishing site
 *   5. Warning page: Go Back / Proceed Anyway
 *
 * Fail-open: if the API is down or times out, navigation is NOT blocked.
 * Bypass: user-approved URLs are remembered for the browser session.
 */

'use strict';

const API_URL        = 'https://url-tracer-lsf2.onrender.com/api/public/analyze';
const TIMEOUT_MS     = 8000;
const BLOCK_LEVELS   = new Set(['HIGH', 'CRITICAL']);
const SKIP_SCHEMES   = ['chrome:', 'chrome-extension:', 'about:', 'file:', 'data:', 'javascript:', 'edge:', 'moz-extension:'];

// In-memory set of user-approved URLs (cleared when service worker restarts)
// Keyed as "tabId:url" so approval is per-tab, not global
const _approved = new Set();

// ── Main navigation listener ──────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only fire when a new navigation starts loading
  if (changeInfo.status !== 'loading') return;

  const url = tab.url || changeInfo.url || '';
  if (!url) return;

  // Skip non-HTTP URLs (browser pages, extension pages, etc.)
  if (SKIP_SCHEMES.some(s => url.startsWith(s))) return;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;

  // Skip our own warning page
  if (url.includes('warning/warning.html')) return;

  // Skip if user already approved this URL in this tab
  const key = `${tabId}:${url}`;
  if (_approved.has(key)) {
    _approved.delete(key); // One-time approval — remove after use
    return;
  }

  // ── Analyse the URL ─────────────────────────────────────────────────────
  let data;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const res = await fetch(API_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url }),
      signal:  controller.signal,
    });

    clearTimeout(timer);

    if (!res.ok) return; // Fail open — API errors don't block navigation

    data = await res.json();
  } catch {
    return; // Timeout or network error — fail open, don't block user
  }

  const risk  = (data?.risk_level ?? '').toUpperCase();
  const score = data?.risk_score ?? 0;

  // ── Redirect dangerous URLs to warning page ──────────────────────────────
  if (BLOCK_LEVELS.has(risk)) {
    const warningUrl = chrome.runtime.getURL('warning/warning.html')
      + `?url=${encodeURIComponent(url)}`
      + `&risk=${encodeURIComponent(risk)}`
      + `&score=${encodeURIComponent(score)}`
      + `&tabId=${tabId}`;

    try {
      await chrome.tabs.update(tabId, { url: warningUrl });
    } catch {
      // Tab may have been closed — ignore
    }
  }
});

// ── Message handler — "proceed anyway" from warning page ─────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'PROCEED_ANYWAY' && msg.url && msg.tabId != null) {
    // Record approval so the next onUpdated event skips analysis
    const key = `${msg.tabId}:${msg.url}`;
    _approved.add(key);
    // Navigate to the original URL
    chrome.tabs.update(msg.tabId, { url: msg.url });
    sendResponse({ ok: true });
  }
});
