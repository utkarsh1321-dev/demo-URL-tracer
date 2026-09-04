/**
 * background/service-worker.js
 * URL Tracer Chrome Extension — Manifest V3 Service Worker
 *
 * Responsibilities:
 *   - Extension lifecycle management (install, activate)
 *   - Badge icon state updates (handled here, not in popup)
 *
 * Architecture note:
 *   API calls are made directly from popup.js (not relayed through here).
 *   Direct fetch is simpler, lower-latency, and avoids MV3 service-worker
 *   lifecycle issues with async message passing.
 *
 * Security:
 *   - No API keys, secrets, or credentials stored here.
 *   - No eval(), no dynamic code execution.
 */

'use strict';

// ── Extension lifecycle ───────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === 'install') {
    console.log('[URL Tracer] Extension installed.');
  } else if (reason === 'update') {
    console.log('[URL Tracer] Extension updated.');
  }
});
