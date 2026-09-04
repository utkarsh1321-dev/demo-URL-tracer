/**
 * warning/warning.js
 * Reads URL params, populates warning page, handles buttons.
 */

'use strict';

const params   = new URLSearchParams(window.location.search);
const origUrl  = params.get('url')   || '';
const risk     = (params.get('risk')  || 'HIGH').toUpperCase();
const score    = params.get('score') || '0';
const tabId    = parseInt(params.get('tabId') || '-1', 10);

// ── Populate page ─────────────────────────────────────────────────────────────

document.getElementById('url-text').textContent   = origUrl || 'Unknown URL';
document.getElementById('risk-level').textContent = risk;
document.getElementById('risk-score').textContent = score;

// Extra pulsing animation for CRITICAL
if (risk === 'CRITICAL') {
  document.getElementById('risk-banner').classList.add('critical');
}

// ── Go Back ───────────────────────────────────────────────────────────────────

document.getElementById('btn-back').addEventListener('click', () => {
  // Try browser back; if no history, go to new tab
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = 'chrome://newtab';
  }
});

// ── Proceed Anyway ────────────────────────────────────────────────────────────

document.getElementById('btn-proceed').addEventListener('click', () => {
  if (!origUrl) return;

  // Ask service worker to record approval then navigate
  // This prevents the service worker from intercepting again immediately
  chrome.runtime.sendMessage(
    { type: 'PROCEED_ANYWAY', url: origUrl, tabId },
    () => {
      // Navigate after message sent (service worker will allow this URL once)
      window.location.href = origUrl;
    }
  );
});
