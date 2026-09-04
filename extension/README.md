# URL Tracer Chrome Extension

A Chrome extension that checks the safety of the currently visited URL using URL Tracer analysis.

## Features

• Checks current website URL for safety risks
• Displays risk levels: LOW (safe), HIGH (suspicious), CRITICAL (dangerous)
• Provides actionable feedback for suspicious/critical sites
• Implements fail-safe security: API unavailability ≠ safe assumption
• No embedded secrets or credentials
• Rate limiting and request validation

## Extension Structure

```
extension/
├── manifest.json
├── background/
│   └── service-worker.js
├── content/
│   └── content.js
├── popup/
│   ├── popup.html
│   ├── popup.js
│   └── popup.css
└── icons/
    ├── icon16.png
    ├── icon32.png
    ├── icon48.png
    └── icon128.png
```

## How It Works

1. User clicks extension icon or visits a website
2. Extension obtains the current URL via `chrome.tabs.query`
3. URL is sent to background service worker
4. Background worker validates URL and sends to analysis API
5. API performs safety check (rate limiting, validation, ML analysis)
6. Result returned to extension
7. Popup displays appropriate UI based on risk level:

   **Safe (LOW Risk)**
   ```
   ✓ Website appears safe
   Risk: LOW
   ```

   **Suspicious (HIGH Risk)**
   ```
   ⚠ Potentially suspicious
   Risk: HIGH
   [Go Back] [Proceed Anyway]
   ```

   **Critical (CRITICAL Risk)**
   ```
    Dangerous Website
    Strong phishing indicators detected.
    [Leave Website]
   ```

## Security Notes

• **No secrets stored in extension**: API keys, tokens, or credentials are never included
• **Fail-safe design**: API unavailability shows warning, never assumes safety
• **Request validation**: URL format validation before API calls
• **Rate limiting**: Prevents abuse from rapid-fire requests
• **Extension-origin headers**: Backend can verify requests come from this extension

## Installation

1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions`
3. Enable "Developer mode" in top right
4. Click "Load unpacked" and select the `extension` folder
5. The URL Tracer icon will appear in your toolbar

## Usage

• Click the extension icon to check the current tab's URL
• For automatic checking on page load, the content script can be enabled
• Review results and take recommended actions

## Customization

• Update `API_URL` in `background/service-worker.js` with your actual backend endpoint
• Modify UI styles in `popup/popup.css`
• Adjust risk thresholds or behavior in popup.js and service-worker.js

## Compliance

• Manifest V3 compliant
• Follows Chrome extension best practices
• No execution of remotely hosted code
• Minimal permissions: only `tabs`, `activeTab`, and `<all_urls>` for API calls

## Note

This is a foundation implementation. For production use:
• Replace placeholder `API_URL` with your actual backend
• Implement proper backend authentication/authorization
• Add comprehensive error logging
• Consider adding user settings/configuration options
• Test with various URL formats and edge cases

---

*Built for Phase 8: Chrome Manifest V3 Extension Implementation*
*Git commit: phase-8: implement Chrome Manifest V3 extension*
