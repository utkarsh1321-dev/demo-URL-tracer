"""
analysis/rules.py
Static rule-based URL checks.

Each rule is a pure function that examines features and/or the raw URL.
Rules run independently — a URL may trigger multiple rules.

Rule severity:
  LOW      — informational; weak signal
  MEDIUM   — moderate concern; correlated with threats
  HIGH     — strong phishing/malicious indicator
  CRITICAL — near-certain malicious pattern

Rules do NOT make network calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from analysis.features import URLFeatures


# ─── Data structures ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RuleFlag:
    """A triggered rule and its context."""
    rule_id:       str             # Stable machine-readable identifier
    severity:      str             # LOW | MEDIUM | HIGH | CRITICAL
    description:   str             # Human-readable explanation
    matched_value: Optional[str]   # What triggered this rule (sanitized)

    def to_dict(self) -> dict:
        return {
            "rule_id":       self.rule_id,
            "severity":      self.severity,
            "description":   self.description,
            "matched_value": self.matched_value,
        }


# ─── Rule definitions ────────────────────────────────────────────────────────

def run_url_rules(url: str, features: URLFeatures) -> list[RuleFlag]:
    """
    Run all static rules against a URL and its extracted features.

    Parameters
    ----------
    url      : Normalized URL string (from validator)
    features : URLFeatures extracted from the same URL

    Returns
    -------
    List of triggered RuleFlag objects (may be empty for benign URLs).
    """
    flags: list[RuleFlag] = []

    # ── R01: IP-based hostname ──────────────────────────────────────────────
    if features.is_ip_host:
        flags.append(RuleFlag(
            rule_id="R01_IP_HOST",
            severity="CRITICAL",
            description=(
                "URL uses a raw IP address as the hostname instead of a domain name. "
                "Legitimate services rarely use bare IPs. Common in phishing infrastructure."
            ),
            matched_value=_extract_hostname(url),
        ))

    # ── R02: No HTTPS ───────────────────────────────────────────────────────
    if not features.has_https:
        flags.append(RuleFlag(
            rule_id="R02_NO_HTTPS",
            severity="LOW",
            description="URL uses HTTP instead of HTTPS. Credentials submitted here are transmitted in plaintext.",
            matched_value="http://",
        ))

    # ── R03: @ symbol before hostname ───────────────────────────────────────
    if features.has_at_in_url:
        flags.append(RuleFlag(
            rule_id="R03_AT_SYMBOL",
            severity="HIGH",
            description=(
                "URL contains '@' before the hostname. "
                "Browsers ignore everything before '@' — e.g., http://paypal.com@evil.com "
                "actually resolves to evil.com. Classic phishing trick."
            ),
            matched_value=_mask_credentials(url),
        ))

    # ── R04: Suspicious TLD ─────────────────────────────────────────────────
    if features.has_suspicious_tld:
        from analysis.features import _extract_tld
        from urllib.parse import urlparse
        tld = _extract_tld(urlparse(url).hostname or "")
        flags.append(RuleFlag(
            rule_id="R04_SUSPICIOUS_TLD",
            severity="HIGH",
            description=(
                f"TLD '{tld}' is commonly associated with free/disposable domain registrations "
                "favoured by phishing campaigns."
            ),
            matched_value=tld,
        ))

    # ── R05: Brand squatting ────────────────────────────────────────────────
    if features.has_brand_keyword:
        flags.append(RuleFlag(
            rule_id="R05_BRAND_SQUATTING",
            severity="CRITICAL",
            description=(
                "A known brand name appears in the hostname but this is not the brand's "
                "legitimate domain. Classic brand-impersonation / squatting attack."
            ),
            matched_value=_extract_hostname(url),
        ))

    # ── R06: Redirect/forwarding parameter ──────────────────────────────────
    if features.has_redirect_param:
        flags.append(RuleFlag(
            rule_id="R06_OPEN_REDIRECT",
            severity="HIGH",
            description=(
                "URL contains a redirect/forwarding parameter (url=, redirect=, next=, etc.). "
                "Can be exploited for open-redirect attacks that bypass URL reputation filters."
            ),
            matched_value=None,
        ))

    # ── R07: Double URL encoding ────────────────────────────────────────────
    if features.has_double_encoding:
        flags.append(RuleFlag(
            rule_id="R07_DOUBLE_ENCODING",
            severity="HIGH",
            description=(
                "URL contains double-encoded characters (%25xx — a percent-encoded percent). "
                "Used to evade WAF and URL scanners."
            ),
            matched_value=None,
        ))

    # ── R08: Base64 payload in query ────────────────────────────────────────
    if features.has_base64_in_query:
        flags.append(RuleFlag(
            rule_id="R08_BASE64_QUERY",
            severity="MEDIUM",
            description=(
                "A query parameter value appears to be base64-encoded data. "
                "May conceal payload URLs or credentials."
            ),
            matched_value=None,
        ))

    # ── R09: Punycode / homograph domain ────────────────────────────────────
    if features.has_punycode:
        flags.append(RuleFlag(
            rule_id="R09_PUNYCODE_HOMOGRAPH",
            severity="HIGH",
            description=(
                "Hostname contains punycode (xn--), indicating an internationalized domain. "
                "Used in homograph attacks where Unicode characters visually mimic ASCII letters."
            ),
            matched_value=_extract_hostname(url),
        ))

    # ── R10: Excessive subdomain depth ──────────────────────────────────────
    if features.num_subdomains >= 4:
        flags.append(RuleFlag(
            rule_id="R10_EXCESSIVE_SUBDOMAINS",
            severity="MEDIUM",
            description=(
                f"Hostname has {features.num_subdomains} subdomain levels. "
                "Attackers use deep subdomain chains to push the real domain out of the visible URL bar."
            ),
            matched_value=_extract_hostname(url),
        ))

    # ── R11: Long subdomain segment ─────────────────────────────────────────
    if _has_long_subdomain(url):
        flags.append(RuleFlag(
            rule_id="R11_LONG_SUBDOMAIN",
            severity="MEDIUM",
            description=(
                "Hostname contains an unusually long subdomain segment (>30 chars). "
                "May be used to push the real TLD off-screen."
            ),
            matched_value=_extract_hostname(url),
        ))

    # ── R12: Excessive hyphens in domain ────────────────────────────────────
    if features.num_hyphens >= 3:
        flags.append(RuleFlag(
            rule_id="R12_EXCESSIVE_HYPHENS",
            severity="MEDIUM",
            description=(
                f"Hostname contains {features.num_hyphens} hyphens. "
                "Legitimate domains rarely have more than 1-2 hyphens."
            ),
            matched_value=_extract_hostname(url),
        ))

    # ── R13: Suspicious keywords in hostname ────────────────────────────────
    if features.has_suspicious_keyword:
        flags.append(RuleFlag(
            rule_id="R13_SUSPICIOUS_KEYWORD",
            severity="HIGH",
            description=(
                "Hostname contains a security-sensitive keyword (login, secure, verify, account, etc.). "
                "Frequently used in phishing domains to appear trustworthy."
            ),
            matched_value=_extract_hostname(url),
        ))

    # ── R14: Excessive URL length ────────────────────────────────────────────
    if features.url_length > 500:
        flags.append(RuleFlag(
            rule_id="R14_LONG_URL",
            severity="MEDIUM",
            description=(
                f"URL is {features.url_length} characters long. "
                "Very long URLs often conceal malicious components after the visible portion."
            ),
            matched_value=f"{features.url_length} chars",
        ))

    # ── R15: High URL entropy ────────────────────────────────────────────────
    if features.url_entropy > 4.5:
        flags.append(RuleFlag(
            rule_id="R15_HIGH_ENTROPY",
            severity="MEDIUM",
            description=(
                f"URL entropy is {features.url_entropy:.2f} (threshold: 4.5). "
                "Random-looking URLs are typical of auto-generated phishing pages or C2 beacons."
            ),
            matched_value=f"entropy={features.url_entropy:.2f}",
        ))

    # ── R16: Many encoded characters ────────────────────────────────────────
    if features.num_encoded_chars > 10:
        flags.append(RuleFlag(
            rule_id="R16_EXCESSIVE_ENCODING",
            severity="MEDIUM",
            description=(
                f"URL contains {features.num_encoded_chars} percent-encoded characters. "
                "Heavy encoding is used to obfuscate payloads."
            ),
            matched_value=f"{features.num_encoded_chars} encoded chars",
        ))

    # ── R17: data: URI in query ─────────────────────────────────────────────
    if features.has_data_uri:
        flags.append(RuleFlag(
            rule_id="R17_DATA_URI",
            severity="CRITICAL",
            description=(
                "URL contains a 'data:' URI embedded in a query parameter. "
                "Used for content injection and drive-by download attacks."
            ),
            matched_value=None,
        ))

    # ── R18: High digit ratio in hostname ───────────────────────────────────
    if features.hostname_digit_ratio > 0.4 and not features.is_ip_host:
        flags.append(RuleFlag(
            rule_id="R18_HIGH_DIGIT_RATIO",
            severity="MEDIUM",
            description=(
                f"Hostname has a high digit ratio ({features.hostname_digit_ratio:.0%}). "
                "Algorithmically generated domain names tend to have more digits."
            ),
            matched_value=f"{features.hostname_digit_ratio:.0%} digits",
        ))

    return flags


# ─── Private helpers ─────────────────────────────────────────────────────────

def _extract_hostname(url: str) -> Optional[str]:
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def _mask_credentials(url: str) -> Optional[str]:
    """Return hostname only, masking any credentials in netloc."""
    from urllib.parse import urlparse
    try:
        p = urlparse(url)
        return p.hostname
    except Exception:
        return None


def _has_long_subdomain(url: str) -> bool:
    """Return True if any subdomain segment is longer than 30 characters."""
    from urllib.parse import urlparse
    try:
        hostname = urlparse(url).hostname or ""
        parts = hostname.split(".")
        if len(parts) <= 2:
            return False
        # Check all but the last two parts (domain + TLD)
        return any(len(p) > 30 for p in parts[:-2])
    except Exception:
        return False
