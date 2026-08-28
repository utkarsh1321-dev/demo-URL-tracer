"""
analysis/features.py
URL feature extraction — the authoritative feature schema.

This module is the SINGLE SOURCE OF TRUTH for all URL features.
It is used by:
  - Phase 3: URL analysis engine (inference)
  - Phase 4: ML model training (same features, same names)
  - Phase 7: PCAP pipeline URL extraction
  - Future: Chrome Extension backend

All features are computed statically — NO network calls are made.

Feature schema version: urltracer-v1
"""

from __future__ import annotations

import math
import re
import ipaddress
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, parse_qs, unquote

# ─── Constants ────────────────────────────────────────────────────────────────

# TLDs commonly associated with free/disposable registrations
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click",
    ".link", ".pw", ".cc", ".ws", ".su", ".biz", ".info",
    ".online", ".site", ".space", ".live", ".icu", ".buzz",
}

# Keywords that appear in phishing domains targeting specific services
SUSPICIOUS_DOMAIN_KEYWORDS = {
    "login", "signin", "secure", "verify", "account", "update",
    "confirm", "billing", "password", "banking", "support",
    "service", "helpdesk", "validate", "authentication", "recovery",
}

# Redirect/forwarding parameter names used in open-redirect attacks
REDIRECT_PARAMS = {"url", "redirect", "next", "return", "goto", "forward", "dest", "destination", "link"}

# Known brand names + their legitimate base domains
BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal":       {"paypal.com", "paypal.me", "paypalobjects.com"},
    "google":       {"google.com", "google.co.in", "google.co.uk", "googleapis.com", "gstatic.com"},
    "microsoft":    {"microsoft.com", "office.com", "live.com", "outlook.com", "azure.com"},
    "amazon":       {"amazon.com", "amazon.in", "amazonaws.com", "aws.amazon.com"},
    "apple":        {"apple.com", "icloud.com", "itunes.com"},
    "facebook":     {"facebook.com", "fb.com", "fbcdn.net", "instagram.com"},
    "twitter":      {"twitter.com", "x.com", "t.co"},
    "netflix":      {"netflix.com", "nflxvideo.net"},
    "linkedin":     {"linkedin.com", "licdn.com"},
    "dropbox":      {"dropbox.com", "dropboxusercontent.com"},
    "chase":        {"chase.com", "jpmorgan.com"},
    "wellsfargo":   {"wellsfargo.com"},
    "bankofamerica":{"bankofamerica.com"},
    "sbi":          {"sbi.co.in", "onlinesbi.com", "onlinesbi.sbi"},
    "hdfc":         {"hdfcbank.com"},
    "icici":        {"icicibank.com"},
}


# ─── Feature Schema ───────────────────────────────────────────────────────────

@dataclass
class URLFeatures:
    """
    Canonical URL feature vector.

    Field names are stable — changing them is a breaking change
    that requires retraining the ML model.

    Version: urltracer-v1
    """

    # ── Length features ──────────────────────────────────────────────────────
    url_length:       int    # Total URL length (chars)
    hostname_length:  int    # Length of hostname component
    path_length:      int    # Length of path component
    query_length:     int    # Length of query string

    # ── Count features ───────────────────────────────────────────────────────
    num_dots:         int    # '.' count in full URL
    num_hyphens:      int    # '-' count in hostname
    num_underscores:  int    # '_' count in full URL
    num_slashes:      int    # '/' count in path
    num_at_symbols:   int    # '@' count in URL (pre-hostname trick)
    num_digits:       int    # digit count in full URL
    num_special_chars: int   # non-alphanumeric chars in URL
    num_subdomains:   int    # subdomain depth (e.g., a.b.example.com = 2)
    path_depth:       int    # number of path segments
    query_param_count: int   # number of distinct query parameters
    num_encoded_chars: int   # %xx sequences count

    # ── Boolean flags ────────────────────────────────────────────────────────
    has_https:           bool  # scheme is https
    is_ip_host:          bool  # hostname is an IP address
    has_double_encoding: bool  # %25xx (encoded %)
    has_redirect_param:  bool  # url=/redirect=/next= in query
    has_suspicious_tld:  bool  # .xyz/.tk/.ml/etc.
    has_brand_keyword:   bool  # brand name in non-brand domain
    has_at_in_url:       bool  # @ before authority (hides real host)
    has_punycode:        bool  # xn-- internationalized domain (homograph)
    has_data_uri:        bool  # data: in query/path (content injection)
    has_base64_in_query: bool  # base64-looking value in query params
    has_suspicious_keyword: bool  # login/verify/secure in hostname

    # ── Computed ─────────────────────────────────────────────────────────────
    url_entropy:              float  # Shannon entropy of full URL string
    hostname_digit_ratio:     float  # digits / total hostname chars


def extract_features(url: str) -> URLFeatures:
    """
    Extract all URL features from a validated, normalized URL string.

    Parameters
    ----------
    url : str
        A validated URL (call validate_and_normalize() first).

    Returns
    -------
    URLFeatures dataclass with all fields populated.
    """
    parsed = urlparse(url)

    hostname    = (parsed.hostname or "").lower()
    path        = parsed.path or ""
    query       = parsed.query or ""
    netloc      = parsed.netloc or ""
    scheme      = parsed.scheme.lower()

    # ── Basic lengths ────────────────────────────────────────────────────────
    url_length      = len(url)
    hostname_length = len(hostname)
    path_length     = len(path)
    query_length    = len(query)

    # ── Counts in full URL ───────────────────────────────────────────────────
    num_dots         = url.count(".")
    num_hyphens      = hostname.count("-")
    num_underscores  = url.count("_")
    num_slashes      = path.count("/")
    num_at_symbols   = netloc.count("@")
    num_digits       = sum(c.isdigit() for c in url)
    num_special_chars = sum(not c.isalnum() and c not in "-._~:/?#[]@!$&'()*+,;=%" for c in url)

    # ── Subdomain depth ──────────────────────────────────────────────────────
    # e.g., secure.login.paypal.com → 2 subdomains above paypal.com
    # We approximate by counting dots in hostname and subtracting 1
    num_subdomains = max(0, hostname.count(".") - 1) if hostname else 0

    # ── Path depth ───────────────────────────────────────────────────────────
    path_depth = len([s for s in path.split("/") if s])

    # ── Query parameters ─────────────────────────────────────────────────────
    try:
        params = parse_qs(query, keep_blank_values=True)
    except Exception:
        params = {}
    query_param_count = len(params)

    # ── Encoded chars ────────────────────────────────────────────────────────
    num_encoded_chars = len(re.findall(r'%[0-9a-fA-F]{2}', url))
    has_double_encoding = bool(re.search(r'%25[0-9a-fA-F]{2}', url, re.IGNORECASE))

    # ── Boolean detections ───────────────────────────────────────────────────
    has_https      = scheme == "https"
    is_ip_host     = _is_ip_address(hostname)
    has_at_in_url  = "@" in netloc

    # Punycode (homograph attack potential)
    has_punycode   = "xn--" in hostname

    # Suspicious TLD
    tld = _extract_tld(hostname)
    has_suspicious_tld = tld in SUSPICIOUS_TLDS

    # Brand squatting — brand keyword in non-brand domain
    has_brand_keyword = _check_brand_squatting(hostname)

    # Redirect parameter in query
    has_redirect_param = any(k.lower() in REDIRECT_PARAMS for k in params)

    # data: URI embedded in query values
    has_data_uri = any(
        "data:" in v.lower()
        for vals in params.values()
        for v in vals
    )

    # Base64-looking query value (length > 20, only base64 charset, ends with =)
    has_base64_in_query = any(
        _looks_like_base64(v)
        for vals in params.values()
        for v in vals
    )

    # Suspicious keyword in hostname (not in path)
    has_suspicious_keyword = any(kw in hostname for kw in SUSPICIOUS_DOMAIN_KEYWORDS)

    # ── Computed metrics ─────────────────────────────────────────────────────
    url_entropy           = _shannon_entropy(url)
    hostname_digit_ratio  = (
        sum(c.isdigit() for c in hostname) / len(hostname)
        if hostname else 0.0
    )

    return URLFeatures(
        url_length=url_length,
        hostname_length=hostname_length,
        path_length=path_length,
        query_length=query_length,
        num_dots=num_dots,
        num_hyphens=num_hyphens,
        num_underscores=num_underscores,
        num_slashes=num_slashes,
        num_at_symbols=num_at_symbols,
        num_digits=num_digits,
        num_special_chars=num_special_chars,
        num_subdomains=num_subdomains,
        path_depth=path_depth,
        query_param_count=query_param_count,
        num_encoded_chars=num_encoded_chars,
        has_https=has_https,
        is_ip_host=is_ip_host,
        has_double_encoding=has_double_encoding,
        has_redirect_param=has_redirect_param,
        has_suspicious_tld=has_suspicious_tld,
        has_brand_keyword=has_brand_keyword,
        has_at_in_url=has_at_in_url,
        has_punycode=has_punycode,
        has_data_uri=has_data_uri,
        has_base64_in_query=has_base64_in_query,
        has_suspicious_keyword=has_suspicious_keyword,
        url_entropy=round(url_entropy, 4),
        hostname_digit_ratio=round(hostname_digit_ratio, 4),
    )


def features_to_dict(f: URLFeatures) -> dict:
    """Convert URLFeatures to a plain dict (for DB storage + API response)."""
    return asdict(f)


def features_to_ml_vector(f: URLFeatures) -> list[float]:
    """
    Convert URLFeatures to a flat numeric list for ML inference.

    Order is stable — matches Phase 4 training schema.
    Boolean values are cast to 0.0 / 1.0.
    """
    return [
        float(f.url_length),
        float(f.hostname_length),
        float(f.path_length),
        float(f.query_length),
        float(f.num_dots),
        float(f.num_hyphens),
        float(f.num_underscores),
        float(f.num_slashes),
        float(f.num_at_symbols),
        float(f.num_digits),
        float(f.num_special_chars),
        float(f.num_subdomains),
        float(f.path_depth),
        float(f.query_param_count),
        float(f.num_encoded_chars),
        1.0 if f.has_https           else 0.0,
        1.0 if f.is_ip_host          else 0.0,
        1.0 if f.has_double_encoding else 0.0,
        1.0 if f.has_redirect_param  else 0.0,
        1.0 if f.has_suspicious_tld  else 0.0,
        1.0 if f.has_brand_keyword   else 0.0,
        1.0 if f.has_at_in_url       else 0.0,
        1.0 if f.has_punycode        else 0.0,
        1.0 if f.has_data_uri        else 0.0,
        1.0 if f.has_base64_in_query else 0.0,
        1.0 if f.has_suspicious_keyword else 0.0,
        f.url_entropy,
        f.hostname_digit_ratio,
    ]


# Feature names in the same order as features_to_ml_vector — used by Phase 4 training
ML_FEATURE_NAMES: list[str] = [
    "url_length", "hostname_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes",
    "num_at_symbols", "num_digits", "num_special_chars", "num_subdomains",
    "path_depth", "query_param_count", "num_encoded_chars",
    "has_https", "is_ip_host", "has_double_encoding", "has_redirect_param",
    "has_suspicious_tld", "has_brand_keyword", "has_at_in_url",
    "has_punycode", "has_data_uri", "has_base64_in_query",
    "has_suspicious_keyword", "url_entropy", "hostname_digit_ratio",
]


# ─── Private helpers ──────────────────────────────────────────────────────────

def _is_ip_address(hostname: str) -> bool:
    """Return True if hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _extract_tld(hostname: str) -> str:
    """Extract the TLD (last dot-separated segment) from a hostname."""
    if not hostname or "." not in hostname:
        return ""
    return "." + hostname.rsplit(".", 1)[-1]


def _check_brand_squatting(hostname: str) -> bool:
    """
    Return True if a known brand keyword appears in the hostname
    but the hostname is NOT one of the brand's legitimate domains.
    """
    hostname = hostname.lower()
    for brand, legit_domains in BRAND_DOMAINS.items():
        if brand in hostname:
            # Check if it's actually a legitimate domain
            is_legit = any(
                hostname == d or hostname.endswith("." + d)
                for d in legit_domains
            )
            if not is_legit:
                return True
    return False


def _looks_like_base64(value: str) -> bool:
    """Heuristic: string looks like base64 encoded data."""
    if len(value) < 20:
        return False
    # Base64 charset + padding
    return bool(re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', value))


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
