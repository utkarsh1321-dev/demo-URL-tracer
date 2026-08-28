"""
analysis/validator.py
URL validation and safe normalization.

Security rules:
- Input length capped at MAX_URL_LENGTH before any parsing
- Only http/https/ftp schemes pass validation (blocks javascript:, data:, file:)
- urllib.parse is used — no network calls ever made
- Malformed URLs raise URLValidationError with a safe message
"""

import re
from urllib.parse import urlparse, urlunparse, quote

# Hard limit before any parsing — prevents ReDoS / memory attacks
MAX_URL_LENGTH = 2048

# Schemes that are safe to analyse (static analysis only)
ALLOWED_SCHEMES = {"http", "https", "ftp"}

# Dangerous schemes we want to DETECT (not allow through as input for analysis)
DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}


class URLValidationError(ValueError):
    """Raised for URLs that cannot be safely parsed."""


def validate_and_normalize(raw_url: str) -> str:
    """
    Validate and normalize a raw URL string.

    Returns a cleaned, parseable URL string.
    Raises URLValidationError for inputs that cannot be safely processed.

    Does NOT make any network calls.
    """
    if not isinstance(raw_url, str):
        raise URLValidationError("URL must be a string.")

    # 1. Strip whitespace
    url = raw_url.strip()

    if not url:
        raise URLValidationError("URL is empty.")

    # 2. Hard length cap — before any regex/parsing
    if len(url) > MAX_URL_LENGTH:
        raise URLValidationError(
            f"URL exceeds maximum length of {MAX_URL_LENGTH} characters."
        )

    # 3. Detect dangerous scheme patterns (case-insensitive, before adding scheme)
    scheme_match = re.match(r'^([a-z][a-z0-9+\-.]*)\s*:', url, re.IGNORECASE)
    if scheme_match:
        scheme_lower = scheme_match.group(1).lower()
        if scheme_lower in DANGEROUS_SCHEMES:
            raise URLValidationError(
                f"Scheme '{scheme_lower}:' is not permitted for analysis."
            )

    # 4. Add scheme if missing (bare domains like "evil.com/phish")
    if not re.match(r'^[a-z][a-z0-9+\-.]*://', url, re.IGNORECASE):
        url = "http://" + url

    # 5. Parse
    try:
        parsed = urlparse(url)
    except Exception:
        raise URLValidationError("URL could not be parsed.")

    # 6. Scheme must be recognized
    if not parsed.scheme:
        raise URLValidationError("URL has no scheme.")

    # 7. Must have a netloc (hostname)
    if not parsed.netloc:
        raise URLValidationError("URL has no hostname.")

    # 8. Hostname must not be empty after stripping credentials
    hostname = parsed.hostname or ""
    if not hostname:
        raise URLValidationError("URL hostname is empty.")

    # 9. Reconstruct a normalized URL
    normalized = urlunparse(parsed)

    return normalized
