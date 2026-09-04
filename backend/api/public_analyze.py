"""
api/public_analyze.py
POST /api/public/analyze — Unauthenticated URL analysis for the Chrome extension.

Security design:
  - NO authentication required (extension users have no account)
  - NO database writes (no user_id to associate records with)
  - Rate limited by client IP: 15 requests / 60 seconds
  - Same URL validation and analysis engine as /api/analyze
  - Returns only public-safe fields (no internal rule details exposed)
  - Safe error messages (no stack traces, no internal paths)
  - Designed to be called from chrome-extension:// origins

Abuse prevention:
  - Per-IP sliding window rate limiter (separate instance from user limiter)
  - URL length capped to 2048 characters
  - All control characters rejected
  - Pydantic input validation
  - Request body size limited to 4 KB (enforced in main.py middleware)
"""

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, field_validator
import re

from analysis.engine   import analyze_url
from analysis.validator import validate_and_normalize, URLValidationError
from analysis.features  import extract_features, features_to_ml_vector
from analysis.url_model import url_predict
from middleware.rate_limiter import RateLimiter

router  = APIRouter()
logger  = logging.getLogger(__name__)

# ── Dedicated IP-based rate limiter for the public endpoint ──────────────────
# More conservative than the user limiter — abuse prevention without accounts
_public_limiter = RateLimiter(max_requests=15, window_seconds=60)

# ── Input schema ─────────────────────────────────────────────────────────────

_CONTROL_CHAR_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
_MAX_URL_LENGTH  = 2048


class PublicAnalyzeRequest(BaseModel):
    url: str

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("URL must not be empty.")
        if len(v) > _MAX_URL_LENGTH:
            raise ValueError(f"URL exceeds maximum length of {_MAX_URL_LENGTH} characters.")
        if _CONTROL_CHAR_RE.search(v):
            raise ValueError("URL contains invalid control characters.")
        return v.strip()


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post("/public/analyze", tags=["Public"])
async def public_analyze(
    payload: PublicAnalyzeRequest,
    request: Request,
):
    """
    Analyze a URL without authentication.
    Intended for the Chrome extension — no account required.

    Rate limit: 15 requests/minute per IP address.
    Results are NOT saved to any database.
    No user data is collected or stored.

    Returns a sanitized result: prediction, risk_level, risk_score, confidence.
    Internal rule flags are NOT returned to prevent information disclosure.
    """
    # ── 1. IP-based rate limiting ────────────────────────────────────────
    client_ip = request.client.host if request.client else "unknown"
    _allowed, _retry_after = _public_limiter.check(client_ip)
    if not _allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait before analysing another URL.",
            headers={"Retry-After": str(_retry_after)},
        )

    # ── 2. Validate and normalize URL ────────────────────────────────────
    try:
        normalized_url = validate_and_normalize(payload.url)
    except URLValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # ── 3. ML prediction (optional — graceful degradation) ───────────────
    ml_pred = None
    ml_conf = None
    try:
        feats   = extract_features(normalized_url)
        vec     = features_to_ml_vector(feats)
        ml_pred, ml_conf = url_predict(vec)
    except Exception:
        pass   # Degrade gracefully — rules-only result still valid

    # ── 4. Full analysis engine ───────────────────────────────────────────
    try:
        result = analyze_url(normalized_url, ml_prediction=ml_pred, ml_confidence=ml_conf)
    except Exception:
        logger.error("Public analysis engine error for ip=...%s", client_ip[-4:] if len(client_ip) > 4 else "?")
        raise HTTPException(
            status_code=500,
            detail="Analysis failed. Please try again later.",
        )

    # ── 5. Safe response — no rule internals exposed ──────────────────────
    # Log minimal info (IP suffix only, no URL content, no token)
    logger.info(
        "public_analyze ip=...%s risk=%s score=%d",
        client_ip[-4:] if len(client_ip) > 4 else "?",
        result.risk_level,
        result.risk_score,
    )

    return {
        "prediction":    result.prediction,
        "risk_level":    result.risk_level,
        "risk_score":    result.risk_score,
        "confidence":    round(result.confidence, 4),
        "model_version": result.model_version,
        # How many rule flags fired (count only — not the flag details)
        "flags_triggered": len(result.rule_flags) if result.rule_flags else 0,
    }
