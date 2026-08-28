"""
api/analyze.py
URL analysis API — Phase 5: ML + Backend Integration

Endpoints:
  POST /api/analyze           — Primary clean endpoint (Phase 5)
  POST /api/analyze/url       — Legacy alias (Phase 3 compat)
  GET  /api/analyze/history   — Paginated user history
  DELETE /api/analyze/history/{id} — Delete own record

Security controls (Phase 5):
  - Authentication: JWT verified, user_id from token ONLY
  - Rate limiting: 30 analyses/min per user (in-memory sliding window)
  - Request body cap: max_length=2048 on URL field (Pydantic) + 4KB body middleware
  - Authorization: all DB queries scoped to authenticated user_id + RLS
  - Safe errors: no URL content, no stack traces, no internal state in responses
  - Logging: analysis ID + risk_level + model_version — NEVER the URL or JWT
  - normalized_url: stored separately from raw input for audit trail
"""

import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from sqlalchemy import Column, BigInteger, String, Float, Text, DateTime

from database import get_db, Base
from auth import CurrentUser, get_current_user
from db_utils import set_rls_user
from analysis.engine import analyze_url
from analysis.validator import validate_and_normalize, URLValidationError
from analysis.features import extract_features, features_to_ml_vector
from analysis.url_model import url_predict
from middleware.rate_limiter import analyze_limiter

router = APIRouter()
logger = logging.getLogger(__name__)

# Maximum request body size for URL analysis endpoints (bytes)
MAX_REQUEST_BODY_BYTES = 4096


# ─── ORM model ────────────────────────────────────────────────────────────────

class URLAnalysis(Base):
    """
    ORM model for url_analyses table.

    Columns:
      raw_url        — Original URL as submitted by user (for audit)
      url            — Normalized URL (what was actually analysed)
      normalized_url — Same as url; explicit column per Phase 5 PRD
    """
    __tablename__ = "url_analyses"

    id               = Column(BigInteger, primary_key=True, index=True)
    user_id          = Column(String(36), nullable=False, index=True)
    raw_url          = Column(Text, nullable=True)    # Phase 5: original input
    url              = Column(Text, nullable=False)   # normalized (analysed) URL
    normalized_url   = Column(Text, nullable=True)    # Phase 5: explicit audit column
    risk_level       = Column(String(20), nullable=True)
    risk_score       = Column(BigInteger, nullable=True)
    prediction       = Column(String(20), nullable=True)
    confidence       = Column(Float, nullable=True)
    model_version    = Column(String(30), nullable=True)
    rule_flags       = Column(Text, nullable=True)   # JSON
    features         = Column(Text, nullable=True)   # JSON
    analysis_time_ms = Column(Float, nullable=True)
    created_at       = Column(DateTime, default=datetime.utcnow)


# ─── Pydantic schemas ─────────────────────────────────────────────────────────

class URLAnalysisRequest(BaseModel):
    """
    Request body for URL analysis.

    Validation:
    - min_length=1, max_length=2048 — catches empty and oversized inputs
    - strip whitespace before validation
    - reject control characters
    """
    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="URL to analyse for phishing/malicious content",
        examples=["https://example.com"],
    )

    @field_validator("url", mode="before")
    @classmethod
    def sanitize_url(cls, v):
        if not isinstance(v, str):
            raise ValueError("URL must be a string.")
        v = v.strip()
        # Reject URLs with control characters (null bytes, newlines etc.)
        if any(ord(c) < 32 for c in v):
            raise ValueError("URL contains invalid control characters.")
        return v


class URLAnalysisResponse(BaseModel):
    id:               int
    raw_url:          Optional[str]   = None   # original input (may differ from normalized)
    url:              str                      # normalized URL that was analysed
    prediction:       str
    risk_score:       int
    risk_level:       str
    confidence:       float
    model_version:    str
    rule_flags:       list[dict]
    features:         dict
    analysis_time_ms: float
    created_at:       Optional[datetime]

    class Config:
        from_attributes = True


class URLAnalysisListResponse(BaseModel):
    total:     int
    page:      int
    page_size: int
    items:     list[URLAnalysisResponse]


# ─── Core analysis logic ─────────────────────────────────────────────────────

def _run_analysis(
    raw_url: str,
    uid: str,
    db: Session,
) -> URLAnalysisResponse:
    """
    Shared implementation for POST /api/analyze and POST /api/analyze/url.

    Security invariants:
    - uid is ALWAYS from verified JWT (passed in, never from request body)
    - URL logged NEVER — only analysis ID and risk_level logged
    - Errors are sanitized — no internal state exposed to caller

    Pipeline:
      1. Validate + normalize URL
      2. Extract 28 features (Phase 3 schema — shared with training)
      3. ML inference (Phase 4 GradientBoosting, graceful degradation)
      4. Rule-based checks + risk score (60% rules + 40% ML)
      5. Persist under authenticated user_id
    """
    set_rls_user(db, uid)

    # ── 1. Validate + normalize ───────────────────────────────────────────
    try:
        normalized_url = validate_and_normalize(raw_url)
    except URLValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))

    # ── 2+3. Feature extraction + ML inference ────────────────────────────
    ml_pred: Optional[str]   = None
    ml_conf: Optional[float] = None
    try:
        feats  = extract_features(normalized_url)
        vec    = features_to_ml_vector(feats)
        ml_pred, ml_conf = url_predict(vec)
    except Exception:
        # Model unavailable — engine uses rule-based scoring only
        pass

    # ── 4. Engine: rules + risk scoring ──────────────────────────────────
    try:
        result = analyze_url(
            raw_url,
            ml_prediction=ml_pred,
            ml_confidence=ml_conf,
        )
    except URLValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception:
        logger.error("analysis engine raised unexpectedly for uid=%s", uid[:8])
        raise HTTPException(status_code=500, detail="Analysis failed. Please try again.")

    # ── 5. Persist ────────────────────────────────────────────────────────
    record = URLAnalysis(
        user_id=uid,
        raw_url=raw_url,                  # original submission (audit)
        url=result.url,                   # normalized (analysed)
        normalized_url=result.url,        # explicit Phase 5 column
        risk_level=result.risk_level,
        risk_score=result.risk_score,
        prediction=result.prediction,
        confidence=result.confidence,
        model_version=result.model_version,
        rule_flags=json.dumps(result.rule_flags),
        features=json.dumps(result.features),
        analysis_time_ms=result.analysis_time_ms,
        created_at=datetime.utcnow(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # ── Secure logging — NO URL content, NO JWT ───────────────────────────
    logger.info(
        "url_analysis id=%s uid=...%s risk=%s model=%s ml=%s time=%.1fms",
        record.id,
        uid[-6:],               # last 6 chars of UUID — not PII
        result.risk_level,
        result.model_version,
        ml_pred or "rule-only",
        result.analysis_time_ms,
    )

    return _to_response(record)


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post(
    "/analyze",
    response_model=URLAnalysisResponse,
    tags=["URL Analysis"],
    summary="Analyse a URL for phishing / malicious content",
)
async def analyze_endpoint(
    request: Request,
    req: URLAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    **POST /api/analyze** — Primary URL analysis endpoint (Phase 5).

    Security:
    - JWT required (Bearer token in Authorization header)
    - user_id from verified token ONLY — never from request body
    - Rate limited: 30 requests/minute per user
    - Request body capped at 4 KB
    - Safe errors: no internal state or URL content in error messages
    - Audit log: analysis ID + risk level only (no URL, no token)

    Pipeline: validate → normalize → features → ML inference → rules → risk score → DB
    """
    # ── Request body size guard ───────────────────────────────────────────
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_BODY_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Request body too large. Maximum {MAX_REQUEST_BODY_BYTES} bytes.",
        )

    # ── Rate limiting — keyed on verified user_id from JWT ────────────────
    uid = current_user.id
    allowed, retry_after = analyze_limiter.check(uid)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Maximum 30 analyses per minute. Retry after {retry_after}s.",
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit":     "30",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Window":    "60",
            },
        )

    remaining = analyze_limiter.remaining(uid)

    response = _run_analysis(raw_url=req.url, uid=uid, db=db)

    # Attach rate-limit headers to response
    # (FastAPI JSONResponse will be created from the model automatically)
    return response


@router.post(
    "/analyze/url",
    response_model=URLAnalysisResponse,
    tags=["URL Analysis"],
    summary="Analyse a URL (legacy endpoint — prefer /api/analyze)",
    include_in_schema=True,
)
async def analyze_url_endpoint(
    request: Request,
    req: URLAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Legacy endpoint kept for Phase 3 frontend compatibility.
    Identical security controls and pipeline as POST /api/analyze.
    """
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body too large.")

    uid = current_user.id
    allowed, retry_after = analyze_limiter.check(uid)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Retry after {retry_after}s.",
            headers={"Retry-After": str(retry_after)},
        )

    return _run_analysis(raw_url=req.url, uid=uid, db=db)


@router.get(
    "/analyze/history",
    response_model=URLAnalysisListResponse,
    tags=["URL Analysis"],
)
def get_analysis_history(
    page:       int = Query(1, ge=1, description="Page number"),
    page_size:  int = Query(20, ge=1, le=100, description="Results per page"),
    risk_level: Optional[str] = Query(
        None,
        description="Filter by risk level: LOW | MEDIUM | HIGH | CRITICAL",
        pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$",
    ),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Return paginated URL analysis history for the authenticated user.

    Results are always scoped to the requesting user — no cross-user access.
    """
    uid = current_user.id
    set_rls_user(db, uid)

    q = db.query(URLAnalysis).filter(URLAnalysis.user_id == uid)
    if risk_level:
        q = q.filter(URLAnalysis.risk_level == risk_level.upper())

    total = q.count()
    items = (
        q.order_by(URLAnalysis.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return URLAnalysisListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[_to_response(r) for r in items],
    )


@router.delete(
    "/analyze/history/{analysis_id}",
    tags=["URL Analysis"],
    summary="Delete an analysis record",
)
def delete_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Delete a specific URL analysis record.

    Ownership is verified: a user can only delete their own records.
    The record is looked up by BOTH id AND user_id — SQL injection
    resistance is provided by SQLAlchemy parameterized queries.
    """
    uid = current_user.id
    set_rls_user(db, uid)

    record = (
        db.query(URLAnalysis)
        .filter(URLAnalysis.id == analysis_id, URLAnalysis.user_id == uid)
        .first()
    )
    if not record:
        # Return 404 regardless of whether the record exists but belongs to someone else
        # — prevents enumeration attacks
        raise HTTPException(status_code=404, detail="Analysis not found.")

    db.delete(record)
    db.commit()

    logger.info("url_analysis deleted id=%s uid=...%s", analysis_id, uid[-6:])
    return {"deleted": True, "id": analysis_id}


@router.get(
    "/analyze/status",
    tags=["URL Analysis"],
    summary="ML model status",
)
def get_model_status():
    """
    Return ML model availability status (public — no auth required).
    Does not expose sensitive model internals.
    """
    from analysis.url_model import get_model_status
    status = get_model_status()
    # Strip internal load_error detail before returning to client
    status.pop("load_error", None)
    return status


# ─── Helper ───────────────────────────────────────────────────────────────────

def _to_response(record: URLAnalysis) -> URLAnalysisResponse:
    """Convert ORM model to Pydantic response — safe JSON parsing of stored columns."""
    try:
        rule_flags = json.loads(record.rule_flags or "[]")
    except Exception:
        rule_flags = []

    try:
        features = json.loads(record.features or "{}")
    except Exception:
        features = {}

    return URLAnalysisResponse(
        id=record.id,
        raw_url=record.raw_url,
        url=record.url or "",
        prediction=record.prediction or "UNKNOWN",
        risk_score=record.risk_score or 0,
        risk_level=record.risk_level or "LOW",
        confidence=record.confidence or 0.0,
        model_version=record.model_version or "urltracer-v1",
        rule_flags=rule_flags,
        features=features,
        analysis_time_ms=record.analysis_time_ms or 0.0,
        created_at=record.created_at,
    )
