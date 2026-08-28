"""
api/analyze.py
POST /api/analyze/url     — Analyse a single URL (authenticated)
GET  /api/analyze/history — Paginated history of past analyses (authenticated)

Phase 3: Engine is auth-free; this layer adds auth + DB persistence.
"""

import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import Column, BigInteger, String, Float, Text, DateTime

from database import get_db, Base
from auth import CurrentUser, get_current_user
from db_utils import set_rls_user
from analysis.engine import analyze_url
from analysis.validator import URLValidationError

router = APIRouter()


# ─── SQLAlchemy model for url_analyses ───────────────────────────────────────

class URLAnalysis(Base):
    """ORM model for the url_analyses table (created by Phase 2 + 004 migration)."""
    __tablename__ = "url_analyses"

    id                = Column(BigInteger, primary_key=True, index=True)
    user_id           = Column(String(36), nullable=False, index=True)
    url               = Column(Text, nullable=False)
    risk_level        = Column(String(20), nullable=True)
    risk_score        = Column(BigInteger, nullable=True)
    prediction        = Column(String(20), nullable=True)
    confidence        = Column(Float, nullable=True)
    model_version     = Column(String(30), nullable=True)
    rule_flags        = Column(Text, nullable=True)   # JSON string
    features          = Column(Text, nullable=True)   # JSON string
    analysis_time_ms  = Column(Float, nullable=True)
    created_at        = Column(DateTime, default=datetime.utcnow)


# ─── Pydantic schemas ─────────────────────────────────────────────────────────

class URLAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL to analyse")


class URLAnalysisResponse(BaseModel):
    id:               int
    url:              str
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


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/analyze/url", response_model=URLAnalysisResponse, tags=["URL Analysis"])
def analyze_url_endpoint(
    req: URLAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Analyse a URL for phishing and malicious content.

    The engine performs:
    - Validation and normalization
    - 28-feature static extraction
    - 18 rule-based checks
    - Risk score computation

    Result is persisted to the user's analysis history.
    """
    uid = current_user.id
    set_rls_user(db, uid)

    # Run the auth-free, DB-free analysis engine
    try:
        result = analyze_url(req.url)
    except URLValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="URL analysis failed. Please try again.")

    # Persist to DB
    record = URLAnalysis(
        user_id=uid,
        url=result.url,
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

    return _to_response(record)


@router.get("/analyze/history", response_model=URLAnalysisListResponse, tags=["URL Analysis"])
def get_analysis_history(
    page:      int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Return paginated history of URL analyses for the authenticated user."""
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


@router.delete("/analyze/history/{analysis_id}", tags=["URL Analysis"])
def delete_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Delete a specific URL analysis (ownership verified)."""
    uid = current_user.id
    set_rls_user(db, uid)

    record = (
        db.query(URLAnalysis)
        .filter(URLAnalysis.id == analysis_id, URLAnalysis.user_id == uid)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    db.delete(record)
    db.commit()
    return {"deleted": True, "id": analysis_id}


# ─── Helper ───────────────────────────────────────────────────────────────────

def _to_response(record: URLAnalysis) -> URLAnalysisResponse:
    """Convert ORM model to Pydantic response, safely parsing JSON columns."""
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
        url=record.url,
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
