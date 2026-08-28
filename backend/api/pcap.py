"""
api/pcap.py
GET /api/pcap/history       — Paginated PCAP analysis history for authenticated user
GET /api/pcap/history/{id}  — Full detail for one PCAP analysis with per-URL records

Phase 7: Real data from pcap_analyses + pcap_records.
All queries are scoped to current_user.id — cross-user access is impossible.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from auth import CurrentUser, get_current_user
from db_utils import set_rls_user
from api.upload import PCAPAnalysis, PCAPRecord   # ORM models defined in upload.py

router = APIRouter()
logger = logging.getLogger(__name__)


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/pcap/history", tags=["PCAP"])
def get_pcap_history(
    page:      int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Return paginated PCAP analysis history for the authenticated user.
    Each item includes summary stats but not the per-URL records.
    """
    uid = current_user.id
    set_rls_user(db, uid)

    q     = db.query(PCAPAnalysis).filter(PCAPAnalysis.user_id == uid)
    total = q.count()
    items = (
        q.order_by(PCAPAnalysis.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "total":     total,
        "page":      page,
        "page_size": page_size,
        "items":     [_analysis_summary(a) for a in items],
    }


@router.get("/pcap/history/{analysis_id}", tags=["PCAP"])
def get_pcap_detail(
    analysis_id: int,
    page:      int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Return full detail for one PCAP analysis, including per-URL records.
    Ownership is enforced — users can only access their own analyses.
    Returns 404 (not 403) to prevent enumeration.
    """
    uid = current_user.id
    set_rls_user(db, uid)

    analysis = (
        db.query(PCAPAnalysis)
        .filter(PCAPAnalysis.id == analysis_id, PCAPAnalysis.user_id == uid)
        .first()
    )
    if not analysis:
        raise HTTPException(status_code=404, detail="PCAP analysis not found.")

    # Paginated per-URL records
    records_q = (
        db.query(PCAPRecord)
        .filter(PCAPRecord.pcap_analysis_id == analysis_id, PCAPRecord.user_id == uid)
    )
    total_records = records_q.count()
    records = (
        records_q.order_by(PCAPRecord.risk_score.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        **_analysis_summary(analysis),
        "records_total": total_records,
        "records_page":  page,
        "records":       [_record_dict(r) for r in records],
    }


@router.delete("/pcap/history/{analysis_id}", tags=["PCAP"])
def delete_pcap_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Delete a PCAP analysis and all its records (ownership enforced)."""
    uid = current_user.id
    set_rls_user(db, uid)

    analysis = (
        db.query(PCAPAnalysis)
        .filter(PCAPAnalysis.id == analysis_id, PCAPAnalysis.user_id == uid)
        .first()
    )
    if not analysis:
        raise HTTPException(status_code=404, detail="PCAP analysis not found.")

    # Delete child records first
    db.query(PCAPRecord).filter(
        PCAPRecord.pcap_analysis_id == analysis_id,
        PCAPRecord.user_id == uid,
    ).delete()

    db.delete(analysis)
    db.commit()

    logger.info("pcap_analysis deleted id=%s uid=...%s", analysis_id, uid[-6:])
    return {"deleted": True, "id": analysis_id}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _analysis_summary(a: PCAPAnalysis) -> dict:
    return {
        "id":                 a.id,
        "filename":           a.filename,
        "status":             a.status,
        "packets_analyzed":   a.packets_analyzed or 0,
        "http_requests":      a.http_requests or 0,
        "urls_extracted":     a.urls_extracted or 0,
        "unique_ips":         a.unique_ips or 0,
        "suspicious_urls":    a.suspicious_urls or 0,
        "high_risk_urls":     a.high_risk_urls or 0,
        "processing_time_ms": a.processing_time_ms or 0,
        "records_extracted":  a.records_extracted or 0,
        "error_message":      a.error_message,
        "created_at":         a.created_at.isoformat() if a.created_at else None,
    }


def _record_dict(r: PCAPRecord) -> dict:
    return {
        "id":             r.id,
        "source_ip":      r.source_ip,
        "destination_ip": r.destination_ip,
        "url":            r.url,
        "method":         r.method,
        "host":           r.host,
        "port":           r.port,
        "prediction":     r.prediction or "UNKNOWN",
        "risk_score":     r.risk_score or 0,
        "risk_level":     r.risk_level or "LOW",
        "confidence":     r.confidence or 0.0,
        "model_version":  r.model_version,
        "status":         r.status,
        "timestamp":      r.timestamp.isoformat() if r.timestamp else None,
    }
