"""
api/attacks.py
GET /api/attacks        — Paginated, filtered detections for the authenticated user.
GET /api/attacks/{id}   — Single detection (ownership verified).
Phase 2: Auth required. Cross-user access denied.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from auth import CurrentUser, get_current_user
from db_utils import set_rls_user
from models import Detection
from schemas import AttackListResponse, DetectionOut

router = APIRouter()


@router.get("/attacks", response_model=AttackListResponse, tags=["Attacks"])
def list_attacks(
    attack_type: Optional[str] = Query(None),
    severity:    Optional[str] = Query(None),
    result:      Optional[str] = Query(None),
    source_ip:   Optional[str] = Query(None),
    page:        int = Query(1, ge=1),
    page_size:   int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    uid = current_user.id
    set_rls_user(db, uid)

    q = db.query(Detection).filter(Detection.user_id == uid)

    if attack_type:
        q = q.filter(Detection.attack_type.ilike(f"%{attack_type}%"))
    if severity:
        q = q.filter(Detection.severity == severity.upper())
    if result:
        q = q.filter(Detection.result == result.upper())
    if source_ip:
        q = q.filter(Detection.source_ip == source_ip)

    total = q.count()
    items = (
        q.order_by(Detection.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return AttackListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[DetectionOut.model_validate(d) for d in items],
    )


@router.get("/attacks/{attack_id}", response_model=DetectionOut, tags=["Attacks"])
def get_attack(
    attack_id: int,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    uid = current_user.id
    set_rls_user(db, uid)

    det = (
        db.query(Detection)
        .filter(Detection.id == attack_id, Detection.user_id == uid)
        .first()
    )
    if not det:
        # Return 404 for both "not found" and "not owned" — never leak existence
        raise HTTPException(status_code=404, detail="Detection not found.")
    return DetectionOut.model_validate(det)
