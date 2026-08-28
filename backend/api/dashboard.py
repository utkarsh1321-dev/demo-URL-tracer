"""
api/dashboard.py
GET /api/dashboard — Aggregate stats scoped to the authenticated user.
Phase 2: Auth required. All queries filtered by current_user.id.
"""

from sqlalchemy.orm import Session
from sqlalchemy import func
from fastapi import APIRouter, Depends

from database import get_db
from auth import CurrentUser, get_current_user
from db_utils import set_rls_user
from models import Request, Detection, IPAnalysis, Upload
from schemas import (
    DashboardResponse, AttackTypeStat, SeverityStat, TopIP, DetectionOut
)

router = APIRouter()


@router.get("/dashboard", response_model=DashboardResponse, tags=["Dashboard"])
def get_dashboard(
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Returns aggregate stats for the authenticated user's data only.
    Cross-user data is never returned.
    """
    uid = current_user.id
    set_rls_user(db, uid)

    total_requests = (
        db.query(func.count(Request.id))
        .join(Upload, Request.upload_id == Upload.id)
        .filter(Upload.user_id == uid)
        .scalar() or 0
    )

    total_attacks = (
        db.query(func.count(Detection.id))
        .filter(Detection.user_id == uid)
        .scalar() or 0
    )

    high_risk_ips = (
        db.query(func.count(IPAnalysis.id))
        .filter(IPAnalysis.user_id == uid, IPAnalysis.risk_level.in_(["HIGH", "CRITICAL"]))
        .scalar() or 0
    )

    critical_ips = (
        db.query(func.count(IPAnalysis.id))
        .filter(IPAnalysis.user_id == uid, IPAnalysis.risk_level == "CRITICAL")
        .scalar() or 0
    )

    # Attacks by type
    type_rows = (
        db.query(Detection.attack_type, func.count(Detection.id).label("cnt"))
        .filter(Detection.user_id == uid)
        .group_by(Detection.attack_type)
        .order_by(func.count(Detection.id).desc())
        .all()
    )
    attacks_by_type = [AttackTypeStat(attack_type=r[0], count=r[1]) for r in type_rows]

    # Attacks by severity
    sev_rows = (
        db.query(Detection.severity, func.count(Detection.id).label("cnt"))
        .filter(Detection.user_id == uid)
        .group_by(Detection.severity)
        .order_by(func.count(Detection.id).desc())
        .all()
    )
    attacks_by_severity = [SeverityStat(severity=r[0], count=r[1]) for r in sev_rows]

    # Top 10 attacking IPs for this user
    top_ips = (
        db.query(IPAnalysis)
        .filter(IPAnalysis.user_id == uid, IPAnalysis.attack_count > 0)
        .order_by(IPAnalysis.risk_score.desc())
        .limit(10)
        .all()
    )
    top_attacking_ips = [
        TopIP(
            ip_address=ip.ip_address,
            risk_score=ip.risk_score,
            risk_level=ip.risk_level,
            attack_count=ip.attack_count,
        )
        for ip in top_ips
    ]

    # 20 most recent detections for this user
    recent = (
        db.query(Detection)
        .filter(Detection.user_id == uid)
        .order_by(Detection.created_at.desc())
        .limit(20)
        .all()
    )
    recent_detections = [DetectionOut.model_validate(d) for d in recent]

    potential_success_count = (
        db.query(func.count(Detection.id))
        .filter(Detection.user_id == uid, Detection.result == "POTENTIAL_SUCCESS")
        .scalar() or 0
    )

    return DashboardResponse(
        total_requests=total_requests,
        total_attacks=total_attacks,
        high_risk_ips=high_risk_ips,
        critical_ips=critical_ips,
        attacks_by_type=attacks_by_type,
        attacks_by_severity=attacks_by_severity,
        top_attacking_ips=top_attacking_ips,
        recent_detections=recent_detections,
        potential_success_count=potential_success_count,
    )
