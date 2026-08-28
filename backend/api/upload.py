"""
api/upload.py
POST /api/upload/csv  — Upload and process a CSV file.
POST /api/upload/pcap — Upload and process a PCAP file.
Phase 2: Auth required. user_id injected from JWT into every record.
"""

import os
import tempfile
from datetime import datetime

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from auth import CurrentUser, get_current_user
from db_utils import set_rls_user
from schemas import UploadResponse
from services.csv_service import process_csv_upload, CSVValidationError
from services.pcap_service import process_pcap
from services.csv_service import _upsert_ip_analysis
from detection.engine import run_detection
from services.ml_service import predict
from models import Request, Detection, Upload
from utils.normalizer import parse_timestamp

router = APIRouter()

_ALLOWED_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}
_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


# ─────────────────────────────────────────────
# CSV Upload
# ─────────────────────────────────────────────

@router.post("/upload/csv", response_model=UploadResponse, tags=["Upload"])
async def upload_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Upload a CSV file with HTTP request records.
    Records are processed, detections stored, and results returned.
    All data is scoped to the authenticated user.
    """
    uid = current_user.id
    set_rls_user(db, uid)

    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Invalid file type. Upload a .csv file.")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(content) > _MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 50 MB.")

    try:
        result = process_csv_upload(content, file.filename or "upload.csv", db, user_id=uid)
    except CSVValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Error processing CSV. Please check the file format.",
        )

    return UploadResponse(**result)


# ─────────────────────────────────────────────
# PCAP Upload
# ─────────────────────────────────────────────

@router.post("/upload/pcap", response_model=UploadResponse, tags=["Upload"])
async def upload_pcap(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Upload a PCAP/PCAPNG capture file.
    Phase 2: Stub — returns empty result. Real PCAP parsing in Phase 7.
    """
    uid = current_user.id
    set_rls_user(db, uid)

    fname = (file.filename or "upload.pcap").lower()
    ext = os.path.splitext(fname)[1]
    if ext not in _ALLOWED_PCAP_EXTS:
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Upload a .pcap or .pcapng file.",
        )

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(content) > _MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 50 MB.")

    # Write to temp file for the pcap_service
    suffix = ext or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    # Create upload record — user_id injected from JWT
    upload = Upload(
        user_id=uid,
        filename=file.filename or "upload.pcap",
        file_type="pcap",
        status="processing",
        uploaded_at=datetime.utcnow(),
    )
    db.add(upload)
    db.flush()

    try:
        records = process_pcap(tmp_path)   # returns [] until Phase 7
    except Exception as e:
        upload.status = "error"
        upload.error_message = str(e)[:500]
        db.commit()
        raise HTTPException(status_code=422, detail=f"PCAP processing failed: {e}")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    # Run detection pipeline (same as CSV)
    ip_detections: dict[str, list] = {}
    ip_request_counts: dict[str, int] = {}
    records_processed = 0
    attacks_detected = 0

    for record in records:
        src_ip = record.get("source_ip", "0.0.0.0")
        ip_request_counts[src_ip] = ip_request_counts.get(src_ip, 0) + 1

        req_obj = Request(
            timestamp=parse_timestamp(record.get("timestamp")),
            source_ip=src_ip,
            destination_ip=record.get("destination_ip"),
            method=record.get("method"),
            host=record.get("host"),
            url=record.get("url"),
            user_agent=record.get("user_agent"),
            status_code=record.get("status_code"),
            response_size=record.get("response_size"),
            upload_id=upload.id,
        )
        db.add(req_obj)
        db.flush()

        det_result = run_detection(record)
        if det_result is None:
            ml_out = predict(record)
            if ml_out["prediction"] != "Benign" and ml_out["confidence"] >= 0.70:
                det_result = {
                    "attack_type": ml_out["prediction"],
                    "severity": "MEDIUM",
                    "confidence": ml_out["confidence"],
                    "detection_method": "ML",
                    "result": "ATTEMPT",
                }
        elif det_result:
            det_result["detection_method"] = "HYBRID"

        if det_result:
            db.add(Detection(
                user_id=uid,
                request_id=req_obj.id,
                attack_type=det_result["attack_type"],
                severity=det_result["severity"],
                confidence=det_result["confidence"],
                detection_method=det_result["detection_method"],
                result=det_result["result"],
                source_ip=src_ip,
                url=record.get("url"),
                host=record.get("host"),
            ))
            attacks_detected += 1
            ip_detections.setdefault(src_ip, []).append(det_result)

        records_processed += 1

    high_risk_ips = _upsert_ip_analysis(db, ip_detections, ip_request_counts, user_id=uid)

    upload.records_processed = records_processed
    upload.attacks_detected = attacks_detected
    upload.high_risk_ips = high_risk_ips
    upload.status = "completed"
    db.commit()

    return UploadResponse(
        status="completed",
        upload_id=upload.id,
        records_processed=records_processed,
        attacks_detected=attacks_detected,
        high_risk_ips=high_risk_ips,
    )
