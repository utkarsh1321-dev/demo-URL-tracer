"""
api/upload.py
POST /api/upload/csv  — Upload and process a CSV file.
POST /api/upload/pcap — Upload a PCAP file through the real analysis pipeline (Phase 7).

Phase 7 PCAP pipeline:
  Validated upload -> Scapy parse -> HTTP/URL extraction -> central URL engine
  -> results persisted to pcap_analyses + pcap_records under authenticated user
"""

import json
import logging
import os
import tempfile
from datetime import datetime

from fastapi import APIRouter, Depends, File, UploadFile, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import Column, BigInteger, Integer, String, Float, Text, DateTime

from database import get_db, Base
from auth import CurrentUser, get_current_user
from db_utils import set_rls_user
from schemas import UploadResponse
from services.csv_service import process_csv_upload, CSVValidationError, _upsert_ip_analysis
from services.pcap_service import process_pcap, PCAPValidationError
from detection.engine import run_detection
from services.ml_service import predict
from models import Request, Detection, Upload
from utils.normalizer import parse_timestamp

router = APIRouter()
logger = logging.getLogger(__name__)

_ALLOWED_PCAP_EXTS = {".pcap", ".pcapng", ".cap"}
_MAX_FILE_SIZE     = 50 * 1024 * 1024   # 50 MB


# ── ORM models for PCAP results ───────────────────────────────────────────────

class PCAPAnalysis(Base):
    """Top-level record for a PCAP upload session. Maps to pcap_analyses."""
    __tablename__ = "pcap_analyses"

    id                  = Column(BigInteger, primary_key=True, index=True)
    user_id             = Column(String(36), nullable=False, index=True)
    filename            = Column(String(255), nullable=False)
    status              = Column(String(20),  default="pending")
    records_extracted   = Column(Integer,     default=0)
    packets_analyzed    = Column(Integer,     default=0)
    http_requests       = Column(Integer,     default=0)
    urls_extracted      = Column(Integer,     default=0)
    unique_ips          = Column(Integer,     default=0)
    suspicious_urls     = Column(Integer,     default=0)
    high_risk_urls      = Column(Integer,     default=0)
    processing_time_ms  = Column(Float,       default=0)
    error_message       = Column(Text,        nullable=True)
    created_at          = Column(DateTime, default=datetime.utcnow)


class PCAPRecord(Base):
    """Per-URL analysis result from a PCAP session. Maps to pcap_records."""
    __tablename__ = "pcap_records"

    id               = Column(BigInteger, primary_key=True, index=True)
    pcap_analysis_id = Column(BigInteger, nullable=False, index=True)
    user_id          = Column(String(36), nullable=False, index=True)
    source_ip        = Column(String(45), nullable=True)
    destination_ip   = Column(String(45), nullable=True)
    url              = Column(Text,       nullable=True)
    method           = Column(String(10), nullable=True)
    host             = Column(String(253),nullable=True)
    user_agent       = Column(Text,       nullable=True)
    port             = Column(Integer,    nullable=True)
    prediction       = Column(String(20), nullable=True)
    risk_score       = Column(Integer,    nullable=True)
    risk_level       = Column(String(20), nullable=True)
    confidence       = Column(Float,      nullable=True)
    model_version    = Column(String(30), nullable=True)
    status           = Column(String(20), default="pending")
    timestamp        = Column(DateTime,   nullable=True)


# ─── CSV Upload (unchanged from Phase 2) ────────────────────────────────────

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


# ─── PCAP Upload (Phase 7 — real pipeline) ───────────────────────────────────

@router.post("/upload/pcap", tags=["Upload"])
async def upload_pcap(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Upload a PCAP/PCAPng capture file and run the full analysis pipeline.

    Phase 7 Pipeline:
    1. Security validation (extension + magic bytes + size + symlink check)
    2. Scapy packet parsing — max 100,000 packets
    3. HTTP request extraction from TCP payloads
    4. URL deduplication + cap at 500 unique URLs
    5. Each URL passed through the central URL analysis engine (same as /api/analyze)
       - validate_and_normalize()
       - extract_features() — 28-feature vector
       - url_predict() — GradientBoosting ML model
       - analyze_url() — 18 rules + ML blending
    6. Results persisted to pcap_analyses + pcap_records under authenticated user_id

    Security controls:
    - user_id from JWT only — never from request body
    - PCAP file validated before any parsing
    - Temp file guaranteed deleted after processing
    - No subprocess, no shell, no exec
    - Per-URL errors are isolated — one bad URL never fails the whole job
    """
    uid = current_user.id
    set_rls_user(db, uid)

    # ── 1. Extension check (pre-content) ────────────────────────────────
    fname = (file.filename or "upload.pcap")
    ext = os.path.splitext(fname.lower())[1]
    if ext not in _ALLOWED_PCAP_EXTS:
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Upload a .pcap, .pcapng, or .cap file.",
        )

    # ── 2. Read + size check ─────────────────────────────────────────────
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(content) > _MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="File too large. Maximum 50 MB.")

    # ── 3. Write to secure temp file ─────────────────────────────────────
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext, prefix="pcap_") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
    except OSError:
        raise HTTPException(status_code=500, detail="Could not write temporary file.")

    # ── 4. Create pending DB record (user_id from JWT) ───────────────────
    analysis = PCAPAnalysis(
        user_id=uid,
        filename=fname[:255],
        status="processing",
        created_at=datetime.utcnow(),
    )
    db.add(analysis)
    db.flush()

    # ── 5. Run full pipeline ─────────────────────────────────────────────
    try:
        result = process_pcap(tmp_path, cleanup=True)   # deletes tmp_path
        tmp_path = None   # already cleaned up inside process_pcap
    except PCAPValidationError as e:
        analysis.status = "error"
        analysis.error_message = str(e)[:500]
        db.commit()
        raise HTTPException(status_code=422, detail=f"Invalid PCAP file: {e}")
    except RuntimeError as e:
        analysis.status = "error"
        analysis.error_message = str(e)[:500]
        db.commit()
        logger.error("PCAP runtime error uid=...%s: %s", uid[-6:], type(e).__name__)
        raise HTTPException(status_code=422, detail="PCAP parsing failed.")
    except Exception:
        analysis.status = "error"
        analysis.error_message = "Unexpected error during analysis"
        db.commit()
        logger.error("PCAP unexpected error uid=...%s", uid[-6:])
        raise HTTPException(status_code=500, detail="PCAP analysis failed.")
    finally:
        # Guarantee temp file deletion even if process_pcap raised before cleanup
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # ── 6. Update analysis record with results ───────────────────────────
    analysis.status             = "completed"
    analysis.packets_analyzed   = result['packets_analyzed']
    analysis.http_requests      = result['http_requests']
    analysis.urls_extracted     = result['urls_extracted']
    analysis.unique_ips         = result['unique_ips']
    analysis.suspicious_urls    = result['suspicious_urls']
    analysis.high_risk_urls     = result['high_risk_urls']
    analysis.processing_time_ms = result['processing_time_ms']
    analysis.records_extracted  = len(result['records'])

    # ── 7. Persist per-URL records ───────────────────────────────────────
    for rec in result['records']:
        ts = None
        try:
            if rec.get('timestamp'):
                ts = datetime.utcfromtimestamp(float(rec['timestamp']))
        except Exception:
            pass

        db.add(PCAPRecord(
            pcap_analysis_id = analysis.id,
            user_id          = uid,
            source_ip        = (rec.get('source_ip') or '')[:45],
            destination_ip   = (rec.get('destination_ip') or '')[:45],
            url              = (rec.get('url') or '')[:2048],
            method           = (rec.get('method') or '')[:10],
            host             = (rec.get('host') or '')[:253],
            user_agent       = (rec.get('user_agent') or '')[:512],
            port             = rec.get('port'),
            prediction       = rec.get('prediction', 'UNKNOWN'),
            risk_score       = rec.get('risk_score', 0),
            risk_level       = rec.get('risk_level', 'LOW'),
            confidence       = rec.get('confidence', 0.0),
            model_version    = rec.get('model_version', 'urltracer-v1'),
            status           = rec.get('status', 'analysed'),
            timestamp        = ts,
        ))

    db.commit()

    # ── 8. Response ───────────────────────────────────────────────────────
    logger.info(
        "PCAP complete id=%s uid=...%s packets=%d urls=%d threats=%d time=%.0fms",
        analysis.id, uid[-6:],
        result['packets_analyzed'], result['urls_extracted'],
        result['high_risk_urls'], result['processing_time_ms'],
    )

    return {
        "status":             "completed",
        "analysis_id":        analysis.id,
        "packets_analyzed":   result['packets_analyzed'],
        "http_requests":      result['http_requests'],
        "urls_extracted":     result['urls_extracted'],
        "unique_ips":         result['unique_ips'],
        "suspicious_urls":    result['suspicious_urls'],
        "high_risk_urls":     result['high_risk_urls'],
        "processing_time_ms": result['processing_time_ms'],
        "records":            result['records'][:100],   # return first 100 for display
    }
