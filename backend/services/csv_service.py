"""
services/csv_service.py
CSV Upload Processing Pipeline.

Phase 2: Accepts user_id and injects it into all DB records.
         _upsert_ip_analysis now scoped per-user (user_id, ip_address unique pair).

Flow:
  CSV bytes → validate → normalize → detect → ML → risk score → PostgreSQL → summary
"""

import io
import json
from datetime import datetime
from typing import Optional

import pandas as pd
from sqlalchemy.orm import Session

from models import Request, Detection, IPAnalysis, Upload
from detection.engine import run_detection
from services.ml_service import predict
from risk.scorer import calculate_risk_score, get_risk_level
from utils.normalizer import normalize_columns, normalize_row, parse_timestamp

_REQUIRED_COLS = {"source_ip"}
_MAX_ROWS = 5_000


class CSVValidationError(Exception):
    pass


def process_csv_upload(
    file_content: bytes,
    filename: str,
    db: Session,
    user_id: str = "",          # ← Phase 2: always passed from verified JWT
) -> dict:
    """
    Full CSV processing pipeline. All records tagged with user_id.

    Returns
    -------
    dict: status, upload_id, records_processed, attacks_detected, high_risk_ips
    """
    # ── 1. Create upload record ─────────────────────────────────────────
    upload = Upload(
        user_id=user_id,
        filename=filename,
        file_type="csv",
        status="processing",
        uploaded_at=datetime.utcnow(),
    )
    db.add(upload)
    db.flush()

    try:
        # ── 2. Read CSV ─────────────────────────────────────────────────
        try:
            df = pd.read_csv(io.BytesIO(file_content), dtype=str, nrows=_MAX_ROWS)
        except Exception as e:
            raise CSVValidationError(f"Cannot parse CSV: {e}")

        if df.empty:
            raise CSVValidationError("CSV file is empty.")

        # ── 3. Normalize column names ───────────────────────────────────
        col_map = normalize_columns(list(df.columns))
        if not any(v == "source_ip" for v in col_map.values()):
            raise CSVValidationError(
                "CSV must contain a source IP column "
                "(e.g., source_ip, src_ip, clientip, ip)."
            )

        # ── 4. Process each row ─────────────────────────────────────────
        ip_detections: dict[str, list[dict]] = {}
        ip_request_counts: dict[str, int] = {}
        records_processed = 0
        attacks_detected = 0

        for _, raw_row in df.iterrows():
            record = normalize_row(raw_row.to_dict(), col_map)
            if record is None:
                continue

            source_ip = record["source_ip"]
            ip_request_counts[source_ip] = ip_request_counts.get(source_ip, 0) + 1

            # ── Store request ───────────────────────────────────────────
            req_obj = Request(
                timestamp=parse_timestamp(record.get("timestamp")),
                source_ip=source_ip,
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

            # ── 5. Rule-based detection ─────────────────────────────────
            det_result = run_detection(record)

            # ── 6. ML supplementation ───────────────────────────────────
            if det_result is None:
                ml_result = predict(record)
                if ml_result["prediction"] != "Benign" and ml_result["confidence"] >= 0.70:
                    det_result = {
                        "attack_type": ml_result["prediction"],
                        "severity": _ml_severity(ml_result["prediction"]),
                        "confidence": ml_result["confidence"],
                        "detection_method": "ML",
                        "result": "ATTEMPT",
                    }
            elif det_result:
                det_result["detection_method"] = "HYBRID"

            if det_result:
                db.add(Detection(
                    user_id=user_id,                  # ← Phase 2: tagged to user
                    request_id=req_obj.id,
                    attack_type=det_result["attack_type"],
                    severity=det_result["severity"],
                    confidence=det_result["confidence"],
                    detection_method=det_result["detection_method"],
                    result=det_result["result"],
                    source_ip=source_ip,
                    url=record.get("url"),
                    host=record.get("host"),
                ))
                attacks_detected += 1
                ip_detections.setdefault(source_ip, []).append(det_result)

            records_processed += 1

        # ── 7. IP risk scores ───────────────────────────────────────────
        high_risk_ips = _upsert_ip_analysis(
            db, ip_detections, ip_request_counts, user_id=user_id
        )

        # ── 8. Finalise upload record ───────────────────────────────────
        upload.records_processed = records_processed
        upload.attacks_detected = attacks_detected
        upload.high_risk_ips = high_risk_ips
        upload.status = "completed"
        db.commit()

        return {
            "status": "completed",
            "upload_id": upload.id,
            "records_processed": records_processed,
            "attacks_detected": attacks_detected,
            "high_risk_ips": high_risk_ips,
        }

    except CSVValidationError as e:
        upload.status = "error"
        upload.error_message = str(e)[:500]
        db.commit()
        raise
    except Exception as e:
        upload.status = "error"
        upload.error_message = str(e)[:500]
        db.commit()
        raise


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _ml_severity(attack_type: str) -> str:
    critical = {"Command Injection", "Web Shell"}
    high = {
        "SQL Injection", "SSRF", "LFI/RFI", "XXE",
        "Directory Traversal", "Brute Force", "Credential Stuffing",
    }
    if attack_type in critical:
        return "CRITICAL"
    if attack_type in high:
        return "HIGH"
    return "MEDIUM"


def _upsert_ip_analysis(
    db: Session,
    ip_detections: dict[str, list[dict]],
    ip_request_counts: dict[str, int],
    user_id: str = "",          # ← Phase 2: per-user IP profiles
) -> int:
    """
    Upsert ip_analysis rows for every IP seen in this upload.
    Uniqueness is (user_id, ip_address) — each user has their own IP risk profile.
    Returns the count of HIGH/CRITICAL IPs.
    """
    high_risk_count = 0
    all_ips = set(ip_detections.keys()) | set(ip_request_counts.keys())

    for ip in all_ips:
        dets = ip_detections.get(ip, [])
        req_count = ip_request_counts.get(ip, 0)

        risk = calculate_risk_score(dets, request_count=req_count)
        attack_types = list({d["attack_type"] for d in dets})

        # Lookup existing row for THIS user and IP
        existing = (
            db.query(IPAnalysis)
            .filter(IPAnalysis.user_id == user_id, IPAnalysis.ip_address == ip)
            .first()
        )

        if existing:
            existing_types = json.loads(existing.attack_types or "[]")
            merged_types = list(set(existing_types + attack_types))
            new_score = existing.risk_score + risk["risk_score"]
            existing.risk_score = new_score
            existing.risk_level = get_risk_level(new_score)
            existing.attack_count = existing.attack_count + len(dets)
            existing.request_count = existing.request_count + req_count
            existing.attack_types = json.dumps(merged_types)
            existing.last_seen = datetime.utcnow()
        else:
            ip_obj = IPAnalysis(
                user_id=user_id,
                ip_address=ip,
                risk_score=risk["risk_score"],
                risk_level=risk["risk_level"],
                attack_count=len(dets),
                request_count=req_count,
                attack_types=json.dumps(attack_types),
                last_seen=datetime.utcnow() if dets else None,
            )
            db.add(ip_obj)
            existing = ip_obj

        if existing.risk_level in {"HIGH", "CRITICAL"}:
            high_risk_count += 1

    db.flush()
    return high_risk_count
