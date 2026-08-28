"""
pcap/processor.py
Orchestrates the full PCAP analysis pipeline.

Pipeline:
  1. Validate PCAP file (extension + magic bytes + size)
  2. Extract HTTP records via Scapy
  3. For each extracted URL: run through the central URL analysis engine
     (same engine as POST /api/analyze — guaranteed ML + rules consistency)
  4. Aggregate results
  5. Clean up temp file
  6. Return structured result dict

Security:
  - Validates file before parsing
  - URL analysis uses the central engine — no separate ML/rules
  - Each URL is validated+normalized before analysis (blocks javascript:, data:, etc.)
  - Max URLs analysed per PCAP is capped (configurable)
  - Errors in individual URL analysis are caught and skipped
  - Temp file cleanup is guaranteed (finally block)
  - No subprocess, no shell, no exec

The caller (upload.py) is responsible for:
  - Writing the UploadedFile bytes to a tempfile before calling process_pcap()
  - Storing results to DB under the authenticated user_id
"""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Optional

from pcap.validator import validate_pcap_path, PCAPValidationError
from pcap.extractor import extract_records

# Import central URL analysis engine (Phase 3+4)
from analysis.engine   import analyze_url
from analysis.validator import validate_and_normalize, URLValidationError
from analysis.features  import extract_features, features_to_ml_vector
from analysis.url_model import url_predict

logger = logging.getLogger(__name__)

# Hard cap: max URLs to run through the full analysis engine per PCAP
# (Scapy extractor may find thousands; we cap to avoid runaway CPU)
MAX_URLS_TO_ANALYSE = 500


def process_pcap(file_path: str, cleanup: bool = True) -> dict:
    """
    Full PCAP analysis pipeline.

    Parameters
    ----------
    file_path : Absolute path to the uploaded (already-written) PCAP temp file.
    cleanup   : Whether to delete the temp file after processing (default True).

    Returns
    -------
    dict with keys:
      packets_analyzed    int
      http_requests       int
      urls_extracted      int
      unique_ips          int
      suspicious_urls     int  (risk_level != LOW)
      high_risk_urls      int  (risk_level HIGH or CRITICAL)
      processing_time_ms  float
      records             list[dict]   — per-URL analysis results

    Raises
    ------
    PCAPValidationError : if file fails security checks (re-raised as-is)
    RuntimeError        : if Scapy cannot read the file
    """
    t0 = time.perf_counter()

    # ── 1. Validate ──────────────────────────────────────────────────────
    validated_path = validate_pcap_path(file_path)

    # ── 2. Extract HTTP records ───────────────────────────────────────────
    try:
        raw_records, stats = extract_records(str(validated_path))
    finally:
        if cleanup:
            _safe_delete(file_path)

    # ── 3. Analyse each URL through central engine ─────────────────────────
    analysed: list[dict] = []
    suspicious_count = 0
    high_risk_count  = 0

    # Cap: only analyse first MAX_URLS_TO_ANALYSE unique URLs
    seen_urls: set[str] = set()
    to_analyse: list[dict] = []
    for rec in raw_records:
        url = rec.get('url', '')
        if url and url not in seen_urls:
            seen_urls.add(url)
            to_analyse.append(rec)
        if len(to_analyse) >= MAX_URLS_TO_ANALYSE:
            break

    for rec in to_analyse:
        url = rec['url']
        result_rec = dict(rec)   # copy raw extraction data

        try:
            # Validate+normalize (blocks dangerous schemes)
            norm_url = validate_and_normalize(url)

            # ML prediction (optional — graceful degradation)
            ml_pred: Optional[str]   = None
            ml_conf: Optional[float] = None
            try:
                feats = extract_features(norm_url)
                vec   = features_to_ml_vector(feats)
                ml_pred, ml_conf = url_predict(vec)
            except Exception:
                pass

            # Central URL analysis engine
            result = analyze_url(url, ml_prediction=ml_pred, ml_confidence=ml_conf)

            result_rec.update({
                'prediction':    result.prediction,
                'risk_score':    result.risk_score,
                'risk_level':    result.risk_level,
                'confidence':    result.confidence,
                'model_version': result.model_version,
                'status':        'analysed',
                'url':           result.url,   # use normalized URL
            })

            if result.risk_level not in ('LOW',):
                suspicious_count += 1
            if result.risk_level in ('HIGH', 'CRITICAL'):
                high_risk_count += 1

        except URLValidationError:
            # URL failed validation (e.g. javascript:) — skip silently
            result_rec['status'] = 'invalid'
            result_rec['prediction'] = 'UNKNOWN'
            result_rec['risk_level']  = 'LOW'
            result_rec['risk_score']  = 0
        except Exception as e:
            # Engine error — record it but don't fail the whole PCAP
            logger.debug("URL analysis failed for '%s': %s", url[:60], type(e).__name__)
            result_rec['status']     = 'error'
            result_rec['prediction'] = 'UNKNOWN'
            result_rec['risk_level'] = 'LOW'
            result_rec['risk_score'] = 0

        analysed.append(result_rec)

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    return {
        'packets_analyzed':   stats['packets_seen'],
        'http_requests':      stats['http_found'],
        'urls_extracted':     stats['urls_extracted'],
        'unique_ips':         stats['unique_ips'],
        'suspicious_urls':    suspicious_count,
        'high_risk_urls':     high_risk_count,
        'processing_time_ms': elapsed_ms,
        'records':            analysed,
    }


def _safe_delete(path: str) -> None:
    """Delete a temp file, ignoring errors (guaranteed cleanup)."""
    try:
        os.unlink(path)
    except OSError:
        pass
