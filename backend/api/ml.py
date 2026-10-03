"""
api/ml.py
ML REST endpoints.

GET  /api/ml/status        — Model availability, version, metrics summary
POST /api/ml/predict       — Single URL prediction
POST /api/ml/predict/batch — Batch URL predictions
GET  /api/ml/metrics       — Full training metrics from last build
"""

import json
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from services.ml_service import predict as ml_predict, batch_predict as ml_batch, get_ml_status

logger = logging.getLogger(__name__)
router = APIRouter()

# model_info.json written by build_model.py during Render build step
_MODELS_DIR  = Path(__file__).parent.parent / "models"
_INFO_FILE   = _MODELS_DIR / "model_info.json"


# ── Schemas ───────────────────────────────────────────────────────────────────

class MLRequest(BaseModel):
    url:           str            = Field(..., example="http://paypal-secure.verify-account.tk/signin")
    method:        Optional[str]  = Field("GET",  example="GET")
    host:          Optional[str]  = Field(None,   example="paypal-secure.verify-account.tk")
    user_agent:    Optional[str]  = Field(None,   example="Mozilla/5.0")
    status_code:   Optional[int]  = Field(None,   example=200)
    response_size: Optional[int]  = Field(None,   example=1024)


class MLResponse(BaseModel):
    prediction:   str
    confidence:   float
    model:        str
    ml_available: bool


class BatchMLRequest(BaseModel):
    records: list[MLRequest] = Field(..., min_length=1, max_length=500)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/ml/status", tags=["ML"])
def ml_status():
    """
    Returns the current ML model status.

    When the model is available, includes version, algorithm, feature schema,
    training date, and F1 score from the held-out test set.
    """
    return get_ml_status()


@router.post("/ml/predict", response_model=MLResponse, tags=["ML"])
def ml_predict_single(req: MLRequest):
    """
    Analyse a URL with the trained RandomForest classifier.

    Returns the predicted threat class (Benign / Phishing / Malware)
    and confidence score. Falls back to rule-based heuristic if the
    model is not available.
    """
    result = ml_predict(req.model_dump())
    return MLResponse(**result)


@router.post("/ml/predict/batch", tags=["ML"])
def ml_predict_batch(req: BatchMLRequest):
    """
    Run batch URL threat predictions.

    Returns predictions in the same order as the input list.
    """
    records = [r.model_dump() for r in req.records]
    results = ml_batch(records)
    return {
        "count":   len(results),
        "results": results,
    }


@router.get("/ml/metrics", tags=["ML"])
def ml_metrics():
    """
    Return full training metrics from the most recent model build.

    Written by build_model.py during the Render build step.
    Includes accuracy, precision, recall, F1 macro, per-class report,
    feature importances, and training metadata.
    """
    if not _INFO_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "No model metrics found. The model has not been built yet. "
                "Check the Render build logs for errors from build_model.py."
            ),
        )
    try:
        return json.loads(_INFO_FILE.read_text())
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not read metrics: {exc}")
