"""
backend/analysis/url_model.py
Loads the trained URL phishing model and exposes url_predict().

This module provides the ML bridge between:
  - ML/models/url_phishing_model.pkl  (trained by Phase 4 pipeline)
  - analysis/engine.py                (calls url_predict() before rule scoring)

Graceful degradation:
  If model artifact is not found (not yet trained), returns (None, None).
  The engine still works using rule-based scoring alone.

Thread safety:
  Model is loaded once at module import time. joblib models are read-only
  at inference and safe to use from multiple threads/workers.
"""

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Model path ────────────────────────────────────────────────────────────────
# Relative to project root; works whether backend is run from root or backend/
_PROJECT_ROOT = Path(__file__).parent.parent.parent
_MODEL_PKL    = _PROJECT_ROOT / "ML" / "models" / "url_phishing_model.pkl"
_MODEL_INFO   = _PROJECT_ROOT / "ML" / "models" / "model_info.json"

# ── Label index → prediction string ──────────────────────────────────────────
_LABEL_MAP = {0: "BENIGN", 1: "PHISHING", 2: "MALWARE"}

# ── Module-level state ────────────────────────────────────────────────────────
_model       = None
_model_info  = {}
_loaded      = False
_load_error  = None


def _load_once():
    """Load the model once at import time. Safe to call multiple times."""
    global _model, _model_info, _loaded, _load_error

    if _loaded:
        return

    if not _MODEL_PKL.exists():
        logger.info(
            "[url_model] Model artifact not found at %s. "
            "Run: python ML/training/train.py  "
            "Engine will use rule-based scoring only.",
            _MODEL_PKL,
        )
        _loaded = True
        return

    try:
        import joblib
        _model = joblib.load(_MODEL_PKL)
        logger.info("[url_model] ✓ URL phishing model loaded from %s", _MODEL_PKL)

        if _MODEL_INFO.exists():
            import json
            _model_info = json.loads(_MODEL_INFO.read_text())
            ver = _model_info.get("model_version", "?")
            algo = _model_info.get("algorithm", "?")
            logger.info("[url_model] Version: %s  Algorithm: %s", ver, algo)

    except Exception as e:
        _load_error = str(e)
        logger.warning("[url_model] Failed to load model: %s. Using rule-based fallback.", e)

    _loaded = True


# Load at import time
_load_once()


# ── Public interface ──────────────────────────────────────────────────────────

def url_predict(feature_vector: list[float]) -> tuple[Optional[str], Optional[float]]:
    """
    Run ML prediction on a pre-extracted feature vector.

    Parameters
    ----------
    feature_vector : 28-element float list from features_to_ml_vector()

    Returns
    -------
    (prediction, confidence) — e.g. ("PHISHING", 0.93)
    (None, None)             — if model is unavailable (graceful degradation)
    """
    if _model is None:
        return None, None

    try:
        import numpy as np
        X = np.array([feature_vector], dtype=np.float32)

        pred_idx   = int(_model.predict(X)[0])
        prediction = _LABEL_MAP.get(pred_idx, "UNKNOWN")

        # Probability of the predicted class
        if hasattr(_model, "predict_proba"):
            proba = _model.predict_proba(X)[0]
            confidence = float(proba[pred_idx])
        else:
            confidence = 0.75  # fallback for models without predict_proba

        return prediction, round(confidence, 4)

    except Exception as e:
        logger.warning("[url_model] Prediction error: %s", e)
        return None, None


def get_model_status() -> dict:
    """Return model availability and metadata for the /api/ml/status endpoint."""
    return {
        "url_model_available": _model is not None,
        "model_version":       _model_info.get("model_version"),
        "algorithm":           _model_info.get("algorithm"),
        "feature_version":     _model_info.get("feature_version"),
        "training_date":       _model_info.get("training_date"),
        "num_features":        _model_info.get("num_features"),
        "test_f1_macro":       _model_info.get("test_evaluation", {}).get("f1_macro"),
        "test_roc_auc":        _model_info.get("test_evaluation", {}).get("roc_auc"),
        "load_error":          _load_error,
    }
