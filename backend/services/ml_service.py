"""
services/ml_service.py
URL-based ML prediction service.

Bridges the FastAPI endpoints to the trained RandomForest model in
analysis/url_model.py. Uses the same feature extractor as the analysis
engine — guaranteeing train/inference consistency.

Graceful degradation:
  - Model available  → RandomForest prediction (BENIGN/PHISHING/MALWARE)
  - Model unavailable → rule-based heuristic fallback
"""

import logging
import sys
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Make sure analysis/ is importable (backend/ must be on sys.path)
_BACKEND = Path(__file__).parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from analysis.url_model import url_predict, get_model_status
from analysis.features import extract_features, features_to_ml_vector

# ── Label mapping ─────────────────────────────────────────────────────────────
_LABEL_TO_ATTACK = {
    "BENIGN":   "Benign",
    "PHISHING": "Phishing",
    "MALWARE":  "Malware",
}

# ── Heuristic fallback (used only when model is unavailable) ──────────────────
_KEYWORD_MAP: list[tuple[str, list[str]]] = [
    ("SQL Injection",           ["union", "select", "drop", "insert", "1=1", "or '", "sleep(", "benchmark("]),
    ("Command Injection",       ["whoami", "ls ", "cat /", "; id", "$(", "&& ", "| bash", "wget ", "curl "]),
    ("Directory Traversal",     ["../", "%2e%2e", "/etc/passwd", "boot.ini"]),
    ("XSS",                     ["<script", "onerror=", "javascript:", "alert(", "document.cookie"]),
    ("SSRF",                    ["169.254", "localhost", "127.0.0.1", "metadata.google"]),
    ("LFI/RFI",                 ["php://", "file://", "include=http", "page=http"]),
    ("Phishing",                ["secure-login", "verify-account", "account-update", "signin-verify"]),
    ("Web Shell",               [".php?cmd=", "shell_exec", "passthru(", "system("]),
    ("Brute Force",             ["/wp-login", "/admin/login", "/auth/login"]),
]


def _heuristic_predict(url: str) -> dict:
    """Rule-based fallback when the ML model is not available."""
    text = url.lower()
    scores: dict[str, float] = {}
    for attack_type, keywords in _KEYWORD_MAP:
        hits = sum(1 for kw in keywords if kw.lower() in text)
        if hits:
            scores[attack_type] = min(0.55 + hits * 0.07, 0.92)

    if not scores:
        return {
            "prediction":   "Benign",
            "confidence":   0.85,
            "model":        "heuristic",
            "ml_available": False,
        }
    best = max(scores, key=lambda k: scores[k])
    return {
        "prediction":   best,
        "confidence":   round(scores[best], 2),
        "model":        "heuristic",
        "ml_available": False,
    }


# ── Public interface ──────────────────────────────────────────────────────────

def predict(request_data: dict) -> dict:
    """
    Predict threat type from a URL (and optional metadata).

    Parameters
    ----------
    request_data : dict
        Must contain 'url'. Other fields (method, host, etc.) are accepted
        but not used — the model works on URL features only.

    Returns
    -------
    dict:
        prediction   : str    — "Benign" | "Phishing" | "Malware" | attack type
        confidence   : float  — [0.0, 1.0]
        model        : str    — "RandomForest-v2.0.0" | "heuristic"
        ml_available : bool
    """
    url = (request_data.get("url") or "").strip()
    if not url:
        return {"prediction": "Benign", "confidence": 0.5, "model": "heuristic", "ml_available": False}

    status = get_model_status()
    if status.get("url_model_available"):
        try:
            feats  = extract_features(url)
            vector = features_to_ml_vector(feats)
            prediction, confidence = url_predict(vector)
            if prediction is not None:
                return {
                    "prediction":   _LABEL_TO_ATTACK.get(prediction, prediction),
                    "confidence":   confidence or 0.75,
                    "model":        f"RandomForest-v{status.get('model_version', '2.0.0')}",
                    "ml_available": True,
                }
        except Exception as exc:
            logger.warning("[ml_service] Prediction error: %s — falling back to heuristic", exc)

    return _heuristic_predict(url)


def batch_predict(records: list[dict]) -> list[dict]:
    """Run predict() over a list of request records."""
    return [predict(r) for r in records]


def get_ml_status() -> dict:
    """Return ML model availability status for GET /api/ml/status."""
    status = get_model_status()
    return {
        "ml_available":    status.get("url_model_available", False),
        "model_version":   status.get("model_version"),
        "algorithm":       status.get("algorithm"),
        "feature_version": status.get("feature_version"),
        "training_date":   status.get("training_date"),
        "num_features":    status.get("num_features"),
        "f1_macro":        status.get("test_f1_macro"),
        "load_error":      status.get("load_error"),
    }
