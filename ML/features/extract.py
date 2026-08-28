"""
ML/features/extract.py
Batch feature extraction for training.

This module wraps backend/analysis/features.py - the SAME feature extractor
used at inference time in the URL analysis engine (Phase 3).

This is the single enforcement point of the feature schema invariant:
  Training features == Inference features (zero train/serve skew)

Usage:
    from ML.features.extract import build_feature_matrix
    X, y, failed = build_feature_matrix(rows)
"""

import os
import sys
import logging
from typing import Optional

import numpy as np

# -- Add backend/ to path so we can import backend/analysis/features.py ------
_BACKEND = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "backend")
)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analysis.features import extract_features, features_to_ml_vector, ML_FEATURE_NAMES
from analysis.validator import validate_and_normalize, URLValidationError

logger = logging.getLogger(__name__)


# -- Label encoding ------------------------------------------------------------

LABEL_MAP = {
    "BENIGN":     0,
    "PHISHING":   1,
    "MALWARE":    2,
    "SUSPICIOUS": 1,   # Map SUSPICIOUS -> PHISHING for binary/ternary classification
}

LABEL_NAMES = ["BENIGN", "PHISHING", "MALWARE"]


def encode_label(label: str) -> Optional[int]:
    return LABEL_MAP.get(label.upper())


def decode_label(idx: int) -> str:
    if 0 <= idx < len(LABEL_NAMES):
        return LABEL_NAMES[idx]
    return "UNKNOWN"


# -- Feature extraction --------------------------------------------------------

def extract_row(url: str) -> Optional[list[float]]:
    """
    Extract the ML feature vector for a single URL.

    Returns None if the URL fails validation or feature extraction.
    This uses the EXACT same code path as Phase 3 inference.
    """
    try:
        normalized = validate_and_normalize(url)
        features   = extract_features(normalized)
        return features_to_ml_vector(features)
    except URLValidationError:
        return None
    except Exception as e:
        logger.debug(f"Feature extraction failed for URL '{url[:60]}': {e}")
        return None


def build_feature_matrix(
    rows: list[dict],
    log_every: int = 10000,
) -> tuple[np.ndarray, np.ndarray, int]:
    """
    Build feature matrix X and label vector y from a list of {url, label} dicts.

    Parameters
    ----------
    rows      : list of {"url": str, "label": str}
    log_every : log progress every N rows

    Returns
    -------
    X       : np.ndarray shape (n_valid, n_features)
    y       : np.ndarray shape (n_valid,)  int labels
    failed  : number of rows dropped due to validation/extraction errors
    """
    X_rows = []
    y_vals = []
    failed = 0

    total = len(rows)
    for i, row in enumerate(rows, 1):
        if i % log_every == 0 or i == total:
            print(f"  [extract] {i:,}/{total:,} rows processed … ({failed:,} failed)")

        url   = row.get("url", "")
        label = row.get("label", "")

        enc = encode_label(label)
        if enc is None:
            failed += 1
            continue

        vec = extract_row(url)
        if vec is None:
            failed += 1
            continue

        X_rows.append(vec)
        y_vals.append(enc)

    X = np.array(X_rows, dtype=np.float32)
    y = np.array(y_vals, dtype=np.int32)

    print(f"  [extract] Done - {len(X):,} rows, {failed:,} failed")
    print(f"  [extract] Feature matrix shape: {X.shape}")
    print(f"  [extract] Label distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

    return X, y, failed


def get_feature_names() -> list[str]:
    """Return the stable ordered list of feature names."""
    return list(ML_FEATURE_NAMES)
