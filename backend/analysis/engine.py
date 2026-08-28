"""
analysis/engine.py
Main entry point for the URL analysis engine.

This is the ONLY function external callers should import.

Callers:
  - api/analyze.py          (Web API — Phase 3)
  - services/pcap_service.py (PCAP pipeline — Phase 7)
  - Future: Chrome Extension backend endpoint
  - Future: Batch analysis scripts

The engine is:
  ✓ Authentication-free
  ✓ Database-free
  ✓ Network-free (no URL fetching)
  ✓ Framework-free (no FastAPI / React dependencies)
  ✓ Callable from any Python context

Usage:
    from analysis.engine import analyze_url

    result = analyze_url("https://secure-paypal-login.xyz/verify?user=admin")
    print(result.prediction)   # PHISHING
    print(result.risk_score)   # 90
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from analysis.validator import validate_and_normalize, URLValidationError
from analysis.features  import extract_features, features_to_dict, URLFeatures
from analysis.rules     import run_url_rules, RuleFlag
from analysis.scorer    import compute_risk

# Current model/pipeline version
MODEL_VERSION = "urltracer-v1"

# Timeout guard — feature extraction should always be fast,
# but we cap it to prevent edge-case DoS on pathological inputs
MAX_ANALYSIS_MS = 5000


# ─── Result schema ────────────────────────────────────────────────────────────

@dataclass
class URLAnalysisResult:
    """
    Standardized URL analysis result.

    This schema is stable across all callers (Web API, PCAP, extension).
    Adding new fields is backwards-compatible; removing is a breaking change.
    """
    url:              str          # Normalized input URL
    prediction:       str          # BENIGN | SUSPICIOUS | PHISHING | MALWARE
    risk_score:       int          # 0-100
    risk_level:       str          # LOW | MEDIUM | HIGH | CRITICAL
    confidence:       float        # 0.0-1.0
    model_version:    str          # "urltracer-v1"
    features:         dict         # All 28 extracted features
    rule_flags:       list[dict]   # Triggered rules with descriptions
    analysis_time_ms: float        # Wall-clock time for this analysis

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class URLAnalysisError:
    """Returned when the URL cannot be analysed (validation failure)."""
    error:   str
    detail:  str
    url:     Optional[str] = None


# ─── Engine ───────────────────────────────────────────────────────────────────

def analyze_url(
    raw_url: str,
    *,
    ml_prediction:  Optional[str]   = None,
    ml_confidence:  Optional[float] = None,
) -> URLAnalysisResult:
    """
    Analyse a URL and return a standardized result.

    The engine performs:
      1. Validation + normalization (no network)
      2. Feature extraction (28 features, static analysis only)
      3. Rule-based checks (18 rules)
      4. Risk scoring (weighted combination)

    Parameters
    ----------
    raw_url        : Raw URL string from the caller (treated as untrusted input)
    ml_prediction  : Optional Phase 4 ML prediction to blend into the score
    ml_confidence  : Optional Phase 4 ML confidence (0.0-1.0)

    Returns
    -------
    URLAnalysisResult with all fields populated.

    Raises
    ------
    URLValidationError : If the URL cannot be safely parsed.
    """
    t0 = time.perf_counter()

    # ── Step 1: Validate + normalize ────────────────────────────────────────
    # URLValidationError propagates to caller for proper HTTP 422 response
    url = validate_and_normalize(raw_url)

    # ── Step 2: Extract features ────────────────────────────────────────────
    features: URLFeatures = extract_features(url)

    # ── Step 3: Run static rules ────────────────────────────────────────────
    flags: list[RuleFlag] = run_url_rules(url, features)

    # ── Step 4: Compute risk ─────────────────────────────────────────────────
    risk = compute_risk(
        features,
        flags,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
    )

    elapsed_ms = (time.perf_counter() - t0) * 1000

    return URLAnalysisResult(
        url=url,
        prediction=risk["prediction"],
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        confidence=risk["confidence"],
        model_version=MODEL_VERSION,
        features=features_to_dict(features),
        rule_flags=[f.to_dict() for f in flags],
        analysis_time_ms=round(elapsed_ms, 2),
    )
