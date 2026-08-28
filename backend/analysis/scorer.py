"""
analysis/scorer.py
Risk score computation from features + rule flags + optional ML result.

Combines signals from three sources:
  1. Rule-based flags (severity-weighted)
  2. Feature heuristics (direct score contributions)
  3. ML model prediction (if available — Phase 4)

Output:
  risk_score  : 0-100 (integer)
  risk_level  : LOW | MEDIUM | HIGH | CRITICAL
  prediction  : BENIGN | SUSPICIOUS | PHISHING | MALWARE
  confidence  : 0.0-1.0
"""

from __future__ import annotations

from analysis.features import URLFeatures
from analysis.rules import RuleFlag

# ─── Severity weights ─────────────────────────────────────────────────────────
# Points added to the raw score per triggered rule severity

_SEVERITY_POINTS: dict[str, int] = {
    "LOW":      5,
    "MEDIUM":   15,
    "HIGH":     25,
    "CRITICAL": 40,
}

# ─── Risk level thresholds ────────────────────────────────────────────────────

def _score_to_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _score_to_prediction(score: int) -> str:
    if score >= 75:
        return "PHISHING"
    if score >= 50:
        return "SUSPICIOUS"
    if score >= 25:
        return "SUSPICIOUS"
    return "BENIGN"


def _score_to_confidence(score: int, num_flags: int) -> float:
    """
    Estimate confidence from the score magnitude and number of corroborating flags.
    More flags = higher confidence the classification is correct.
    """
    base = min(score / 100.0, 1.0)
    # Corroboration bonus: each flag above 1 adds a small confidence boost
    corroboration = min(0.05 * max(0, num_flags - 1), 0.20)
    return round(min(base + corroboration, 0.99), 2)


# ─── Main scorer ─────────────────────────────────────────────────────────────

def compute_risk(
    features: URLFeatures,
    flags: list[RuleFlag],
    ml_prediction: str | None = None,
    ml_confidence: float | None = None,
) -> dict:
    """
    Combine rule flags and ML output into a unified risk score.

    Parameters
    ----------
    features       : Extracted URLFeatures
    flags          : Triggered RuleFlags from rules.py
    ml_prediction  : Optional prediction string from Phase 4 ML model
    ml_confidence  : Optional confidence float from Phase 4 ML model

    Returns
    -------
    dict with: risk_score, risk_level, prediction, confidence
    """
    # ── 1. Rule-based score ────────────────────────────────────────────────
    rule_score = sum(_SEVERITY_POINTS.get(f.severity, 0) for f in flags)

    # ── 2. Feature heuristic bonus ─────────────────────────────────────────
    heuristic = 0

    # HTTPS absence + other suspicious signals amplifies risk
    if not features.has_https and rule_score > 0:
        heuristic += 5

    # IP host is already covered by rule R01 (CRITICAL), no double-count needed

    # Very long URL on top of other flags
    if features.url_length > 200 and rule_score > 0:
        heuristic += 5

    # Many encoded chars
    if features.num_encoded_chars > 5:
        heuristic += min(features.num_encoded_chars, 10)

    # Entropy boost
    if features.url_entropy > 4.0:
        heuristic += int((features.url_entropy - 4.0) * 5)

    raw_score = rule_score + heuristic

    # ── 3. ML model override / blend (Phase 4+) ───────────────────────────
    if ml_prediction and ml_confidence is not None:
        ml_score = _ml_to_score(ml_prediction, ml_confidence)
        # Weighted blend: 60% rules + 40% ML
        raw_score = int(0.60 * raw_score + 0.40 * ml_score)

    # ── 4. Clamp to 0-100 ─────────────────────────────────────────────────
    risk_score = max(0, min(100, raw_score))

    risk_level  = _score_to_level(risk_score)
    prediction  = ml_prediction if ml_prediction else _score_to_prediction(risk_score)
    confidence  = (
        ml_confidence if ml_confidence is not None
        else _score_to_confidence(risk_score, len(flags))
    )

    return {
        "risk_score":  risk_score,
        "risk_level":  risk_level,
        "prediction":  prediction,
        "confidence":  confidence,
    }


def _ml_to_score(prediction: str, confidence: float) -> int:
    """Convert an ML prediction + confidence to a 0-100 numeric score."""
    base = {
        "PHISHING":   90,
        "MALWARE":    95,
        "SUSPICIOUS": 55,
        "BENIGN":     5,
    }.get(prediction.upper(), 50)
    # Scale by confidence so a low-confidence PHISHING still signals risk
    return int(base * confidence)
