"""
backend/prepare_training_data.py
=================================
One-time local preprocessing script.
Run this ONCE after downloading the Kaggle dataset, then commit the output.

Usage:
    python prepare_training_data.py --input path/to/malicious_phish.csv
    python prepare_training_data.py --input path/to/malicious_phish.csv --sample 100000

Input:
    malicious_phish.csv from Kaggle:
    https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
    Columns: url (str), type (benign|phishing|malware|defacement)

Output:
    backend/training_data/training_data.npz
      - X: float32 array (N, 28) — feature vectors
      - y: int32 array  (N,)     — labels: 0=BENIGN 1=PHISHING 2=MALWARE
    backend/training_data/dataset_info.json
      — stats about the processed dataset

Commit both output files to git. build_model.py reads them at Render build time.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("prepare")

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE      = Path(__file__).parent
_OUT_DIR   = _HERE / "training_data"
_OUT_NPZ   = _OUT_DIR / "training_data.npz"
_OUT_INFO  = _OUT_DIR / "dataset_info.json"

# ── Label mapping ─────────────────────────────────────────────────────────────
# malicious_phish.csv has 4 classes — we fold defacement into MALWARE (2)
LABEL_MAP = {
    "benign":      0,
    "phishing":    1,
    "malware":     2,
    "defacement":  2,   # defaced sites often serve malware
}
LABEL_NAMES = {0: "BENIGN", 1: "PHISHING", 2: "MALWARE"}


def prepare(csv_path: str, sample: int | None) -> None:
    log.info("=" * 60)
    log.info("URL Tracer — Training Data Preparation")
    log.info("=" * 60)

    # ── Step 1: Import deps ──────────────────────────────────────────────────
    log.info("[1/4] Importing dependencies...")
    try:
        import numpy as np
        import pandas as pd
    except ImportError as e:
        log.error("Missing: %s  — pip install numpy pandas", e)
        sys.exit(1)

    sys.path.insert(0, str(_HERE))
    from analysis.features import extract_features, features_to_ml_vector

    # ── Step 2: Load CSV ─────────────────────────────────────────────────────
    log.info("[2/4] Loading %s ...", csv_path)
    if not Path(csv_path).exists():
        log.error("File not found: %s", csv_path)
        log.error("Download from: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset")
        sys.exit(1)

    df = pd.read_csv(csv_path)
    log.info("      Loaded %d rows. Columns: %s", len(df), list(df.columns))

    # Normalize column names
    df.columns = [c.strip().lower() for c in df.columns]
    if "url" not in df.columns or "type" not in df.columns:
        log.error("Expected columns 'url' and 'type'. Got: %s", list(df.columns))
        sys.exit(1)

    df = df[["url", "type"]].dropna()
    df["type"] = df["type"].str.strip().str.lower()

    # Filter to known labels only
    known = set(LABEL_MAP.keys())
    df = df[df["type"].isin(known)].copy()
    df["label"] = df["type"].map(LABEL_MAP)

    log.info("      After filtering: %d rows", len(df))
    for t, grp in df.groupby("type"):
        log.info("      %-15s %d rows -> label %d (%s)",
                 t, len(grp), LABEL_MAP[t], LABEL_NAMES[LABEL_MAP[t]])

    # ── Step 3: Sample ───────────────────────────────────────────────────────
    if sample and sample < len(df):
        log.info("      Sampling %d rows (stratified) from %d...", sample, len(df))
        df = (
            df.groupby("label", group_keys=False)
              .apply(lambda g: g.sample(
                  min(len(g), int(sample * len(g) / len(df))),
                  random_state=42
              ))
        )
        log.info("      Sample size: %d rows", len(df))

    # ── Step 4: Extract features ─────────────────────────────────────────────
    log.info("[3/4] Extracting features using analysis/features.py ...")
    log.info("      This uses the SAME extractor as production inference.")
    log.info("      Processing %d URLs (may take a few minutes)...", len(df))

    X_list, y_list, errors = [], [], 0
    t0 = time.time()
    urls   = df["url"].tolist()
    labels = df["label"].tolist()

    for i, (url, label) in enumerate(zip(urls, labels)):
        if i % 10000 == 0 and i > 0:
            elapsed = time.time() - t0
            rate    = i / elapsed
            remain  = (len(urls) - i) / rate
            log.info("      %d / %d  (%.0f URLs/s, ~%.0fs remaining)",
                     i, len(urls), rate, remain)
        try:
            feats = extract_features(str(url).strip())
            vec   = features_to_ml_vector(feats)
            X_list.append(vec)
            y_list.append(int(label))
        except Exception:
            errors += 1

    log.info("      Done. %d features extracted, %d errors skipped.", len(X_list), errors)

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)
    log.info("      X shape: %s   y shape: %s", X.shape, y.shape)

    # ── Step 5: Save ─────────────────────────────────────────────────────────
    log.info("[4/4] Saving to %s ...", _OUT_NPZ)
    _OUT_DIR.mkdir(parents=True, exist_ok=True)

    np.savez_compressed(_OUT_NPZ, X=X, y=y)
    size_kb = _OUT_NPZ.stat().st_size / 1024
    log.info("      Saved (%.1f KB compressed)", size_kb)

    # Save info JSON
    from datetime import datetime, timezone
    label_dist = {}
    for lbl, name in LABEL_NAMES.items():
        count = int((y == lbl).sum())
        label_dist[name] = count

    info = {
        "source":        "malicious_phish.csv (Kaggle: sid321axn/malicious-urls-dataset)",
        "total_samples": int(X.shape[0]),
        "num_features":  int(X.shape[1]),
        "label_distribution": label_dist,
        "label_map":     {str(k): v for k, v in LABEL_NAMES.items()},
        "errors_skipped": errors,
        "feature_version": "urltracer-v1",
        "prepared_at":   datetime.now(timezone.utc).isoformat(),
    }
    _OUT_INFO.write_text(json.dumps(info, indent=2))
    log.info("      Info saved to %s", _OUT_INFO)

    log.info("")
    log.info("=" * 60)
    log.info("DONE. Commit these files to git:")
    log.info("  backend/training_data/training_data.npz")
    log.info("  backend/training_data/dataset_info.json")
    log.info("")
    log.info("build_model.py will auto-detect and use them on Render.")
    log.info("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare Kaggle URL dataset for training.")
    parser.add_argument("--input",  required=True, help="Path to malicious_phish.csv")
    parser.add_argument("--sample", type=int, default=None,
                        help="Max total rows to sample (stratified). Default: use all.")
    args = parser.parse_args()
    prepare(args.input, args.sample)
