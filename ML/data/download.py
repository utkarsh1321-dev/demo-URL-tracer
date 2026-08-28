"""
ML/data/download.py
Download raw phishing URL dataset for Phase 4 training.

Two sources supported:
  --source kaggle   (default): Malicious URLs Dataset — CC0 Public Domain
  --source github             : MIT-licensed fallback dataset

Usage:
    python ML/data/download.py                   # Kaggle (requires ~/.kaggle/kaggle.json)
    python ML/data/download.py --source github   # GitHub (no auth required)

Output:
    ML/data/raw/urls.csv  (columns: url, label)
    ML/data/raw/dataset_info.json
"""

import argparse
import csv
import gzip
import io
import json
import os
import sys
import urllib.request
from pathlib import Path

RAW_DIR = Path(__file__).parent / "raw"
OUTPUT_CSV  = RAW_DIR / "urls.csv"
INFO_FILE   = RAW_DIR / "dataset_info.json"


# ─── Kaggle download ─────────────────────────────────────────────────────────

KAGGLE_DATASET = "sid321axn/malicious-urls-dataset"
KAGGLE_FILE    = "malicious_phish.csv"

DATASET_INFO_KAGGLE = {
    "name":      "Malicious URLs Dataset",
    "source":    f"https://www.kaggle.com/datasets/{KAGGLE_DATASET}",
    "license":   "CC0 1.0 Universal (Public Domain Dedication)",
    "version":   "1",
    "labels":    {"benign": "BENIGN", "phishing": "PHISHING",
                  "defacement": "MALWARE", "malware": "MALWARE"},
    "url_column":   "url",
    "label_column": "type",
}

def download_kaggle():
    """Download using kaggle Python API or CLI."""
    print("[download] Attempting Kaggle download...")
    print(f"[download] Dataset: {KAGGLE_DATASET}")
    print(f"[download] License: {DATASET_INFO_KAGGLE['license']}")

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    # Try kaggle Python package first
    try:
        import kaggle  # noqa: F401
    except ImportError:
        print("[download] 'kaggle' package not installed. Run: pip install kaggle")
        return False

    try:
        import kaggle
        kaggle.api.authenticate()
        kaggle.api.dataset_download_file(
            KAGGLE_DATASET,
            KAGGLE_FILE,
            path=str(RAW_DIR),
            force=True,
        )
    except Exception as e:
        print(f"[download] Kaggle download failed: {e}")
        print("[download] Make sure ~/.kaggle/kaggle.json exists with valid credentials.")
        print("[download] Alternative: run with --source github")
        return False

    # Unzip if needed
    gz = RAW_DIR / f"{KAGGLE_FILE}.zip"
    src = RAW_DIR / KAGGLE_FILE

    if not src.exists():
        import zipfile
        zfiles = list(RAW_DIR.glob("*.zip"))
        if zfiles:
            with zipfile.ZipFile(zfiles[0]) as zf:
                zf.extractall(RAW_DIR)
            zfiles[0].unlink()

    # Normalize to standard CSV
    _normalize_csv(
        src=src,
        url_col=DATASET_INFO_KAGGLE["url_column"],
        label_col=DATASET_INFO_KAGGLE["label_column"],
        label_map=DATASET_INFO_KAGGLE["labels"],
        info=DATASET_INFO_KAGGLE,
    )
    return True


# ─── GitHub MIT-licensed fallback ────────────────────────────────────────────

GITHUB_URL = (
    "https://raw.githubusercontent.com/"
    "faizann24/Using-Machine-Learning-To-Detect-Malicious-URLs/"
    "master/data/data.csv"
)

DATASET_INFO_GITHUB = {
    "name":      "Malicious URL Detection Dataset",
    "source":    "https://github.com/faizann24/Using-Machine-Learning-To-Detect-Malicious-URLs",
    "license":   "MIT License",
    "version":   "1",
    "labels":    {"bad": "PHISHING", "good": "BENIGN"},
    "url_column":   "url",
    "label_column": "label",
}

def download_github():
    """Download MIT-licensed dataset directly from GitHub (no auth needed)."""
    print("[download] Downloading from GitHub (MIT license, no auth required)...")
    print(f"[download] Source: {GITHUB_URL}")

    RAW_DIR.mkdir(parents=True, exist_ok=True)

    try:
        req = urllib.request.Request(GITHUB_URL, headers={"User-Agent": "urltracer/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            content = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[download] GitHub download failed: {e}")
        return False

    raw_csv = RAW_DIR / "raw_github.csv"
    raw_csv.write_text(content, encoding="utf-8")

    _normalize_csv(
        src=raw_csv,
        url_col=DATASET_INFO_GITHUB["url_column"],
        label_col=DATASET_INFO_GITHUB["label_column"],
        label_map=DATASET_INFO_GITHUB["labels"],
        info=DATASET_INFO_GITHUB,
    )
    raw_csv.unlink()
    return True


# ─── Normalization ────────────────────────────────────────────────────────────

def _normalize_csv(src: Path, url_col: str, label_col: str,
                   label_map: dict, info: dict):
    """Read raw CSV, map labels, write normalized urls.csv."""
    import csv as _csv

    rows_written = 0
    rows_skipped = 0

    with open(src, "r", encoding="utf-8", errors="replace") as fin, \
         open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as fout:

        reader = _csv.DictReader(fin)
        writer = _csv.DictWriter(fout, fieldnames=["url", "label"])
        writer.writeheader()

        for row in reader:
            url   = (row.get(url_col) or "").strip()
            raw_label = (row.get(label_col) or "").strip().lower()
            label = label_map.get(raw_label)

            if not url or not label:
                rows_skipped += 1
                continue

            writer.writerow({"url": url, "label": label})
            rows_written += 1

    # Save dataset metadata
    info_out = dict(info)
    info_out["rows_downloaded"] = rows_written
    info_out["rows_skipped"] = rows_skipped
    INFO_FILE.write_text(json.dumps(info_out, indent=2), encoding="utf-8")

    print(f"[download] Saved {rows_written:,} rows to {OUTPUT_CSV}")
    print(f"[download] Metadata saved to {INFO_FILE}")
    print(f"[download] Skipped {rows_skipped:,} rows (missing url or label)")


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download phishing URL dataset")
    parser.add_argument(
        "--source", choices=["kaggle", "github"], default="kaggle",
        help="Dataset source (default: kaggle)"
    )
    args = parser.parse_args()

    if args.source == "kaggle":
        ok = download_kaggle()
        if not ok:
            print("[download] Trying GitHub fallback...")
            ok = download_github()
    else:
        ok = download_github()

    sys.exit(0 if ok else 1)
