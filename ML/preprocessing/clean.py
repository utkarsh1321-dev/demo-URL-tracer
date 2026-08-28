"""
ML/preprocessing/clean.py
Data cleaning, deduplication, validation, and balancing pipeline.

Steps:
  1. Load raw urls.csv
  2. Remove duplicates (exact URL match)
  3. Validate URLs (length, parseable, non-empty)
  4. Class distribution report
  5. Optional class balancing (cap majority class)
  6. Train / Validation / Test split (70/15/15)
  7. Save splits to ML/data/processed/

Output:
  ML/data/processed/train.csv
  ML/data/processed/val.csv
  ML/data/processed/test.csv
  ML/data/processed/split_info.json
"""

import csv
import json
import random
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

# Paths
DATA_DIR      = Path(__file__).parent.parent / "data"
RAW_CSV       = DATA_DIR / "raw" / "urls.csv"
PROCESSED_DIR = DATA_DIR / "processed"

# Split ratios
TRAIN_RATIO = 0.70
VAL_RATIO   = 0.15
TEST_RATIO  = 0.15

# URL constraints
MIN_URL_LEN  = 5
MAX_URL_LEN  = 2048

# Class balancing: cap majority class at N× minority class size
BALANCE_RATIO = 3.0   # majority class capped at 3× smallest class size


def run(
    raw_csv: Path = RAW_CSV,
    out_dir: Path = PROCESSED_DIR,
    balance: bool = True,
    seed: int = 42,
    max_rows: int | None = None,
) -> dict:
    """
    Run the full cleaning pipeline.

    Returns dict with split sizes and class distribution.
    """
    print(f"\n[clean] Loading {raw_csv} …")
    rows = _load_csv(raw_csv)

    if max_rows:
        random.seed(seed)
        random.shuffle(rows)
        rows = rows[:max_rows]

    print(f"[clean] Loaded {len(rows):,} rows")

    # -- 1. Remove duplicates ------------------------------------------------
    rows = _deduplicate(rows)
    print(f"[clean] After dedup: {len(rows):,} rows")

    # -- 2. Validate --------------------------------------------------------─
    rows = _validate(rows)
    print(f"[clean] After validation: {len(rows):,} rows")

    # -- 3. Class distribution ------------------------------------------------
    dist = Counter(r["label"] for r in rows)
    print(f"[clean] Class distribution: {dict(dist)}")

    # -- 4. Balance ----------------------------------------------------------
    if balance and len(dist) > 1:
        rows = _balance(rows, dist, seed=seed)
        dist = Counter(r["label"] for r in rows)
        print(f"[clean] After balancing: {len(rows):,} rows -> {dict(dist)}")

    # -- 5. Split ------------------------------------------------------------─
    random.seed(seed)
    random.shuffle(rows)

    n      = len(rows)
    n_val  = int(n * VAL_RATIO)
    n_test = int(n * TEST_RATIO)
    n_train = n - n_val - n_test

    train = rows[:n_train]
    val   = rows[n_train:n_train + n_val]
    test  = rows[n_train + n_val:]

    print(f"[clean] Split - train: {len(train):,}  val: {len(val):,}  test: {len(test):,}")

    # -- 6. Save --------------------------------------------------------------
    out_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(train, out_dir / "train.csv")
    _write_csv(val,   out_dir / "val.csv")
    _write_csv(test,  out_dir / "test.csv")

    info = {
        "train_size": len(train),
        "val_size":   len(val),
        "test_size":  len(test),
        "total":      n,
        "class_distribution": dict(dist),
        "train_dist": dict(Counter(r["label"] for r in train)),
        "val_dist":   dict(Counter(r["label"] for r in val)),
        "test_dist":  dict(Counter(r["label"] for r in test)),
        "seed":       seed,
    }
    (out_dir / "split_info.json").write_text(json.dumps(info, indent=2))
    print(f"[clean] [ok] Splits saved to {out_dir}")
    return info


# --─ Helpers ----------------------------------------------------------------─

def _load_csv(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        return [{"url": r["url"], "label": r["label"]} for r in reader if r.get("url")]


def _deduplicate(rows: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for r in rows:
        key = r["url"].lower().strip()
        if key not in seen:
            seen.add(key)
            out.append(r)
    print(f"[clean] Removed {len(rows) - len(out):,} duplicate URLs")
    return out


def _validate(rows: list[dict]) -> list[dict]:
    valid = []
    invalid = 0
    for r in rows:
        url = r["url"].strip()
        # Length check
        if not (MIN_URL_LEN <= len(url) <= MAX_URL_LEN):
            invalid += 1
            continue
        # Must parse to have a netloc
        try:
            p = urlparse(url if "://" in url else "http://" + url)
            if not p.netloc:
                invalid += 1
                continue
        except Exception:
            invalid += 1
            continue
        # Label must be known
        if r["label"] not in {"BENIGN", "PHISHING", "MALWARE", "SUSPICIOUS"}:
            invalid += 1
            continue
        valid.append({"url": url, "label": r["label"]})
    print(f"[clean] Removed {invalid:,} invalid rows")
    return valid


def _balance(rows: list[dict], dist: Counter, seed: int) -> list[dict]:
    """Cap majority classes so no class is more than BALANCE_RATIO × smallest."""
    min_count = min(dist.values())
    cap = int(min_count * BALANCE_RATIO)

    by_label: dict[str, list] = {}
    for r in rows:
        by_label.setdefault(r["label"], []).append(r)

    rng = random.Random(seed)
    balanced = []
    for label, items in by_label.items():
        if len(items) > cap:
            items = rng.sample(items, cap)
        balanced.extend(items)
    return balanced


def _write_csv(rows: list[dict], path: Path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    run()
