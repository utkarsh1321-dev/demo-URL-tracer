"""
ML/training/train.py
Multi-model training pipeline for URL phishing classification.

Pipeline:
  1. Download dataset (if not already downloaded)
  2. Preprocess + clean + split
  3. Extract features (shared with Phase 3 inference)
  4. Train: Logistic Regression, Random Forest, Gradient Boosting
  5. Evaluate each on validation set
  6. Select best model by macro F1
  7. Re-evaluate selected model on held-out test set
  8. Serialize model + metadata to ML/models/

Usage:
    cd c:\\Users\\user\\OneDrive\\Desktop\\sih
    python ML/training/train.py

    # Skip download if data already exists:
    python ML/training/train.py --no-download

    # Limit rows for a quick test run:
    python ML/training/train.py --max-rows 20000 --no-download
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np

# -- Path setup - must happen before any local imports ------------------------
_ROOT    = Path(__file__).parent.parent.parent          # project root
_ML_ROOT = Path(__file__).parent.parent                  # ML/
_BACKEND = _ROOT / "backend"

for p in [str(_ROOT), str(_ML_ROOT), str(_BACKEND)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# -- ML imports ----------------------------------------------------------------
from sklearn.linear_model    import LogisticRegression
from sklearn.ensemble        import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing   import StandardScaler
from sklearn.pipeline        import Pipeline

from ML.preprocessing.clean   import run as clean_data
from ML.features.extract       import build_feature_matrix, get_feature_names, LABEL_NAMES
from ML.evaluation.evaluate    import evaluate

# -- Paths --------------------------------------------------------------------
DATA_DIR      = _ML_ROOT / "data"
RAW_CSV       = DATA_DIR / "raw" / "urls.csv"
PROCESSED_DIR = DATA_DIR / "processed"
MODELS_DIR    = _ML_ROOT / "models"
MODEL_PKL     = MODELS_DIR / "url_phishing_model.pkl"
MODEL_INFO    = MODELS_DIR / "model_info.json"

MODELS_DIR.mkdir(parents=True, exist_ok=True)


# -- Model definitions --------------------------------------------------------─

def get_models() -> dict[str, object]:
    return {
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                C=1.0, max_iter=1000, solver="lbfgs",
                random_state=42, n_jobs=-1,
            )),
        ]),
        "RandomForest": RandomForestClassifier(
            n_estimators=200, max_depth=20, min_samples_leaf=5,
            class_weight="balanced", random_state=42, n_jobs=-1,
        ),
        "GradientBoosting": GradientBoostingClassifier(
            n_estimators=150, max_depth=5, learning_rate=0.1,
            subsample=0.8, random_state=42,
        ),
    }


# -- Data loading --------------------------------------------------------------

def load_split(path: Path) -> list[dict]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append({"url": row["url"], "label": row["label"]})
    return rows


# -- Main pipeline ------------------------------------------------------------─

def run(
    skip_download: bool = False,
    max_rows: int | None = None,
    seed: int = 42,
):
    print("\n" + "=" * 60)
    print("  URL Tracer -- Phase 4 ML Training Pipeline")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 60)

    # -- Step 1: Download --------------------------------------------------
    if not skip_download:
        if RAW_CSV.exists():
            print(f"\n[train] Raw data already exists ({RAW_CSV}). Skipping download.")
            print("[train] Run with --force-download to re-download.")
        else:
            print("\n[train] Step 1/6: Downloading dataset …")
            from ML.data.download import download_github, download_kaggle
            ok = download_kaggle() or download_github()
            if not ok:
                print("[train] [FAIL] Could not download dataset. Aborting.")
                sys.exit(1)
    else:
        if not RAW_CSV.exists():
            print(f"[train] [FAIL] {RAW_CSV} not found. Run download.py first.")
            sys.exit(1)
        print(f"\n[train] Using existing data at {RAW_CSV}")

    # Dataset info
    info_file = DATA_DIR / "raw" / "dataset_info.json"
    dataset_info = json.loads(info_file.read_text()) if info_file.exists() else {}

    # -- Step 2: Preprocess ------------------------------------------------
    print("\n[train] Step 2/6: Preprocessing …")
    split_info = clean_data(
        raw_csv=RAW_CSV,
        out_dir=PROCESSED_DIR,
        balance=True,
        seed=seed,
        max_rows=max_rows,
    )

    # -- Step 3: Feature extraction ----------------------------------------
    print("\n[train] Step 3/6: Extracting features …")
    feature_names = get_feature_names()
    print(f"  Features: {len(feature_names)} -> {feature_names[:5]} …")

    print("  [train] -> train split")
    X_train, y_train, _ = build_feature_matrix(load_split(PROCESSED_DIR / "train.csv"))
    print("  [train] -> val split")
    X_val,   y_val,   _ = build_feature_matrix(load_split(PROCESSED_DIR / "val.csv"))
    print("  [train] -> test split")
    X_test,  y_test,  _ = build_feature_matrix(load_split(PROCESSED_DIR / "test.csv"))

    # -- Step 4: Train all models ------------------------------------------
    print("\n[train] Step 4/6: Training models …")
    models = get_models()
    val_results: dict[str, dict] = {}

    for name, model in models.items():
        print(f"\n  -- Training {name} …")
        t0 = time.perf_counter()
        model.fit(X_train, y_train)
        elapsed = time.perf_counter() - t0
        print(f"  Training time: {elapsed:.1f}s")

        # Validation evaluation
        y_pred = model.predict(X_val)
        from sklearn.metrics import f1_score, accuracy_score
        acc  = accuracy_score(y_val, y_pred)
        f1   = f1_score(y_val, y_pred, average="macro", zero_division=0)
        print(f"  Val Accuracy: {acc:.4f}   Val Macro F1: {f1:.4f}")
        val_results[name] = {
            "model":       model,
            "val_acc":     acc,
            "val_f1":      f1,
            "train_time":  elapsed,
        }

    # -- Step 5: Select best model ----------------------------------------─
    print("\n[train] Step 5/6: Model selection …")
    print("\n  Validation summary:")
    for name, res in val_results.items():
        marker = ""
        print(f"    {name:<25} Acc={res['val_acc']:.4f}  F1={res['val_f1']:.4f}  "
              f"Train={res['train_time']:.1f}s {marker}")

    best_name = max(val_results, key=lambda k: val_results[k]["val_f1"])
    best_model = val_results[best_name]["model"]
    print(f"\n  [ok] Selected: {best_name} (Val F1={val_results[best_name]['val_f1']:.4f})")

    # -- Step 6: Test evaluation ------------------------------------------─
    print("\n[train] Step 6/6: Evaluating on held-out test set …")
    test_metrics = evaluate(best_model, X_test, y_test, model_name=best_name)

    # -- Inference time benchmark ------------------------------------------
    sample = X_test[:100]
    t0 = time.perf_counter()
    for _ in range(100):
        best_model.predict(sample)
    infer_ms = (time.perf_counter() - t0) / 100 * 1000 / 100  # ms per URL
    print(f"\n  Inference time: {infer_ms:.3f} ms/URL (avg over 10,000 predictions)")

    # -- Serialize --------------------------------------------------------─
    joblib.dump(best_model, MODEL_PKL)
    print(f"\n  [ok] Model saved to {MODEL_PKL}")

    # -- Save metadata ----------------------------------------------------─
    model_info = {
        "model_version":          "urltracer-v1.0.0",
        "feature_version":        "urltracer-v1",
        "algorithm":              best_name,
        "num_features":           len(feature_names),
        "feature_names":          feature_names,
        "label_names":            LABEL_NAMES,
        "training_date":          datetime.now(timezone.utc).isoformat(),
        "seed":                   seed,
        "dataset":                {
            "name":     dataset_info.get("name",    "Malicious URL Dataset"),
            "source":   dataset_info.get("source",  "public"),
            "license":  dataset_info.get("license", "see ML/README.md"),
            "version":  dataset_info.get("version", "1"),
            "rows_downloaded": dataset_info.get("rows_downloaded", 0),
        },
        "data_split": split_info,
        "validation_results": {
            name: {
                "val_acc": res["val_acc"],
                "val_f1":  res["val_f1"],
                "train_time_s": res["train_time"],
            }
            for name, res in val_results.items()
        },
        "test_evaluation":        test_metrics,
        "inference_time_ms_per_url": round(infer_ms, 4),
    }

    MODEL_INFO.write_text(json.dumps(model_info, indent=2))
    print(f"  [ok] Metadata saved to {MODEL_INFO}")

    # -- Summary ----------------------------------------------------------─
    print("\n" + "=" * 60)
    print("  Training Complete")
    print(f"  Model     : {best_name}")
    print(f"  Test Acc  : {test_metrics['accuracy']:.4f}")
    print(f"  Test F1   : {test_metrics['f1_macro']:.4f}")
    if test_metrics.get("roc_auc"):
        print(f"  ROC-AUC   : {test_metrics['roc_auc']:.4f}")
    print(f"  Infer     : {infer_ms:.3f} ms/URL")
    print(f"  Artifact  : {MODEL_PKL}")
    print("=" * 60)


# --─ Entry point ------------------------------------------------------------─

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train URL phishing classifier")
    parser.add_argument("--no-download",    action="store_true", help="Skip download step")
    parser.add_argument("--force-download", action="store_true", help="Force re-download")
    parser.add_argument("--max-rows",  type=int, default=None,
                        help="Limit total rows (for quick testing)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    skip_dl = args.no_download and not args.force_download

    run(
        skip_download=skip_dl,
        max_rows=args.max_rows,
        seed=args.seed,
    )
