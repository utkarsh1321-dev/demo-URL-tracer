# URL Phishing ML Pipeline — Phase 4

## Overview

Reproducible offline training pipeline for the URL phishing classifier.

The model is trained on public phishing URL datasets, evaluated on a held-out test set,
and serialized to `ML/models/url_phishing_model.pkl` for backend inference.

**Feature schema is shared exactly with Phase 3 inference** — no train/serve skew.

---

## Dataset

### Primary: Malicious URLs Dataset (Kaggle)
- **Source**: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
- **License**: CC0 1.0 Universal (Public Domain Dedication)
- **Size**: ~651,000 URLs
- **Labels**: `benign`, `defacement`, `phishing`, `malware`
- **Columns**: `url`, `type`

### Fallback: MIT-Licensed GitHub Dataset
- **Source**: https://github.com/faizann24/Using-Machine-Learning-To-Detect-Malicious-URLs
- **License**: MIT
- **Size**: ~420,000 URLs
- **Labels**: `bad` (→ PHISHING), `good` (→ BENIGN)

---

## Directory Structure

```
ML/
├── data/
│   ├── download.py           ← Dataset download (Kaggle API or GitHub fallback)
│   └── raw/                  ← Raw CSVs (gitignored)
├── preprocessing/
│   └── clean.py              ← Dedup, validate, balance, split
├── features/
│   └── extract.py            ← Wraps backend/analysis/features.py (shared schema)
├── training/
│   └── train.py              ← Multi-model training + selection
├── evaluation/
│   └── evaluate.py           ← Classification report + ROC-AUC
├── models/
│   ├── url_phishing_model.pkl   ← Trained model (gitignored)
│   └── model_info.json          ← Metadata (tracked)
└── README.md
```

---

## Quickstart

### Option A — Kaggle Dataset (recommended, larger)

```bash
# 1. Set up Kaggle credentials
# Create ~/.kaggle/kaggle.json with {"username":"...","key":"..."}
# OR set env vars: KAGGLE_USERNAME, KAGGLE_KEY

# 2. Download dataset
python ML/data/download.py

# 3. Run full pipeline
python ML/training/train.py
```

### Option B — GitHub Fallback (no auth, smaller)

```bash
python ML/data/download.py --source github
python ML/training/train.py
```

---

## Pipeline Steps

| Step | Script | Description |
|---|---|---|
| 1 | `data/download.py` | Download raw CSV from Kaggle or GitHub |
| 2 | `training/train.py` | Preprocess → extract features → train → evaluate → save |

`train.py` calls `preprocessing/clean.py`, `features/extract.py`, and `evaluation/evaluate.py` internally.

---

## Feature Schema

**28 features** extracted by `backend/analysis/features.py` (Phase 3).

The same function `extract_features(url) → URLFeatures` is used at:
- **Training time**: `ML/features/extract.py` wraps it for batch processing
- **Inference time**: `backend/analysis/engine.py` calls it per request

This guarantees zero train/serve skew.

Feature vector order is defined by `ML_FEATURE_NAMES` in `features.py`.

---

## Models Evaluated

| Model | Notes |
|---|---|
| Logistic Regression | Fast baseline; interpretable coefficients |
| Random Forest | Strong default; handles non-linearity |
| Gradient Boosting | Usually best F1; slower to train |

Best model by F1-macro on validation set is selected and serialized.

---

## Evaluation Metrics

Per-class: Precision, Recall, F1-Score, Support
Overall: Accuracy, Macro F1, ROC-AUC (one-vs-rest)
Per-class False Positive Rate and False Negative Rate

All metrics stored in `models/model_info.json`.

---

## Model Versioning

```json
{
  "model_version": "urltracer-v1.0.0",
  "feature_version": "urltracer-v1",
  "algorithm": "...",
  "num_features": 28,
  "training_date": "...",
  "dataset": { "name": "...", "source": "...", "license": "..." },
  "evaluation": { "accuracy": ..., "f1_macro": ..., "roc_auc": ... }
}
```

---

## Data Gitignore

`ML/data/raw/` and `ML/models/*.pkl` are gitignored.
`ML/models/model_info.json` (metadata) is tracked.
