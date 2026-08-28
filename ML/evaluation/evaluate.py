"""
ML/evaluation/evaluate.py
Detailed model evaluation on held-out test data.

Generates:
  - Per-class precision, recall, F1
  - Macro / weighted averages
  - ROC-AUC (one-vs-rest)
  - False Positive Rate and False Negative Rate per class
  - Confusion matrix

Called automatically by train.py after model selection.
"""

import json
import numpy as np
from pathlib import Path
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    accuracy_score,
)

from ML.features.extract import LABEL_NAMES, decode_label


def evaluate(
    model,
    X_test: np.ndarray,
    y_test: np.ndarray,
    model_name: str,
    label_names: list[str] = LABEL_NAMES,
) -> dict:
    """
    Evaluate a trained classifier on test data.

    Returns
    -------
    dict with all metrics (suitable for storing in model_info.json)
    """
    y_pred = model.predict(X_test)

    # -- Basic metrics --------------------------------------------------------─
    acc = accuracy_score(y_test, y_pred)

    report = classification_report(
        y_test, y_pred,
        target_names=label_names[:len(np.unique(y_test))],
        output_dict=True,
        zero_division=0,
    )

    # -- ROC-AUC (one-vs-rest, requires probability estimates) ----------------─
    roc_auc = None
    try:
        y_proba = model.predict_proba(X_test)
        n_classes = y_proba.shape[1]
        if n_classes == 2:
            roc_auc = round(roc_auc_score(y_test, y_proba[:, 1]), 4)
        else:
            roc_auc = round(roc_auc_score(
                y_test, y_proba,
                multi_class="ovr", average="macro",
                labels=list(range(n_classes)),
            ), 4)
    except Exception as e:
        print(f"  [evaluate] ROC-AUC could not be computed: {e}")

    # -- Confusion matrix & FPR/FNR per class ----------------------------------
    cm = confusion_matrix(y_test, y_pred)
    classes = sorted(np.unique(np.concatenate([y_test, y_pred])))
    fpr_fnr = {}
    for i, cls in enumerate(classes):
        tp = cm[i, i]
        fn = cm[i, :].sum() - tp
        fp = cm[:, i].sum() - tp
        tn = cm.sum() - tp - fn - fp
        fpr_fnr[decode_label(cls)] = {
            "FPR": round(fp / (fp + tn + 1e-9), 4),
            "FNR": round(fn / (fn + tp + 1e-9), 4),
        }

    # -- Print report --------------------------------------------------------─
    print(f"\n  -- {model_name} - Test Evaluation --")
    print(f"  Accuracy   : {acc:.4f}")
    print(f"  Macro F1   : {report.get('macro avg', {}).get('f1-score', 0):.4f}")
    if roc_auc:
        print(f"  ROC-AUC    : {roc_auc:.4f}")
    print(f"\n  Per-class metrics:")
    for cls_name in label_names[:len(classes)]:
        r = report.get(cls_name, {})
        fpfn = fpr_fnr.get(cls_name, {})
        print(
            f"    {cls_name:<12} "
            f"P={r.get('precision', 0):.3f}  "
            f"R={r.get('recall', 0):.3f}  "
            f"F1={r.get('f1-score', 0):.3f}  "
            f"FPR={fpfn.get('FPR', 0):.3f}  "
            f"FNR={fpfn.get('FNR', 0):.3f}"
        )

    return {
        "accuracy":  round(acc, 4),
        "f1_macro":  round(report.get("macro avg", {}).get("f1-score", 0), 4),
        "f1_weighted": round(report.get("weighted avg", {}).get("f1-score", 0), 4),
        "precision_macro": round(report.get("macro avg", {}).get("precision", 0), 4),
        "recall_macro":    round(report.get("macro avg", {}).get("recall", 0), 4),
        "roc_auc":   roc_auc,
        "per_class": {
            cls: {
                "precision": round(report.get(cls, {}).get("precision", 0), 4),
                "recall":    round(report.get(cls, {}).get("recall", 0), 4),
                "f1":        round(report.get(cls, {}).get("f1-score", 0), 4),
                "support":   int(report.get(cls, {}).get("support", 0)),
                "FPR":       fpr_fnr.get(cls, {}).get("FPR", 0),
                "FNR":       fpr_fnr.get(cls, {}).get("FNR", 0),
            }
            for cls in label_names[:len(classes)]
        },
        "confusion_matrix": cm.tolist(),
    }
