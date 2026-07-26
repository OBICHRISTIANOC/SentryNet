"""
train_model.py — trains the Random Forest phishing classifier and
persists it to disk as model.pkl.

Usage
-----
    python ml/train_model.py                  # train on the bundled synthetic dataset
    python ml/train_model.py --csv path.csv    # train on a real labelled CSV (columns: url,label)

This script is run manually (or triggered from the Admin Panel's
"Retrain model" action) — it is NEVER invoked automatically when the
Flask app starts. app.py and routes/scan.py only ever *load* the
already-trained model.pkl from disk; startup latency stays flat no
matter how large the training set grows. See predict.py for the
load-once-at-import pattern that enforces this.
"""

import argparse
import csv
import json
import os
import pickle
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from ml.feature_extraction import extract_features, to_vector, FEATURE_ORDER
from ml.generate_dataset import build_dataset

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")


def load_csv_dataset(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append((row["url"], int(row["label"])))
    return rows


def vectorize(rows):
    X, y, skipped = [], [], 0
    for url, label in rows:
        try:
            result = extract_features(url, live_lookups=False)
            X.append(to_vector(result["features"]))
            y.append(label)
        except Exception:
            skipped += 1
    return X, y, skipped


def train(csv_path=None, n_estimators=200, max_depth=12, test_size=0.2, random_state=42):
    print("=" * 60)
    print("SentryNet — Random Forest training pipeline")
    print("=" * 60)

    if csv_path:
        print(f"Loading dataset from {csv_path} ...")
        rows = load_csv_dataset(csv_path)
    else:
        print("No --csv given — generating the bundled synthetic dataset ...")
        rows = build_dataset()
    print(f"Loaded {len(rows)} labelled URLs "
          f"({sum(1 for _, l in rows if l == 1)} phishing / {sum(1 for _, l in rows if l == 0)} legitimate)")

    print("Extracting features (network lookups disabled during training) ...")
    t0 = time.time()
    X, y, skipped = vectorize(rows)
    print(f"Extracted {len(X)} feature vectors in {time.time() - t0:.1f}s ({skipped} rows skipped on error)")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    print(f"Train/test split: {len(X_train)} train / {len(X_test)} test ({int(test_size * 100)}% held out)")

    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_leaf=2,
        random_state=random_state,
        n_jobs=-1,
    )
    print(f"Training RandomForestClassifier(n_estimators={n_estimators}, max_depth={max_depth}) ...")
    t0 = time.time()
    clf.fit(X_train, y_train)
    train_time = time.time() - t0
    print(f"Training complete in {train_time:.2f}s")

    y_pred = clf.predict(X_test)
    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred), 4),
        "recall": round(recall_score(y_test, y_pred), 4),
        "f1_score": round(f1_score(y_test, y_pred), 4),
    }
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("-" * 60)
    print("Evaluation on held-out test set:")
    for k, v in metrics.items():
        print(f"  {k:10s}: {v}")
    print(f"  confusion matrix [[TN, FP], [FN, TP]]: {cm}")
    print("-" * 60)

    importances = dict(zip(FEATURE_ORDER, [round(v, 4) for v in clf.feature_importances_]))
    ranked_importances = dict(sorted(importances.items(), key=lambda kv: kv[1], reverse=True))

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"Saved trained model to {MODEL_PATH}")

    metadata = {
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_samples": len(X),
        "n_train": len(X_train),
        "n_test": len(X_test),
        "n_estimators": n_estimators,
        "max_depth": max_depth,
        "train_time_seconds": round(train_time, 2),
        "metrics": metrics,
        "confusion_matrix": cm,
        "feature_order": FEATURE_ORDER,
        "feature_importances": ranked_importances,
        "source": os.path.basename(csv_path) if csv_path else "synthetic_generator",
    }
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Saved training metadata to {METADATA_PATH}")
    print("=" * 60)

    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the SentryNet Random Forest phishing classifier.")
    parser.add_argument("--csv", help="Path to a labelled CSV with 'url' and 'label' columns", default=None)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--max-depth", type=int, default=12)
    args = parser.parse_args()

    train(csv_path=args.csv, n_estimators=args.n_estimators, max_depth=args.max_depth)
