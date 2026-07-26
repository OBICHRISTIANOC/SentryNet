"""
predict.py — loads the persisted model.pkl exactly once, at import time,
and exposes predict(url) for the rest of the app.

This is the enforcement point for "do NOT retrain the model every time
the application starts": nothing in this module calls train_model.py.
If model.pkl is missing, predict() raises a clear error telling the
operator to run the training script — it does not silently retrain.

The Admin Panel's "Retrain model" action (routes/admin.py) calls
`reload_model()` after training finishes, which re-reads model.pkl from
disk into this module's cached `_model` — so a retrain takes effect
without restarting the Flask process, but still never happens implicitly.
"""

import os
import pickle
import threading

from ml.feature_extraction import extract_features, to_vector, FEATURE_ORDER, FEATURE_LABELS

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")

_model = None
_lock = threading.Lock()


class ModelNotTrainedError(RuntimeError):
    pass


def _load():
    global _model
    if not os.path.exists(MODEL_PATH):
        raise ModelNotTrainedError(
            f"No trained model found at {MODEL_PATH}. Run `python ml/train_model.py` first."
        )
    with open(MODEL_PATH, "rb") as f:
        _model = pickle.load(f)


def reload_model():
    """Re-reads model.pkl from disk. Called after an Admin Panel retrain."""
    with _lock:
        _load()


# Load once at import time — this is what keeps startup instant even as
# the training set grows, per the "don't retrain on startup" requirement.
try:
    _load()
except ModelNotTrainedError:
    _model = None  # routes/scan.py checks for this and returns a clear 503


def is_ready() -> bool:
    return _model is not None


def _feature_status_and_weight(name: str, value, importance: float):
    """
    Turns a raw feature value into a UI-friendly (status, weight) pair —
    'weight' here is a 0-100 display scale derived from the trained
    model's feature_importances_, scaled by how far this particular
    value sits from what a legitimate URL usually looks like.
    """
    risky_map = {
        "has_https": value == 0,
        "has_ip": value == 1,
        "has_at_symbol": value == 1,
        "has_double_slash_redirect": value == 1,
        "is_suspicious_tld": value == 1,
        "has_ssl": value == 0,
        "whois_available": value == 0,
        "dns_resolves": value == 0,
    }
    if name in risky_map:
        is_risky = risky_map[name]
    elif name == "entropy":
        is_risky = value > 3.6
    elif name == "redirect_count":
        is_risky = value >= 2
    elif name == "suspicious_word_count":
        is_risky = value >= 1
    elif name == "hyphen_count":
        is_risky = value >= 2
    elif name == "dot_count" or name == "subdomain_count":
        is_risky = value > 3
    elif name == "url_length":
        is_risky = value > 75
    elif name == "domain_age_days":
        is_risky = value < 60
    elif name == "special_char_count":
        is_risky = value > 2
    elif name == "digit_count":
        is_risky = value > 4
    else:
        is_risky = False

    weight = round(min(max(importance * 400, 5), 95)) if is_risky else round(min(importance * 100, 15))
    status = "danger" if (is_risky and weight >= 55) else ("warn" if is_risky else "safe")
    return status, weight


def predict(raw_url: str) -> dict:
    """
    Runs the full pipeline for one URL: feature extraction -> model
    inference -> UI-shaped result. Raises ModelNotTrainedError if
    model.pkl hasn't been produced yet.
    """
    if _model is None:
        raise ModelNotTrainedError("Model is not loaded — train it first via ml/train_model.py.")

    extraction = extract_features(raw_url, live_lookups=True)
    features = extraction["features"]
    meta = extraction["meta"]
    vector = [to_vector(features)]

    proba = _model.predict_proba(vector)[0]
    # Class 1 = phishing (see generate_dataset.py / train_model.py labelling).
    classes = list(_model.classes_)
    phishing_idx = classes.index(1) if 1 in classes else 1
    risk_score = round(proba[phishing_idx] * 100)
    confidence_score = round(max(proba) * 100)

    importances = getattr(_model, "feature_importances_", [1 / len(FEATURE_ORDER)] * len(FEATURE_ORDER))
    importance_map = dict(zip(FEATURE_ORDER, importances))

    feature_report = []
    for name in FEATURE_ORDER:
        status, weight = _feature_status_and_weight(name, features[name], importance_map[name])
        feature_report.append({
            "key": name,
            "name": FEATURE_LABELS[name],
            "value": features[name],
            "status": status,
            "weight": weight,
            "modelImportance": round(importance_map[name] * 100, 2),
        })

    top_features = sorted(feature_report, key=lambda f: f["modelImportance"], reverse=True)[:5]

    return {
        "riskScore": risk_score,
        "confidenceScore": confidence_score,
        "securityScore": 100 - risk_score,
        "features": feature_report,
        "topFeatures": [f["name"] for f in top_features],
        "meta": meta,
        "modelClasses": classes,
    }
