"""
routes/scan.py — the core public API: POST /api/scan.

Every request is validated and sanitized (utils/security.sanitize_url)
before it ever reaches feature extraction, rate limited per-IP, and
logged to scan_history for the Admin Panel / Dashboard to read back.
"""

import time

from flask import Blueprint, request, jsonify

from ml import predict as predict_module
from ml.report import build_report
from utils.security import sanitize_url, InvalidUrlError, contains_attack_pattern, rate_limit
from utils.db import insert_scan, log_event

scan_bp = Blueprint("scan", __name__, url_prefix="/api")


@scan_bp.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "modelLoaded": predict_module.is_ready(),
    })


@scan_bp.post("/scan")
@rate_limit(max_requests=30, window_seconds=60)
def scan():
    t0 = time.time()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    body = request.get_json(silent=True) or {}
    raw_url = body.get("url", "")

    attack = contains_attack_pattern(raw_url)
    if attack:
        log_event("warning", f"Blocked {attack.upper()}-like payload in /api/scan: {raw_url[:200]}", ip)
        return jsonify({"error": "Request rejected — invalid characters detected."}), 400

    try:
        clean_url = sanitize_url(raw_url)
    except InvalidUrlError as e:
        log_event("info", f"Rejected invalid URL from {ip}: {e}", ip)
        return jsonify({"error": str(e)}), 400

    if not predict_module.is_ready():
        return jsonify({
            "error": "The model hasn't been trained yet. Run `python ml/train_model.py`, "
                     "or ask an administrator to trigger a retrain from the Admin Panel."
        }), 503

    try:
        prediction = predict_module.predict(clean_url)
        report = build_report(clean_url, prediction)
    except Exception as e:
        log_event("error", f"Scan failed for {clean_url}: {e}", ip)
        return jsonify({"error": "Something went wrong analysing that URL. Please try again."}), 500

    response_time_ms = round((time.time() - t0) * 1000)
    report["responseTimeMs"] = response_time_ms

    insert_scan(
        url=clean_url,
        verdict=report["verdict"],
        threat_level=report["threatLevel"],
        risk_score=report["riskScore"],
        confidence_score=report["confidenceScore"],
        ip_address=ip,
    )
    if report["verdict"] == "phishing":
        log_event("warning", f"Phishing verdict for {clean_url} (risk {report['riskScore']}%)", ip)

    return jsonify(report)
