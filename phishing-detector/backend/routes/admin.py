"""
routes/admin.py — Admin Panel API.

Every route except /login requires a valid Bearer token (utils.security.
require_admin). All inputs are sanitized before use; all DB access goes
through utils/db.py's parameterized queries.
"""

import csv
import io
import os
import time

from flask import Blueprint, request, jsonify, Response
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from utils.security import require_admin, rate_limit, sanitize_text, contains_attack_pattern
from utils import db
from ml import predict as predict_module
from ml.train_model import train

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml", "dataset")
MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5MB


# ============================================================
# Auth
# ============================================================

@admin_bp.post("/login")
@rate_limit(max_requests=5, window_seconds=60)
def login():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    body = request.get_json(silent=True) or {}
    username = sanitize_text(body.get("username", ""), max_len=80)
    password = body.get("password", "")

    if contains_attack_pattern(username) or contains_attack_pattern(password):
        db.log_event("warning", f"Blocked attack-pattern login attempt for '{username[:40]}'", ip)
        return jsonify({"error": "Invalid credentials."}), 400

    user = db.get_user_by_username(username)
    if not user or not check_password_hash(user["password_hash"], password):
        db.log_event("warning", f"Failed admin login for '{username[:40]}'", ip)
        return jsonify({"error": "Invalid username or password."}), 401

    from utils.security import issue_token
    token = issue_token(username)
    db.log_event("info", f"Admin '{username}' logged in", ip)
    return jsonify({"token": token, "username": username, "role": user["role"]})


# ============================================================
# Dashboard summary
# ============================================================

@admin_bp.get("/dashboard")
@require_admin
def dashboard():
    scans = db.list_scans(limit=100000)
    total = len(scans)
    by_verdict = {"safe": 0, "suspicious": 0, "phishing": 0}
    for s in scans:
        by_verdict[s["verdict"]] = by_verdict.get(s["verdict"], 0) + 1

    return jsonify({
        "totalScans": total,
        "byVerdict": by_verdict,
        "totalUsers": len(db.list_users()),
        "totalTrustedDomains": len(db.list_trusted_domains()),
        "modelLoaded": predict_module.is_ready(),
    })


# ============================================================
# Users
# ============================================================

@admin_bp.get("/users")
@require_admin
def get_users():
    return jsonify(db.list_users())


@admin_bp.post("/users")
@require_admin
def create_user():
    body = request.get_json(silent=True) or {}
    username = sanitize_text(body.get("username", ""), max_len=80)
    password = body.get("password", "")
    role = sanitize_text(body.get("role", "admin"), max_len=20) or "admin"

    if not username or len(password) < 8:
        return jsonify({"error": "Username is required and password must be at least 8 characters."}), 400
    if db.get_user_by_username(username):
        return jsonify({"error": "That username already exists."}), 409

    db.create_user(username, generate_password_hash(password), role)
    db.log_event("info", f"Admin user '{username}' created by '{request.admin_username}'")
    return jsonify({"message": "User created."}), 201


@admin_bp.delete("/users/<int:user_id>")
@require_admin
def remove_user(user_id):
    db.delete_user(user_id)
    db.log_event("info", f"User #{user_id} deleted by '{request.admin_username}'")
    return jsonify({"message": "User deleted."})


# ============================================================
# Scan history
# ============================================================

@admin_bp.get("/history")
@require_admin
def get_history():
    limit = min(int(request.args.get("limit", 200)), 2000)
    return jsonify(db.list_scans(limit=limit))


@admin_bp.delete("/history/<int:scan_id>")
@require_admin
def remove_scan(scan_id):
    db.delete_scan(scan_id)
    return jsonify({"message": "Record deleted."})


@admin_bp.delete("/history")
@require_admin
def clear_history():
    db.clear_scans()
    db.log_event("info", f"All scan history cleared by '{request.admin_username}'")
    return jsonify({"message": "Scan history cleared."})


# ============================================================
# Trusted domains
# ============================================================

@admin_bp.get("/trusted-domains")
@require_admin
def get_trusted_domains():
    return jsonify(db.list_trusted_domains())


@admin_bp.post("/trusted-domains")
@require_admin
def add_trusted_domain():
    body = request.get_json(silent=True) or {}
    brand = sanitize_text(body.get("brand", ""), max_len=80)
    domain = sanitize_text(body.get("domain", ""), max_len=200).lower()
    official_url = sanitize_text(body.get("officialUrl", ""), max_len=300)
    aliases = sanitize_text(body.get("aliases", ""), max_len=300)

    if not brand or not domain or not official_url:
        return jsonify({"error": "Brand, domain, and official URL are required."}), 400

    try:
        db.add_trusted_domain(brand, domain, official_url, aliases)
    except Exception:
        return jsonify({"error": "That domain is already in the registry."}), 409

    db.log_event("info", f"Trusted domain '{domain}' added by '{request.admin_username}'")
    return jsonify({"message": "Trusted domain added."}), 201


@admin_bp.delete("/trusted-domains/<int:domain_id>")
@require_admin
def remove_trusted_domain(domain_id):
    db.delete_trusted_domain(domain_id)
    return jsonify({"message": "Trusted domain removed."})


# ============================================================
# Dataset upload + retrain
# ============================================================

@admin_bp.post("/dataset/upload")
@require_admin
def upload_dataset():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    file = request.files["file"]
    if not file.filename.lower().endswith(".csv"):
        return jsonify({"error": "Only .csv files are accepted."}), 400

    raw = file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        return jsonify({"error": "File exceeds the 5MB limit."}), 400

    try:
        text = raw.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        fieldnames = {f.lower() for f in (reader.fieldnames or [])}
        if not {"url", "label"}.issubset(fieldnames):
            return jsonify({"error": "CSV must contain 'url' and 'label' columns."}), 400
        row_count = sum(1 for _ in reader)
    except Exception:
        return jsonify({"error": "Could not parse that file as CSV."}), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    safe_name = secure_filename(f"uploaded_{int(time.time())}.csv")
    dest = os.path.join(UPLOAD_DIR, safe_name)
    with open(dest, "w", encoding="utf-8") as f:
        f.write(text)

    db.log_event("info", f"Dataset '{safe_name}' ({row_count} rows) uploaded by '{request.admin_username}'")
    return jsonify({"message": "Dataset uploaded.", "filename": safe_name, "rows": row_count}), 201


@admin_bp.get("/dataset")
@require_admin
def list_datasets():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    files = sorted(
        [f for f in os.listdir(UPLOAD_DIR) if f.endswith(".csv")],
        key=lambda f: os.path.getmtime(os.path.join(UPLOAD_DIR, f)),
        reverse=True,
    )
    return jsonify(files)


@admin_bp.post("/retrain")
@require_admin
def retrain():
    """
    Explicit, admin-triggered retrain — this is the ONLY code path in the
    whole application that calls train_model.train(). It never runs on
    app startup or on a schedule.
    """
    body = request.get_json(silent=True) or {}
    dataset_file = body.get("dataset")  # filename from /dataset, or None = synthetic default
    csv_path = os.path.join(UPLOAD_DIR, secure_filename(dataset_file)) if dataset_file else None
    if csv_path and not os.path.exists(csv_path):
        return jsonify({"error": "That dataset file was not found."}), 404

    try:
        metadata = train(csv_path=csv_path)
        predict_module.reload_model()
    except Exception as e:
        db.log_event("error", f"Retrain failed: {e}", None)
        return jsonify({"error": f"Training failed: {e}"}), 500

    db.log_event("info", f"Model retrained by '{request.admin_username}' "
                          f"(accuracy {metadata['metrics']['accuracy']})")
    return jsonify({"message": "Model retrained and reloaded.", "metadata": metadata})


@admin_bp.get("/model-metadata")
@require_admin
def model_metadata():
    import json
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml", "model_metadata.json")
    if not os.path.exists(path):
        return jsonify({"error": "No metadata yet — train the model first."}), 404
    with open(path) as f:
        return jsonify(json.load(f))


# ============================================================
# Logs
# ============================================================

@admin_bp.get("/logs")
@require_admin
def get_logs():
    limit = min(int(request.args.get("limit", 300)), 2000)
    return jsonify(db.list_logs(limit=limit))


# ============================================================
# Reports
# ============================================================

@admin_bp.get("/reports/export")
@require_admin
def export_report():
    scans = db.list_scans(limit=100000)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "URL", "Verdict", "Threat Level", "Risk Score", "Confidence", "IP Address", "Scanned At"])
    for s in scans:
        writer.writerow([s["id"], s["url"], s["verdict"], s["threat_level"],
                          s["risk_score"], s["confidence_score"], s["ip_address"], s["created_at"]])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentrynet_report.csv"},
    )
