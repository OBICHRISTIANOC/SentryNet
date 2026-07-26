"""
app.py — SentryNet Flask application entry point.

Run with:
    python app.py

This module ONLY loads the already-trained model (via ml/predict.py's
import-time load) and initializes the database schema — it never trains
or retrains a model on startup. See ml/train_model.py and the Admin
Panel's "Retrain model" action for the only two ways training happens.
"""

import os

from flask import Flask, jsonify, send_from_directory

from config import Config
from utils.db import init_db
from utils.security import apply_security_headers
from routes.scan import scan_bp
from routes.admin import admin_bp


def create_app():
    # Detect frontend folder for unified single-host deployments
    frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
    serve_frontend = os.environ.get("SERVE_FRONTEND", "0") == "1" or os.environ.get("SERVE_STATIC", "0") == "1"

    if serve_frontend and os.path.exists(frontend_dir):
        app = Flask(__name__, static_folder=frontend_dir, static_url_path="")
    else:
        app = Flask(__name__)

    app.config.from_object(Config)

    init_db()  # idempotent — creates tables + seeds default admin on first run only

    app.register_blueprint(scan_bp)
    app.register_blueprint(admin_bp)

    # ---- Minimal hand-rolled CORS (no external dependency) ----
    @app.after_request
    def add_cors_and_security_headers(response):
        response.headers["Access-Control-Allow-Origin"] = Config.ALLOWED_ORIGIN
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return apply_security_headers(response)

    @app.route("/api/<path:_any>", methods=["OPTIONS"])
    def cors_preflight(_any):
        return "", 204

    # Optional unified static serving
    if serve_frontend and os.path.exists(frontend_dir):
        @app.route("/")
        def serve_index():
            return send_from_directory(frontend_dir, "index.html")

        @app.route("/<path:path>")
        def serve_static(path):
            if os.path.exists(os.path.join(frontend_dir, path)):
                return send_from_directory(frontend_dir, path)
            # Fallback to index.html for SPA/HTML pages if missing extension
            if not os.path.extsep in path and os.path.exists(os.path.join(frontend_dir, path + ".html")):
                return send_from_directory(frontend_dir, path + ".html")
            return jsonify({"error": "Not found."}), 404

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "Not found."}), 404

    @app.errorhandler(500)
    def server_error(_e):
        return jsonify({"error": "Internal server error."}), 500

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"SentryNet API starting on http://0.0.0.0:{port} (debug={debug})")
    app.run(host="0.0.0.0", port=port, debug=debug)

