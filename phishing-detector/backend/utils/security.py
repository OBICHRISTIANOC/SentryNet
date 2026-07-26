"""
security.py — request validation, sanitization, rate limiting, and
suspicious-activity logging shared across every route.

Threat model covered here:
  - SQL injection      -> we never string-format SQL (see utils/db.py);
                           this module additionally flags obvious SQLi
                           payloads in incoming text fields for logging.
  - XSS                -> all API responses are JSON, not HTML, so there
                           is no reflected-HTML surface; text fields are
                           still length-capped and control-character
                           stripped before storage, and a strict CSP
                           header is set on every response as defence
                           in depth.
  - Abuse / brute force -> a lightweight in-memory sliding-window rate
                           limiter, keyed by client IP + route.
  - Malformed/hostile URLs -> scheme allow-list, length cap, control
                           character rejection before the URL ever
                           reaches feature extraction.
"""

import re
import time
from functools import wraps
from urllib.parse import urlparse

from flask import request, jsonify, current_app
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https", ""}  # "" covers bare domains like "example.com"

SQLI_PATTERNS = [
    r"(\bunion\b.+\bselect\b)", r"(\bor\b\s+1\s*=\s*1)", r"(;\s*drop\s+table)",
    r"(--\s)", r"(\bxp_cmdshell\b)", r"('\s*or\s*')",
]
XSS_PATTERNS = [
    r"<\s*script", r"javascript\s*:", r"on\w+\s*=\s*['\"]", r"<\s*iframe",
]

_SQLI_RE = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]
_XSS_RE = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]


# ============================================================
# URL validation & sanitization
# ============================================================

class InvalidUrlError(ValueError):
    pass


def sanitize_url(raw: str) -> str:
    """
    Validates and normalizes a URL submitted to /api/scan.
    Raises InvalidUrlError with a user-safe message on anything invalid.
    """
    if not raw or not isinstance(raw, str):
        raise InvalidUrlError("URL is required.")

    candidate = raw.strip()

    if len(candidate) > MAX_URL_LENGTH:
        raise InvalidUrlError(f"URL exceeds the {MAX_URL_LENGTH} character limit.")

    # Reject control/non-printable characters outright (log-injection /
    # smuggling defence) rather than trying to strip and continue.
    if any(ord(ch) < 32 for ch in candidate):
        raise InvalidUrlError("URL contains invalid control characters.")

    normalized = candidate if re.match(r"^https?://", candidate, re.IGNORECASE) else "http://" + candidate

    parsed = urlparse(normalized)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise InvalidUrlError("Only http/https URLs are supported.")
    if not parsed.hostname:
        raise InvalidUrlError("URL is missing a valid host.")

    return normalized


def contains_attack_pattern(text: str) -> str | None:
    """Returns a short label ('sqli' / 'xss') if text matches a known
    attack pattern, else None. Used for logging, not for blocking valid
    URLs outright (a URL legitimately can contain '--' etc.)."""
    if not text:
        return None
    for rx in _SQLI_RE:
        if rx.search(text):
            return "sqli"
    for rx in _XSS_RE:
        if rx.search(text):
            return "xss"
    return None


def sanitize_text(value: str, max_len=500) -> str:
    """General-purpose sanitizer for admin form fields (usernames, brand
    names, etc): strips control characters and caps length."""
    if value is None:
        return ""
    cleaned = "".join(ch for ch in str(value) if ord(ch) >= 32)
    return cleaned.strip()[:max_len]


# ============================================================
# Rate limiting (in-memory sliding window — no external dependency)
# ============================================================

_hits = {}  # key -> list[timestamps]


def rate_limit(max_requests: int, window_seconds: int):
    """Decorator: limits a route to `max_requests` per `window_seconds`
    per client IP. Logs and returns 429 when exceeded."""
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
            key = f"{fn.__name__}:{ip}"
            now = time.time()
            window_start = now - window_seconds

            hits = [t for t in _hits.get(key, []) if t > window_start]
            if len(hits) >= max_requests:
                from utils.db import log_event
                log_event("warning", f"Rate limit exceeded on {fn.__name__} by {ip}", ip)
                return jsonify({"error": "Too many requests. Please slow down."}), 429

            hits.append(now)
            _hits[key] = hits
            return fn(*args, **kwargs)
        return wrapped
    return decorator


# ============================================================
# Admin token auth (stateless, signed, expiring)
# ============================================================

TOKEN_MAX_AGE_SECONDS = 60 * 60 * 8  # 8 hours


def _serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt="sentrynet-admin")


def issue_token(username: str) -> str:
    return _serializer().dumps({"username": username})


def verify_token(token: str):
    try:
        data = _serializer().loads(token, max_age=TOKEN_MAX_AGE_SECONDS)
        return data.get("username")
    except (BadSignature, SignatureExpired):
        return None


def require_admin(fn):
    """Route decorator — requires a valid `Authorization: Bearer <token>` header."""
    @wraps(fn)
    def wrapped(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else None
        username = verify_token(token) if token else None
        if not username:
            return jsonify({"error": "Unauthorized. Please log in again."}), 401
        request.admin_username = username
        return fn(*args, **kwargs)
    return wrapped


# ============================================================
# Security headers (defence in depth for the XSS/clickjacking surface)
# ============================================================

def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response
