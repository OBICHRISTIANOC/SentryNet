"""
db.py — lightweight SQLite persistence layer for the Admin Panel.

Security note: every query in this module uses parameterized `?`
placeholders — user-supplied values are NEVER interpolated into SQL
strings. This is the actual defence against SQL injection; see
utils/security.py for the input-validation layer that runs before
values ever reach here.
"""

import os
import sqlite3
import time
from contextlib import contextmanager

from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sentrynet.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    verdict TEXT NOT NULL,
    threat_level TEXT,
    risk_score INTEGER,
    confidence_score INTEGER,
    ip_address TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS trusted_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    brand TEXT NOT NULL,
    domain TEXT UNIQUE NOT NULL,
    official_url TEXT NOT NULL,
    aliases TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    ip_address TEXT,
    created_at TEXT NOT NULL
);
"""

DEFAULT_ADMIN_USERNAME = os.environ.get("SENTRYNET_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASSWORD = os.environ.get("SENTRYNET_ADMIN_PASSWORD", "ChangeMe123!")


@contextmanager
def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Creates tables if they don't exist and seeds a default admin user
    plus the trusted-domain registry on first run. Safe to call on every
    app startup — all statements are idempotent."""
    with get_conn() as conn:
        conn.executescript(SCHEMA)

        existing = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        if existing == 0:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (DEFAULT_ADMIN_USERNAME, generate_password_hash(DEFAULT_ADMIN_PASSWORD), "admin", _now()),
            )
            print(
                f"[SentryNet] Seeded default admin user '{DEFAULT_ADMIN_USERNAME}'. "
                f"Change this password immediately in production (SENTRYNET_ADMIN_PASSWORD env var)."
            )

        domain_count = conn.execute("SELECT COUNT(*) AS c FROM trusted_domains").fetchone()["c"]
        if domain_count == 0:
            from ml.trusted_domains import REGISTRY
            for brand in REGISTRY:
                conn.execute(
                    "INSERT OR IGNORE INTO trusted_domains (brand, domain, official_url, aliases, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (brand["name"], brand["domain"], brand["official"], ",".join(brand["aliases"]), _now()),
                )


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---- Scan history ----------------------------------------------------

def insert_scan(url, verdict, threat_level, risk_score, confidence_score, ip_address):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scan_history (url, verdict, threat_level, risk_score, confidence_score, ip_address, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (url, verdict, threat_level, risk_score, confidence_score, ip_address, _now()),
        )


def list_scans(limit=200, offset=0):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
        return [dict(r) for r in rows]


def delete_scan(scan_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))


def clear_scans():
    with get_conn() as conn:
        conn.execute("DELETE FROM scan_history")


# ---- Users -------------------------------------------------------------

def get_user_by_username(username):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def list_users():
    with get_conn() as conn:
        rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()
        return [dict(r) for r in rows]


def create_user(username, password_hash, role="admin"):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, _now()),
        )


def delete_user(user_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ---- Trusted domains -----------------------------------------------------

def list_trusted_domains():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM trusted_domains ORDER BY brand").fetchall()
        return [dict(r) for r in rows]


def add_trusted_domain(brand, domain, official_url, aliases):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO trusted_domains (brand, domain, official_url, aliases, created_at) VALUES (?, ?, ?, ?, ?)",
            (brand, domain, official_url, aliases, _now()),
        )


def delete_trusted_domain(domain_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM trusted_domains WHERE id = ?", (domain_id,))


# ---- Logs ----------------------------------------------------------------

def log_event(level, message, ip_address=None):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO logs (level, message, ip_address, created_at) VALUES (?, ?, ?, ?)",
            (level, message, ip_address, _now()),
        )


def list_logs(limit=300):
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
