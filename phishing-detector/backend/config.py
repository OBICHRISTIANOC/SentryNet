"""
config.py — central configuration, overridable via environment variables
so nothing sensitive is hardcoded for a real deployment.
"""

import os
import secrets


class Config:
    # In production, set SENTRYNET_SECRET_KEY explicitly — a random key
    # generated on every restart would invalidate all issued admin tokens.
    SECRET_KEY = os.environ.get("SENTRYNET_SECRET_KEY", secrets.token_hex(32))

    # The origin the static frontend is served from. "*" is convenient
    # for local development but should be locked down to a real origin
    # (e.g. "https://sentrynet.example.com") in production.
    ALLOWED_ORIGIN = os.environ.get("SENTRYNET_ALLOWED_ORIGIN", "*")

    JSON_SORT_KEYS = False
