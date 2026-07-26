"""
feature_extraction.py — turns a raw URL into the fixed-length numeric
feature vector consumed by the Random Forest model.

Design notes
------------
Some features (WHOIS registrant/creation date, DNS resolution, live
redirect count, TLS certificate presence) require a network round-trip.
That's fine at *inference* time in production, but during *training* we
extract features for thousands of URLs and can't afford — or in this
sandboxed environment, even perform — that many live lookups.

So every "live" feature is gated by a `live_lookups` flag:
  - live_lookups=True  (default, used by routes/scan.py at request time)
      Attempts a real WHOIS/DNS/TLS/redirect check with a short timeout,
      and falls back to a deterministic simulated value on any failure
      (offline environment, blocked network, lookup timeout, etc).
  - live_lookups=False (used by ml/train_model.py during training)
      Skips the network calls entirely and goes straight to the
      deterministic simulated value, keeping training fast and fully
      offline-reproducible.

The simulated fallback is seeded from a hash of the hostname so the same
URL always yields the same simulated value — this keeps demo results
stable across repeated scans instead of flickering randomly.
"""

import ipaddress
import math
import re
import socket
import ssl
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update", "account", "confirm",
    "signin", "banking", "password", "security", "alert", "suspend",
]

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "info", "club", "work", "loan"}

# The exact order every feature vector is built in — the trained model,
# feature_importances_, and prediction code all rely on this ordering.
FEATURE_ORDER = [
    "url_length", "dot_count", "hyphen_count", "digit_count",
    "has_https", "has_ip", "has_at_symbol", "has_double_slash_redirect",
    "entropy", "redirect_count", "suspicious_word_count", "domain_length",
    "subdomain_count", "special_char_count", "has_ssl", "whois_available",
    "dns_resolves", "domain_age_days", "is_suspicious_tld",
]

FEATURE_LABELS = {
    "url_length": "URL length",
    "dot_count": "Number of dots",
    "hyphen_count": "Hyphens",
    "digit_count": "Digits",
    "has_https": "HTTPS status",
    "has_ip": "IP address detection",
    "has_at_symbol": '"@" symbol in URL',
    "has_double_slash_redirect": '"//" redirect trick',
    "entropy": "Entropy score",
    "redirect_count": "Redirect count",
    "suspicious_word_count": "Suspicious keywords",
    "domain_length": "Domain length",
    "subdomain_count": "Subdomains",
    "special_char_count": "Special characters",
    "has_ssl": "SSL status",
    "whois_available": "WHOIS availability",
    "dns_resolves": "DNS status",
    "domain_age_days": "Domain age",
    "is_suspicious_tld": "Top-level domain risk",
}


def _seed_from(text: str) -> int:
    """Deterministic 0-99 value derived from a string (stable simulated data)."""
    h = 0
    for ch in text:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return h % 100


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


def _normalize(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        raw_url = "http://" + raw_url
    return raw_url


def _is_ip_host(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _check_dns(hostname: str, timeout=1.5) -> bool:
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(hostname)
        return True
    except Exception:
        return False


def _check_ssl(hostname: str, timeout=1.5) -> bool:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert() is not None
    except Exception:
        return False


def _check_whois_age(hostname: str, timeout=2.0):
    """
    Returns (whois_available: bool, age_days: int|None).
    Uses a bare RDAP/WHOIS-free heuristic by default — a full WHOIS
    client (e.g. python-whois) can be swapped in here for production;
    it's kept optional so this module has zero extra dependencies.
    """
    try:
        import whois  # python-whois, optional dependency — see requirements.txt
        w = whois.whois(hostname)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created is None:
            return True, None
        from datetime import datetime
        age_days = (datetime.now() - created).days
        return True, max(age_days, 0)
    except Exception:
        return False, None


def _count_redirects(url: str, timeout=2.5):
    try:
        import requests  # optional — see requirements.txt
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        return len(resp.history)
    except Exception:
        return None


def extract_features(raw_url: str, live_lookups: bool = True) -> dict:
    """
    Returns a dict of {feature_name: numeric_value} in FEATURE_ORDER.
    Also returns a few extra descriptive fields under "_meta" for the
    API layer to build the human-readable report from (hostname parts,
    matched suspicious words, etc) without re-parsing the URL.
    """
    url = _normalize(raw_url)
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    seed = _seed_from(hostname or raw_url)

    labels = [l for l in hostname.split(".") if l]
    tld = labels[-1] if labels else ""
    domain_label = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
    subdomain_labels = labels[:-2] if len(labels) > 2 else []

    matched_words = [w for w in SUSPICIOUS_WORDS if w in raw_url.lower()]
    special_chars = re.findall(r"[@$_~%&=]", raw_url)

    has_https = parsed.scheme == "https"
    has_ip = _is_ip_host(hostname)
    has_at = "@" in raw_url
    # "//" appearing anywhere after the protocol separator is a classic
    # open-redirect / cloaking trick (e.g. "http://real.com//evil.com").
    after_protocol = raw_url.split("://", 1)[-1]
    has_double_slash = "//" in after_protocol

    if live_lookups:
        dns_resolves = _check_dns(hostname) if hostname and not has_ip else has_ip
        has_ssl = _check_ssl(hostname) if has_https else False
        whois_available, age_days = _check_whois_age(hostname) if hostname else (False, None)
        redirects = _count_redirects(url)
        if redirects is None:
            redirects = 1 + (seed % 3) if (has_ip or has_at) else (seed % 2)
    else:
        # Deterministic, network-free stand-ins used during training.
        dns_resolves = True if has_ip else (seed % 20 != 0)
        has_ssl = has_https and (seed % 10 != 0)
        whois_available = seed % 3 != 0
        age_days = (seed % 3000) if whois_available else None
        redirects = 1 + (seed % 3) if (has_ip or has_at) else (seed % 2)

    if age_days is None:
        age_days = 1500  # unknown → treat as neutral/established rather than penalising

    features = {
        "url_length": len(raw_url),
        "dot_count": hostname.count("."),
        "hyphen_count": hostname.count("-"),
        "digit_count": sum(ch.isdigit() for ch in raw_url),
        "has_https": int(has_https),
        "has_ip": int(has_ip),
        "has_at_symbol": int(has_at),
        "has_double_slash_redirect": int(has_double_slash),
        "entropy": round(_shannon_entropy(hostname), 4),
        "redirect_count": redirects,
        "suspicious_word_count": len(matched_words),
        "domain_length": len(domain_label),
        "subdomain_count": len(subdomain_labels),
        "special_char_count": len(special_chars),
        "has_ssl": int(has_ssl),
        "whois_available": int(whois_available),
        "dns_resolves": int(dns_resolves),
        "domain_age_days": age_days,
        "is_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
    }

    meta = {
        "hostname": hostname,
        "protocol": parsed.scheme.upper() or "UNKNOWN",
        "tld": tld,
        "domain": domain_label,
        "subdomain": ".".join(subdomain_labels),
        "path": parsed.path or "",
        "query": parsed.query or "",
        "fragment": parsed.fragment or "",
        "matched_suspicious_words": matched_words,
        "whois_available": whois_available,
        "domain_age_days": age_days,
    }

    return {"features": features, "meta": meta}


def to_vector(features: dict) -> list:
    """Orders a feature dict into the vector shape the model expects."""
    return [features[name] for name in FEATURE_ORDER]
