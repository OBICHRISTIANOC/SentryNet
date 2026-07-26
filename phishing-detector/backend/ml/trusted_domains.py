"""
trusted_domains.py — reference list of frequently-impersonated brands, plus
string-similarity helpers used to flag lookalike domains.

This mirrors frontend/js/trusted-domains.js so the backend and the
JS demo-mode fallback agree on the same detection contract. In a larger
production system this registry would live in the database (see
utils/db.py) so it can be managed from the Admin Panel — the current
in-memory REGISTRY below is the seed data used to populate that table
on first run.
"""

REGISTRY = [
    {"name": "PayPal", "domain": "paypal.com", "official": "https://www.paypal.com", "aliases": ["paypal"]},
    {"name": "Facebook", "domain": "facebook.com", "official": "https://www.facebook.com", "aliases": ["facebook", "fb"]},
    {"name": "Instagram", "domain": "instagram.com", "official": "https://www.instagram.com", "aliases": ["instagram", "insta"]},
    {"name": "Google", "domain": "google.com", "official": "https://www.google.com", "aliases": ["google", "gmail"]},
    {"name": "Microsoft", "domain": "microsoft.com", "official": "https://www.microsoft.com", "aliases": ["microsoft", "msft", "outlook"]},
    {"name": "Apple", "domain": "apple.com", "official": "https://www.apple.com", "aliases": ["apple", "icloud"]},
    {"name": "Amazon", "domain": "amazon.com", "official": "https://www.amazon.com", "aliases": ["amazon"]},
    {"name": "Netflix", "domain": "netflix.com", "official": "https://www.netflix.com", "aliases": ["netflix"]},
    {"name": "eBay", "domain": "ebay.com", "official": "https://www.ebay.com", "aliases": ["ebay"]},
    {"name": "LinkedIn", "domain": "linkedin.com", "official": "https://www.linkedin.com", "aliases": ["linkedin"]},
    {"name": "GTBank", "domain": "gtbank.com", "official": "https://www.gtbank.com", "aliases": ["gtbank", "gtbnk", "gtb"]},
    {"name": "Access Bank", "domain": "accessbankplc.com", "official": "https://www.accessbankplc.com", "aliases": ["accessbank"]},
    {"name": "First Bank", "domain": "firstbanknigeria.com", "official": "https://www.firstbanknigeria.com", "aliases": ["firstbank"]},
    {"name": "Zenith Bank", "domain": "zenithbank.com", "official": "https://www.zenithbank.com", "aliases": ["zenithbank"]},
    {"name": "Chase", "domain": "chase.com", "official": "https://www.chase.com", "aliases": ["chase"]},
    {"name": "Bank of America", "domain": "bankofamerica.com", "official": "https://www.bankofamerica.com", "aliases": ["bankofamerica", "bofa"]},
    {"name": "WhatsApp", "domain": "whatsapp.com", "official": "https://www.whatsapp.com", "aliases": ["whatsapp"]},
    {"name": "X (Twitter)", "domain": "x.com", "official": "https://x.com", "aliases": ["twitter"]},
    {"name": "Dropbox", "domain": "dropbox.com", "official": "https://www.dropbox.com", "aliases": ["dropbox"]},
    {"name": "Coinbase", "domain": "coinbase.com", "official": "https://www.coinbase.com", "aliases": ["coinbase"]},
]


def levenshtein(a: str, b: str) -> int:
    """Classic edit-distance DP. O(len(a)*len(b)), fine at this string size."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        prev = curr
    return prev[-1]


def similarity(a: str, b: str) -> int:
    """0-100 similarity score between two strings (100 = identical)."""
    longer = max(len(a), len(b))
    if longer == 0:
        return 100
    dist = levenshtein(a.lower(), b.lower())
    return round((1 - dist / longer) * 100)


def _clean(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum())


def find_impersonation(hostname: str, registry=None):
    """
    Compares a hostname against the trusted registry and returns the
    closest brand match if the hostname looks like an attempted
    impersonation (high similarity, but not the real domain or a
    legitimate subdomain of it).

    Tokenizes on hyphens/underscores because phishing domains often
    append words like "-login" or "-security" around the imitated
    brand name (e.g. "paypal-login-secure").
    """
    registry = registry if registry is not None else REGISTRY
    host = hostname.lower()
    if host.startswith("www."):
        host = host[4:]

    first_label = host.split(".")[0]
    candidate_strings = [_clean(first_label)]
    for token in first_label.replace("_", "-").split("-"):
        cleaned = _clean(token)
        if cleaned:
            candidate_strings.append(cleaned)

    best = None
    for brand in registry:
        if host == brand["domain"] or host.endswith("." + brand["domain"]):
            continue  # exact or legitimate subdomain — not impersonation

        brand_names = [brand["domain"].split(".")[0]] + list(brand["aliases"])
        best_for_brand = 0
        for candidate in candidate_strings:
            if len(candidate) < 3:
                continue
            for name in brand_names:
                score = similarity(candidate, _clean(name))
                if score > best_for_brand:
                    best_for_brand = score

        if best is None or best_for_brand > best["score"]:
            best = {"brand": brand, "score": best_for_brand}

    if best and best["score"] >= 70:
        return {
            "brand": best["brand"]["name"],
            "officialUrl": best["brand"]["official"],
            "similarityScore": best["score"],
        }
    return None
