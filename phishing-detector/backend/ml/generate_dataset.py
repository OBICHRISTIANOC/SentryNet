"""
generate_dataset.py — builds a labelled training set of legitimate and
phishing-style URLs.

This project doesn't have network access to pull a real corpus (e.g.
PhishTank + Tranco) at build time, so this generator produces synthetic
URLs that follow the *structural* patterns real phishing and legitimate
URLs are known to follow — typosquatted brand names, suspicious TLDs,
raw IP hosts, credential-lure keywords, versus normal domains with
ordinary paths. This keeps the training pipeline fully offline and
reproducible.

For a production deployment, swap `build_dataset()`'s two generator
functions for a loader that reads a real labelled CSV (see
`--csv` support in train_model.py) — the rest of the pipeline
(feature extraction, train/test split, model persistence) is unchanged.
"""

import random
import string

RANDOM_SEED = 42

LEGIT_DOMAINS = [
    "google.com", "wikipedia.org", "github.com", "stackoverflow.com", "amazon.com",
    "microsoft.com", "apple.com", "netflix.com", "bbc.com", "nytimes.com",
    "reddit.com", "linkedin.com", "paypal.com", "facebook.com", "instagram.com",
    "twitter.com", "dropbox.com", "spotify.com", "adobe.com", "salesforce.com",
    "gtbank.com", "accessbankplc.com", "zenithbank.com", "chase.com", "ebay.com",
    "coinbase.com", "whatsapp.com", "yahoo.com", "cnn.com", "medium.com",
    "quora.com", "trello.com", "notion.so", "figma.com", "slack.com",
    "zoom.us", "airbnb.com", "booking.com", "shopify.com", "wordpress.com",
]

LEGIT_SUBDOMAINS = ["", "www", "mail", "docs", "blog", "shop", "support", "accounts", "id"]
LEGIT_PATHS = ["", "/", "/login", "/account", "/help", "/products", "/about", "/pricing", "/docs/api", "/settings"]

BRAND_ROOTS = ["paypal", "facebook", "google", "apple", "microsoft", "amazon", "netflix",
               "gtbank", "instagram", "linkedin", "chase", "ebay", "coinbase", "whatsapp"]
SUSPICIOUS_WORDS = ["login", "verify", "secure", "update", "account", "confirm", "signin", "banking", "alert", "suspend"]
SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "info", "club", "work"]


def _typosquat(brand: str, rng: random.Random) -> str:
    """Applies one random character-level mutation to a brand name."""
    op = rng.choice(["swap_case", "insert", "delete", "double", "substitute"])
    i = rng.randrange(len(brand))
    if op == "swap_case" and brand[i].isalpha():
        return brand[:i] + brand[i].upper() + brand[i + 1:]
    if op == "insert":
        return brand[:i] + rng.choice(string.ascii_lowercase) + brand[i:]
    if op == "delete" and len(brand) > 3:
        return brand[:i] + brand[i + 1:]
    if op == "double":
        return brand[:i] + brand[i] + brand[i:]
    if op == "substitute":
        return brand[:i] + rng.choice(string.ascii_lowercase) + brand[i + 1:]
    return brand


def _random_token(rng: random.Random, length=6):
    return "".join(rng.choices(string.ascii_lowercase + string.digits, k=length))


def _gen_legit_url(rng: random.Random) -> str:
    domain = rng.choice(LEGIT_DOMAINS)
    sub = rng.choice(LEGIT_SUBDOMAINS)
    host = f"{sub}.{domain}" if sub else domain
    path = rng.choice(LEGIT_PATHS)
    query = ""
    if rng.random() < 0.2:
        query = "?ref=" + _random_token(rng, 4)
    return f"https://{host}{path}{query}"


def _gen_phishing_url(rng: random.Random) -> str:
    style = rng.choice(["typosquat", "keyword_stuff", "ip_host", "at_symbol", "random_suspicious_tld", "long_obfuscated"])
    protocol = "https" if rng.random() < 0.35 else "http"  # phishing sites increasingly do use https

    if style == "typosquat":
        brand = rng.choice(BRAND_ROOTS)
        fake = _typosquat(brand, rng)
        extra = rng.choice(SUSPICIOUS_WORDS)
        tld = rng.choice(SUSPICIOUS_TLDS + ["com", "net"])
        return f"{protocol}://{fake}-{extra}.{tld}"

    if style == "keyword_stuff":
        brand = rng.choice(BRAND_ROOTS)
        words = rng.sample(SUSPICIOUS_WORDS, k=rng.randint(1, 2))
        tld = rng.choice(SUSPICIOUS_TLDS)
        return f"{protocol}://{brand}-{'-'.join(words)}.{tld}/session"

    if style == "ip_host":
        ip = ".".join(str(rng.randint(1, 254)) for _ in range(4))
        word = rng.choice(SUSPICIOUS_WORDS)
        return f"{protocol}://{ip}/{word}.php"

    if style == "at_symbol":
        brand = rng.choice(BRAND_ROOTS)
        decoy = _random_token(rng, 8)
        return f"{protocol}://{brand}.com@{decoy}.{rng.choice(SUSPICIOUS_TLDS)}"

    if style == "random_suspicious_tld":
        token = _random_token(rng, rng.randint(6, 12))
        tld = rng.choice(SUSPICIOUS_TLDS)
        return f"{protocol}://{token}.{tld}"

    # long_obfuscated
    brand = rng.choice(BRAND_ROOTS)
    padding = "-".join(_random_token(rng, 4) for _ in range(rng.randint(2, 4)))
    tld = rng.choice(SUSPICIOUS_TLDS)
    return f"{protocol}://{brand}-{padding}-secure-{_random_token(rng, 5)}.{tld}/login/verify"


def build_dataset(n_legit=2500, n_phishing=2500, seed=RANDOM_SEED):
    """Returns a list of (url, label) tuples — label 1 = phishing, 0 = legitimate."""
    rng = random.Random(seed)
    rows = []
    seen = set()

    while sum(1 for _, l in rows if l == 0) < n_legit:
        url = _gen_legit_url(rng)
        if url not in seen:
            seen.add(url)
            rows.append((url, 0))

    while sum(1 for _, l in rows if l == 1) < n_phishing:
        url = _gen_phishing_url(rng)
        if url not in seen:
            seen.add(url)
            rows.append((url, 1))

    rng.shuffle(rows)
    return rows


if __name__ == "__main__":
    import csv
    import os

    rows = build_dataset()
    out_path = os.path.join(os.path.dirname(__file__), "dataset", "phishing_dataset.csv")
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out_path}")
