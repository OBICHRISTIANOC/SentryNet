"""
report.py — turns predict.py's raw model output into the same rich JSON
shape the frontend's local heuristic (frontend/js/api.js) produces, so
the UI needs zero changes whether it's talking to demo mode or this
live backend. See the contract documented at the top of api.js.
"""

from ml.trusted_domains import find_impersonation

FEATURE_WHY = {
    "url_length": "Phishing URLs are often padded with extra characters to bury the real domain or evade filters.",
    "dot_count": "Extra dots usually mean extra subdomains, a common trick to make a fake host look legitimate.",
    "hyphen_count": 'Hyphens are cheap ways to combine words into a lookalike brand name (e.g. "paypal-secure").',
    "digit_count": "A high digit count can indicate randomly generated or auto-created phishing subdomains.",
    "has_https": "Legitimate sites handling credentials almost always serve over HTTPS.",
    "has_ip": "A raw IP address instead of a domain name is a strong phishing signal — real brands don't link to their IP.",
    "has_at_symbol": 'An "@" symbol can hide the real destination host from a quick visual check.',
    "has_double_slash_redirect": 'A stray "//" after the domain can be used to smuggle in a different redirect target.',
    "entropy": "Measures randomness in the domain string. Auto-generated phishing domains tend to have higher entropy than real words.",
    "redirect_count": "Multiple redirects can be used to obscure the final malicious destination from filters and users.",
    "suspicious_word_count": 'Words like "verify" or "login" are commonly used to create urgency and imitate account-security emails.',
    "domain_length": "Unusually short or long domain labels can indicate a hastily registered throwaway domain.",
    "subdomain_count": "Attackers stack subdomains to push the real (malicious) domain out of the visible address bar.",
    "special_char_count": 'Symbols like "@", "%", or "_" can hide the real destination or evade simple text-matching filters.',
    "has_ssl": "A missing or invalid certificate means the connection cannot be trusted or is unencrypted.",
    "whois_available": "Legitimate businesses usually register domains under a public, verifiable identity rather than a redacted one.",
    "dns_resolves": "Confirms the domain resolves through normal DNS infrastructure rather than unstable or freshly-provisioned records.",
    "domain_age_days": "Phishing domains are typically registered days or weeks before a campaign, then abandoned.",
    "is_suspicious_tld": "This top-level domain is disproportionately used in phishing campaigns.",
}

REASON_ICON = {
    "has_https": "lock", "suspicious_word_count": "keyword", "redirect_count": "redirect",
    "url_length": "ruler", "entropy": "entropy", "domain_age_days": "calendar",
    "has_ip": "ip", "hyphen_count": "hyphen", "has_at_symbol": "at", "is_suspicious_tld": "tld",
}


def band_threat_level(risk_score: int) -> str:
    if risk_score <= 25:
        return "low"
    if risk_score <= 50:
        return "medium"
    if risk_score <= 75:
        return "high"
    return "critical"


def band_verdict(risk_score: int) -> str:
    if risk_score <= 25:
        return "safe"
    if risk_score <= 50:
        return "suspicious"
    return "phishing"


def build_report(raw_url: str, prediction: dict) -> dict:
    features = {f["key"]: f for f in prediction["features"]}
    meta = prediction["meta"]
    hostname = meta["hostname"]

    risk_score = prediction["riskScore"]
    impersonation = find_impersonation(hostname) if hostname else None
    if impersonation:
        # A confident brand match is, on its own, a strong enough signal
        # that it shouldn't be diluted by otherwise-clean lexical features.
        risk_score = max(risk_score, round(impersonation["similarityScore"] * 0.9))

    verdict = band_verdict(risk_score)
    threat_level = band_threat_level(risk_score)

    # ---- Developer Mode: technical analysis cards ----
    technical_analysis = [
        {"label": "Random Forest prediction",
         "value": "Legitimate" if verdict == "safe" else ("Suspicious" if verdict == "suspicious" else "Phishing"),
         "why": "The final class output by the ensemble of decision trees, taken by majority vote across all trees.",
         "impact": "reduced" if verdict == "safe" else "increased"},
        {"label": "Prediction probability", "value": f"{risk_score}%",
         "why": "The proportion of trees in the forest that voted for the \"phishing\" class.",
         "impact": "increased" if risk_score >= 50 else "reduced"},
        {"label": "Model confidence", "value": f"{prediction['confidenceScore']}%",
         "why": "How decisively the trees agreed — high confidence means most trees reached the same verdict.",
         "impact": "neutral"},
        {"label": "Feature importance", "value": ", ".join(prediction["topFeatures"][:3]),
         "why": "The features that contributed most to this specific prediction, ranked by their weight in the forest's decision.",
         "impact": "neutral"},
    ]
    for key in [
        "entropy", "url_length", "dot_count", "hyphen_count", "digit_count", "has_https", "has_ssl",
        "subdomain_count", "redirect_count", "has_ip", "domain_age_days", "special_char_count",
        "suspicious_word_count", "whois_available", "dns_resolves", "is_suspicious_tld",
    ]:
        f = features[key]
        technical_analysis.append({
            "label": f["name"],
            "value": _display_value(key, f["value"]),
            "why": FEATURE_WHY[key],
            "impact": "increased" if f["status"] in ("danger", "warn") else "reduced",
        })
    # Similarity score, presented alongside the impersonation banner.
    technical_analysis.append({
        "label": "Similarity score",
        "value": f"{impersonation['similarityScore']}% match to {impersonation['brand']}" if impersonation else "No close brand match",
        "why": "Compares the domain against known trusted brands using string-edit distance to catch lookalike spelling.",
        "impact": "increased" if impersonation else "reduced",
    })

    # ---- Why this website is risky ----
    risk_reasons = []
    if features["has_https"]["value"] == 0:
        risk_reasons.append({"icon": "lock", "text": "HTTPS certificate missing"})
    if features["suspicious_word_count"]["value"] >= 1:
        risk_reasons.append({"icon": "keyword", "text": f"Contains suspicious keyword(s): {', '.join(meta['matched_suspicious_words'][:2])}"})
    if features["redirect_count"]["value"] >= 2:
        risk_reasons.append({"icon": "redirect", "text": f"{features['redirect_count']['value']} redirects detected"})
    if features["url_length"]["value"] > 75:
        risk_reasons.append({"icon": "ruler", "text": "Excessive URL length"})
    if impersonation:
        risk_reasons.append({"icon": "brand", "text": f"Looks similar to {impersonation['brand']}"})
    if features["entropy"]["value"] > 3.6:
        risk_reasons.append({"icon": "entropy", "text": "High entropy in domain name"})
    if features["domain_age_days"]["value"] < 60:
        risk_reasons.append({"icon": "calendar", "text": "Recently registered domain"})
    if features["has_ip"]["value"] == 1:
        risk_reasons.append({"icon": "ip", "text": "Contains embedded IP address"})
    if features["hyphen_count"]["value"] >= 2:
        risk_reasons.append({"icon": "hyphen", "text": "Too many hyphens in domain"})
    if features["has_at_symbol"]["value"] == 1:
        risk_reasons.append({"icon": "at", "text": 'Contains "@" symbol in URL'})
    if features["is_suspicious_tld"]["value"] == 1:
        risk_reasons.append({"icon": "tld", "text": "Uses a high-risk top-level domain"})
    if not risk_reasons:
        risk_reasons.append({"icon": "check", "text": "No significant risk indicators were detected"})

    # ---- URL breakdown ----
    url_parts = {
        "protocol": {"value": meta["protocol"], "safe": meta["protocol"] == "HTTPS",
                     "reason": "Encrypted connection." if meta["protocol"] == "HTTPS" else "No TLS encryption in use."},
        "subdomain": {"value": meta["subdomain"] or "(none)", "risky": features["subdomain_count"]["value"] > 3,
                      "reason": "Unusually deep subdomain chain can mask the real host." if features["subdomain_count"]["value"] > 3 else "Subdomain depth is within normal range."},
        "domain": {"value": meta["domain"], "risky": bool(impersonation) or risk_score >= 50,
                   "reason": (f"Domain closely resembles {impersonation['brand']} ({impersonation['similarityScore']}% similar)."
                              if impersonation else ("Domain structure matches known phishing patterns." if risk_score >= 50 else "No brand impersonation detected."))},
        "tld": {"value": ("." + meta["tld"]) if meta["tld"] else "(none)", "risky": features["is_suspicious_tld"]["value"] == 1,
                "reason": "This TLD is disproportionately used in phishing campaigns." if features["is_suspicious_tld"]["value"] == 1 else "No strong abuse association for this TLD."},
        "path": {"value": meta["path"] if meta["path"] and meta["path"] != "/" else "(none)"},
        "query": {"value": ("?" + meta["query"]) if meta["query"] else "(none)"},
        "fragment": {"value": ("#" + meta["fragment"]) if meta["fragment"] else "(none)"},
    }

    return {
        "url": raw_url,
        "verdict": verdict,
        "threatLevel": threat_level,
        "riskScore": risk_score,
        "confidenceScore": prediction["confidenceScore"],
        "securityScore": 100 - risk_score,
        "model": "RandomForestClassifier",
        "features": [
            {"name": f["name"], "detail": FEATURE_WHY[f["key"]], "status": f["status"], "weight": f["weight"]}
            for f in prediction["features"]
        ],
        "technicalAnalysis": technical_analysis,
        "riskReasons": risk_reasons,
        "urlParts": url_parts,
        "impersonation": impersonation,
    }


def _display_value(key, value):
    if key == "has_https":
        return "Present" if value else "Missing"
    if key == "has_ssl":
        return "Valid certificate detected" if value else "No certificate to verify"
    if key == "has_ip":
        return "Detected" if value else "Not detected"
    if key == "whois_available":
        return "Publicly listed registrant" if value else "Private / redacted registrant"
    if key == "dns_resolves":
        return "Resolves normally" if value else "Resolution issue detected"
    if key == "domain_age_days":
        return f"{value} days" if value < 365 else f"{round(value / 365, 1)} years"
    if key == "entropy":
        return f"{value} bits"
    if key == "url_length":
        return f"{value} characters"
    if key == "is_suspicious_tld":
        return "High-risk TLD" if value else "Standard TLD"
    return str(value)
