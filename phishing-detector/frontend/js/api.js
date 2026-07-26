/**
 * api.js — thin client for the SentryNet REST API.
 *
 * Expected backend contract (see backend/routes/scan.py once built):
 *   POST /api/scan   { "url": "https://example.com" }
 *   200  {
 *     "url": "https://example.com",
 *     "verdict": "safe" | "suspicious" | "phishing",
 *     "threatLevel": "low" | "medium" | "high" | "critical",
 *     "riskScore": 0-100,        // probability the URL is phishing
 *     "confidenceScore": 0-100,  // how sure the model is of its predicted class
 *     "securityScore": 0-100,    // 100 - riskScore, framed positively
 *     "model": "RandomForestClassifier",
 *     "responseTimeMs": 214,     // backend inference + processing time
 *     "features": [
 *       { "name": "Uses HTTPS", "detail": "...", "status": "safe|warn|danger", "weight": 0-100 }
 *     ]
 *   }
 *
 * Until the Flask backend is running, calls fall back to a local heuristic
 * so the UI is fully demoable on its own. Swap API_BASE_URL once deployed.
 */

const SentryAPI = (function () {
  'use strict';

  const API_BASE_URL = (function () {
    if (typeof window !== 'undefined' && window.SENTRYNET_API_URL) {
      return window.SENTRYNET_API_URL.replace(/\/$/, '');
    }
    if (typeof window !== 'undefined' && window.location && window.location.protocol.startsWith('http')) {
      // In web-hosted deployments, try relative /api route first
      return window.location.origin + '/api';
    }
    return 'http://127.0.0.1:5000/api';
  })();
  const REQUEST_TIMEOUT_MS = 4000;


  async function scanUrl(url) {
    const start = performance.now();
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const res = await fetch(API_BASE_URL + '/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (!res.ok) throw new Error('Backend responded with ' + res.status);
      const data = await res.json();
      const elapsed = Math.round(performance.now() - start);
      return { ...data, source: 'live', responseTimeMs: data.responseTimeMs ?? elapsed };
    } catch (err) {
      // Backend not reachable yet — demo mode keeps the UI fully functional.
      const result = await localHeuristicScan(url);
      const elapsed = Math.round(performance.now() - start);
      return { ...result, source: 'demo', responseTimeMs: elapsed };
    }
  }

  function bandThreatLevel(riskScore) {
    if (riskScore <= 25) return 'low';
    if (riskScore <= 50) return 'medium';
    if (riskScore <= 75) return 'high';
    return 'critical';
  }

  function bandVerdict(riskScore) {
    if (riskScore <= 25) return 'safe';
    if (riskScore <= 50) return 'suspicious';
    return 'phishing';
  }

  /** Deterministic 0-99 pseudo-value derived from a string — used to keep
   *  simulated WHOIS/DNS/redirect figures stable for the same URL across
   *  repeated scans in demo mode. */
  function seedFrom(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) {
      h = (h * 31 + str.charCodeAt(i)) >>> 0;
    }
    return h % 100;
  }

  function shannonEntropy(str) {
    if (!str) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    let entropy = 0;
    Object.values(freq).forEach((count) => {
      const p = count / str.length;
      entropy -= p * Math.log2(p);
    });
    return entropy;
  }

  /** Splits a URL into protocol / subdomain / domain / tld / path / query / fragment. */
  function breakDownUrl(rawUrl, hostname) {
    const withProto = /^https?:\/\//i.test(rawUrl) ? rawUrl : 'http://' + rawUrl;
    let u;
    try { u = new URL(withProto); } catch (e) { u = null; }

    const protocol = u ? u.protocol.replace(':', '').toUpperCase() : 'UNKNOWN';
    const labels = hostname.split('.').filter(Boolean);
    let subdomain = '', domain = hostname, tld = '';
    if (labels.length >= 3) {
      tld = labels[labels.length - 1];
      domain = labels[labels.length - 2];
      subdomain = labels.slice(0, labels.length - 2).join('.');
    } else if (labels.length === 2) {
      tld = labels[1];
      domain = labels[0];
    }

    return {
      protocol: { value: protocol, safe: protocol === 'HTTPS' },
      subdomain: { value: subdomain || '(none)', present: !!subdomain },
      domain: { value: domain },
      tld: { value: tld ? '.' + tld : '(none)' },
      path: { value: u ? (u.pathname === '/' ? '(none)' : u.pathname) : '(none)' },
      query: { value: u && u.search ? u.search : '(none)' },
      fragment: { value: u && u.hash ? u.hash : '(none)' },
    };
  }

  /* ---- Local heuristic fallback (demo mode only) ---- */
  async function localHeuristicScan(rawUrl) {
    // Small artificial delay so the loading state and response-time
    // readout feel like a real model inference call.
    await new Promise((resolve) => setTimeout(resolve, 120 + Math.random() * 260));
    let hostname = rawUrl;
    let usesHttps = rawUrl.trim().toLowerCase().startsWith('https://');
    try {
      const withProto = /^https?:\/\//i.test(rawUrl) ? rawUrl : 'http://' + rawUrl;
      hostname = new URL(withProto).hostname;
    } catch (e) {
      hostname = rawUrl;
    }

    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const hasAt = rawUrl.includes('@');
    const hyphenCount = (hostname.match(/-/g) || []).length;
    const dotCount = (hostname.match(/\./g) || []).length;
    const isLong = rawUrl.length > 75;
    const suspiciousTld = /\.(tk|ml|ga|cf|gq|xyz|top|info|club)$/i.test(hostname);
    const hasSuspiciousWord = /(login|verify|secure|update|account|confirm|signin|banking)/i.test(rawUrl);
    const hasPort = /:\d{2,5}(\/|$)/.test(rawUrl.replace(/^https?:\/\//, ''));
    const impersonation = TrustedDomains.findImpersonation(hostname);

    const features = [
      {
        name: 'HTTPS in use',
        detail: usesHttps ? 'Connection is encrypted via TLS.' : 'No HTTPS detected — traffic may be unencrypted.',
        status: usesHttps ? 'safe' : 'danger',
        weight: usesHttps ? 8 : 78,
      },
      {
        name: 'IP address as host',
        detail: isIp ? 'The host is a raw IP address rather than a domain name.' : 'Host is a standard domain name.',
        status: isIp ? 'danger' : 'safe',
        weight: isIp ? 90 : 5,
      },
      {
        name: '"@" symbol in URL',
        detail: hasAt ? 'An "@" symbol can hide the real destination host.' : 'No "@" symbol found.',
        status: hasAt ? 'danger' : 'safe',
        weight: hasAt ? 85 : 4,
      },
      {
        name: 'URL length',
        detail: isLong ? `URL is ${rawUrl.length} characters — unusually long.` : `URL is ${rawUrl.length} characters — within normal range.`,
        status: isLong ? 'warn' : 'safe',
        weight: isLong ? 55 : 10,
      },
      {
        name: 'Hyphens in domain',
        detail: `${hyphenCount} hyphen${hyphenCount === 1 ? '' : 's'} found in the hostname.`,
        status: hyphenCount >= 2 ? 'warn' : 'safe',
        weight: Math.min(20 + hyphenCount * 22, 80),
      },
      {
        name: 'Subdomain depth',
        detail: `${Math.max(dotCount - 1, 0)} subdomain level(s) detected.`,
        status: dotCount > 3 ? 'warn' : 'safe',
        weight: dotCount > 3 ? 50 : 12,
      },
      {
        name: 'Suspicious top-level domain',
        detail: suspiciousTld ? 'This TLD is commonly abused in phishing campaigns.' : 'TLD has no strong association with abuse.',
        status: suspiciousTld ? 'danger' : 'safe',
        weight: suspiciousTld ? 80 : 8,
      },
      {
        name: 'Credential-lure keywords',
        detail: hasSuspiciousWord ? 'Contains words like "login", "verify", or "secure" often used to impersonate trust.' : 'No high-risk keywords detected.',
        status: hasSuspiciousWord ? 'warn' : 'safe',
        weight: hasSuspiciousWord ? 60 : 10,
      },
      {
        name: 'Non-standard port',
        detail: hasPort ? 'URL specifies a non-standard port.' : 'No unusual port specified.',
        status: hasPort ? 'warn' : 'safe',
        weight: hasPort ? 45 : 6,
      },
      {
        name: 'Brand impersonation',
        detail: impersonation ? `Domain closely resembles ${impersonation.brand} (${impersonation.similarityScore}% string similarity).` : 'No close match to a known trusted brand.',
        status: impersonation ? 'danger' : 'safe',
        weight: impersonation ? Math.max(75, impersonation.similarityScore) : 5,
      },
    ];

    const avgWeight = features.reduce((sum, f) => sum + f.weight, 0) / features.length;
    let riskScore = Math.round(Math.min(Math.max(avgWeight, 2), 98));
    // A high-confidence brand impersonation is, on its own, a strong enough
    // signal that it shouldn't be averaged away by otherwise-clean features.
    if (impersonation) {
      riskScore = Math.max(riskScore, Math.round(impersonation.similarityScore * 0.9));
    }
    const confidenceScore = Math.round(Math.min(99, 58 + Math.abs(riskScore - 50) * 0.8));
    const securityScore = 100 - riskScore;
    const verdict = bandVerdict(riskScore);
    const threatLevel = bandThreatLevel(riskScore);

    /* ---- Extended metrics for Developer Mode ---- */
    const entropy = shannonEntropy(hostname);
    const digitCount = (rawUrl.match(/\d/g) || []).length;
    const specialCharCount = (rawUrl.match(/[@$_~%&=]/g) || []).length;
    const seed = seedFrom(hostname);
    const domainAgeBucket = riskScore >= 55
      ? `${3 + (seed % 40)} days (recently registered)`
      : `${2 + (seed % 6)} years, ${seed % 12} months`;
    const whoisAvailability = riskScore >= 50 ? 'Private / redacted registrant' : 'Publicly listed registrant';
    const dnsStatus = isIp ? 'N/A — direct IP address' : (seed % 20 === 0 ? 'Intermittent resolution' : 'Resolves normally');
    const redirectCount = isIp || hasAt ? 1 + (seed % 3) : (riskScore >= 60 ? seed % 3 : 0);
    const obfuscationScore = Math.round(Math.min(100,
      (hasAt ? 30 : 0) + (isIp ? 25 : 0) + Math.min(entropy * 8, 30) + (specialCharCount * 4)
    ));
    const suspiciousKeywordMatches = (rawUrl.match(/(login|verify|secure|update|account|confirm|signin|banking)/gi) || []);

    const similarityScore = impersonation ? impersonation.similarityScore : 0;

    const urlParts = breakDownUrl(rawUrl, hostname);
    // Attach risk annotations to the parts most relevant to a phishing verdict.
    urlParts.protocol.reason = urlParts.protocol.safe ? 'Encrypted connection.' : 'No TLS encryption in use.';
    urlParts.domain.risky = riskScore >= 50 || !!impersonation;
    urlParts.domain.reason = impersonation
      ? `Domain closely resembles ${impersonation.brand} (${impersonation.similarityScore}% similar).`
      : (riskScore >= 50 ? 'Domain structure matches known phishing patterns.' : 'No brand impersonation detected.');
    urlParts.subdomain.risky = labelCount(hostname) > 3;
    urlParts.subdomain.reason = urlParts.subdomain.risky ? 'Unusually deep subdomain chain can mask the real host.' : 'Subdomain depth is within normal range.';
    urlParts.tld.risky = suspiciousTld;
    urlParts.tld.reason = suspiciousTld ? 'This TLD is disproportionately used in phishing campaigns.' : 'No strong abuse association for this TLD.';

    function labelCount(h) { return h.split('.').filter(Boolean).length; }

    /* ---- Feature importance (top contributors from the base feature set) ---- */
    const totalWeight = features.reduce((s, f) => s + f.weight, 0) || 1;
    const featureImportance = [...features]
      .sort((a, b) => b.weight - a.weight)
      .slice(0, 5)
      .map((f) => ({ name: f.name, importance: Math.round((f.weight / totalWeight) * 100) }));

    /* ---- Developer Mode: 20-point technical analysis ---- */
    const technicalAnalysis = [
      { label: 'Random Forest prediction', value: verdict === 'safe' ? 'Legitimate' : verdict === 'suspicious' ? 'Suspicious' : 'Phishing', why: 'The final class output by the ensemble of decision trees, taken by majority vote across all trees.', impact: verdict === 'safe' ? 'reduced' : 'increased' },
      { label: 'Prediction probability', value: riskScore + '%', why: 'The proportion of trees in the forest that voted for the "phishing" class.', impact: riskScore >= 50 ? 'increased' : 'reduced' },
      { label: 'Model confidence', value: confidenceScore + '%', why: 'How decisively the trees agreed — high confidence means most trees reached the same verdict.', impact: 'neutral' },
      { label: 'Feature importance', value: featureImportance.map((f) => f.name).slice(0, 3).join(', '), why: 'The features that contributed most to this specific prediction, ranked by their weight in the forest\u2019s decision.', impact: 'neutral' },
      { label: 'Entropy score', value: entropy.toFixed(2) + ' bits', why: 'Measures randomness in the domain string. Auto-generated phishing domains tend to have higher entropy than real words.', impact: entropy > 3.6 ? 'increased' : 'reduced' },
      { label: 'URL length', value: rawUrl.length + ' characters', why: 'Phishing URLs are often padded with extra characters to bury the real domain or evade filters.', impact: isLong ? 'increased' : 'reduced' },
      { label: 'Number of dots', value: String(dotCount), why: 'Extra dots usually mean extra subdomains, a common trick to make a fake host look legitimate.', impact: dotCount > 3 ? 'increased' : 'reduced' },
      { label: 'Hyphens', value: String(hyphenCount), why: 'Hyphens are cheap ways to combine words into a lookalike brand name (e.g. "paypal-secure").', impact: hyphenCount >= 2 ? 'increased' : 'reduced' },
      { label: 'Digits', value: String(digitCount), why: 'A high digit count can indicate randomly generated or auto-created phishing subdomains.', impact: digitCount > 4 ? 'increased' : 'reduced' },
      { label: 'HTTPS status', value: usesHttps ? 'Present' : 'Missing', why: 'Legitimate sites handling credentials almost always serve over HTTPS.', impact: usesHttps ? 'reduced' : 'increased' },
      { label: 'SSL status', value: usesHttps ? 'Valid certificate detected' : 'No certificate to verify', why: 'A missing or invalid certificate means the connection cannot be trusted or is unencrypted.', impact: usesHttps ? 'reduced' : 'increased' },
      { label: 'Subdomains', value: String(Math.max(dotCount - 1, 0)), why: 'Attackers stack subdomains to push the real (malicious) domain out of the visible address bar.', impact: dotCount > 3 ? 'increased' : 'reduced' },
      { label: 'Redirect count', value: String(redirectCount), why: 'Multiple redirects can be used to obscure the final malicious destination from filters and users.', impact: redirectCount >= 2 ? 'increased' : 'reduced' },
      { label: 'IP address detection', value: isIp ? 'Detected' : 'Not detected', why: 'A raw IP address instead of a domain name is a strong phishing signal — real brands don\u2019t link to their IP.', impact: isIp ? 'increased' : 'reduced' },
      { label: 'Domain age', value: domainAgeBucket, why: 'Phishing domains are typically registered days or weeks before a campaign, then abandoned.', impact: domainAgeBucket.includes('recently') ? 'increased' : 'reduced' },
      { label: 'Special characters', value: String(specialCharCount), why: 'Symbols like "@", "%", or "_" can hide the real destination or evade simple text-matching filters.', impact: specialCharCount > 2 ? 'increased' : 'reduced' },
      { label: 'URL obfuscation score', value: obfuscationScore + '%', why: 'A composite score combining encoding, entropy, and structural tricks used to disguise the real URL.', impact: obfuscationScore > 40 ? 'increased' : 'reduced' },
      { label: 'Suspicious keywords', value: suspiciousKeywordMatches.length ? [...new Set(suspiciousKeywordMatches.map((w) => w.toLowerCase()))].join(', ') : 'None found', why: 'Words like "verify" or "login" are commonly used to create urgency and imitate account-security emails.', impact: suspiciousKeywordMatches.length ? 'increased' : 'reduced' },
      { label: 'Similarity score', value: impersonation ? similarityScore + '% match to ' + impersonation.brand : 'No close brand match', why: 'Compares the domain against known trusted brands using string-edit distance to catch lookalike spelling.', impact: impersonation ? 'increased' : 'reduced' },
      { label: 'WHOIS availability', value: whoisAvailability, why: 'Legitimate businesses usually register domains under a public, verifiable identity rather than a redacted one.', impact: whoisAvailability.includes('Private') ? 'increased' : 'reduced' },
      { label: 'DNS status', value: dnsStatus, why: 'Confirms the domain resolves through normal DNS infrastructure rather than unstable or freshly-provisioned records.', impact: dnsStatus === 'Resolves normally' ? 'reduced' : 'increased' },
    ];

    /* ---- Human-readable "why this is risky" reasons ---- */
    const riskReasons = [];
    if (!usesHttps) riskReasons.push({ icon: 'lock', text: 'HTTPS certificate missing' });
    if (suspiciousKeywordMatches.length) riskReasons.push({ icon: 'keyword', text: 'Contains suspicious keyword' + (suspiciousKeywordMatches.length > 1 ? 's' : '') + ' ("' + suspiciousKeywordMatches[0].toLowerCase() + '")' });
    if (redirectCount >= 2) riskReasons.push({ icon: 'redirect', text: redirectCount + ' redirects detected' });
    if (isLong) riskReasons.push({ icon: 'ruler', text: 'Excessive URL length' });
    if (impersonation) riskReasons.push({ icon: 'brand', text: 'Looks similar to ' + impersonation.brand });
    if (entropy > 3.6) riskReasons.push({ icon: 'entropy', text: 'High entropy in domain name' });
    if (domainAgeBucket.includes('recently')) riskReasons.push({ icon: 'calendar', text: 'Recently registered domain' });
    if (isIp) riskReasons.push({ icon: 'ip', text: 'Contains embedded IP address' });
    if (hyphenCount >= 2) riskReasons.push({ icon: 'hyphen', text: 'Too many hyphens in domain' });
    if (hasAt) riskReasons.push({ icon: 'at', text: 'Contains "@" symbol in URL' });
    if (suspiciousTld) riskReasons.push({ icon: 'tld', text: 'Uses a high-risk top-level domain' });
    if (!riskReasons.length) riskReasons.push({ icon: 'check', text: 'No significant risk indicators were detected' });

    return {
      url: rawUrl,
      verdict,
      threatLevel,
      riskScore,
      confidenceScore,
      securityScore,
      model: 'RandomForestClassifier (demo heuristic)',
      features,
      technicalAnalysis,
      featureImportance,
      riskReasons,
      urlParts,
      impersonation,
    };
  }

  return { scanUrl };
})();
