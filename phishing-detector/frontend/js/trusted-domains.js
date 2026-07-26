/**
 * trusted-domains.js — a small reference list of frequently-impersonated
 * brands, plus string-similarity helpers used to flag lookalike domains.
 *
 * In production this list (and the similarity threshold) would live in the
 * Flask backend next to the model, likely backed by a larger curated set.
 */

const TrustedDomains = (function () {
  'use strict';

  const REGISTRY = [
    { name: 'PayPal', domain: 'paypal.com', official: 'https://www.paypal.com', aliases: ['paypal'] },
    { name: 'Facebook', domain: 'facebook.com', official: 'https://www.facebook.com', aliases: ['facebook', 'fb'] },
    { name: 'Instagram', domain: 'instagram.com', official: 'https://www.instagram.com', aliases: ['instagram', 'insta'] },
    { name: 'Google', domain: 'google.com', official: 'https://www.google.com', aliases: ['google', 'gmail'] },
    { name: 'Microsoft', domain: 'microsoft.com', official: 'https://www.microsoft.com', aliases: ['microsoft', 'msft', 'outlook'] },
    { name: 'Apple', domain: 'apple.com', official: 'https://www.apple.com', aliases: ['apple', 'icloud'] },
    { name: 'Amazon', domain: 'amazon.com', official: 'https://www.amazon.com', aliases: ['amazon'] },
    { name: 'Netflix', domain: 'netflix.com', official: 'https://www.netflix.com', aliases: ['netflix'] },
    { name: 'eBay', domain: 'ebay.com', official: 'https://www.ebay.com', aliases: ['ebay'] },
    { name: 'LinkedIn', domain: 'linkedin.com', official: 'https://www.linkedin.com', aliases: ['linkedin'] },
    { name: 'GTBank', domain: 'gtbank.com', official: 'https://www.gtbank.com', aliases: ['gtbank', 'gtbnk', 'gtb'] },
    { name: 'Access Bank', domain: 'accessbankplc.com', official: 'https://www.accessbankplc.com', aliases: ['accessbank'] },
    { name: 'First Bank', domain: 'firstbanknigeria.com', official: 'https://www.firstbanknigeria.com', aliases: ['firstbank'] },
    { name: 'Zenith Bank', domain: 'zenithbank.com', official: 'https://www.zenithbank.com', aliases: ['zenithbank'] },
    { name: 'Chase', domain: 'chase.com', official: 'https://www.chase.com', aliases: ['chase'] },
    { name: 'Bank of America', domain: 'bankofamerica.com', official: 'https://www.bankofamerica.com', aliases: ['bankofamerica', 'bofa'] },
    { name: 'WhatsApp', domain: 'whatsapp.com', official: 'https://www.whatsapp.com', aliases: ['whatsapp'] },
    { name: 'X (Twitter)', domain: 'x.com', official: 'https://x.com', aliases: ['twitter'] },
    { name: 'Dropbox', domain: 'dropbox.com', official: 'https://www.dropbox.com', aliases: ['dropbox'] },
    { name: 'Coinbase', domain: 'coinbase.com', official: 'https://www.coinbase.com', aliases: ['coinbase'] },
  ];

  /** Levenshtein edit distance between two strings. */
  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    if (m === 0) return n;
    if (n === 0) return m;
    const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...new Array(n).fill(0)]);
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      }
    }
    return dp[m][n];
  }

  /** 0-100 similarity score between two strings (100 = identical). */
  function similarity(a, b) {
    const longer = Math.max(a.length, b.length);
    if (longer === 0) return 100;
    const dist = levenshtein(a.toLowerCase(), b.toLowerCase());
    return Math.round((1 - dist / longer) * 100);
  }

  /**
   * Compares a hostname against the trusted registry and returns the
   * closest brand match if the hostname looks like an attempted
   * impersonation (high similarity, but not an exact/subdomain match).
   */
  function findImpersonation(hostname) {
    const host = hostname.toLowerCase().replace(/^www\./, '');
    const firstLabel = host.split('.')[0];
    // Compare both the whole label and its hyphen-separated tokens, since
    // phishing domains often append words like "-login" or "-security"
    // around the imitated brand name (e.g. "paypal-login-secure").
    const candidateStrings = [
      firstLabel.replace(/[^a-z0-9]/g, ''),
      ...firstLabel.split(/[-_]+/).map((t) => t.replace(/[^a-z0-9]/g, '')).filter(Boolean),
    ];

    let best = null;

    REGISTRY.forEach((brand) => {
      // Exact match or legitimate subdomain of the real domain — not impersonation.
      if (host === brand.domain || host.endsWith('.' + brand.domain)) return;

      const brandNames = [brand.domain.split('.')[0], ...brand.aliases];
      let bestForBrand = 0;
      candidateStrings.forEach((candidate) => {
        if (candidate.length < 3) return;
        brandNames.forEach((name) => {
          const score = similarity(candidate, name.replace(/[^a-z0-9]/g, ''));
          if (score > bestForBrand) bestForBrand = score;
        });
      });

      if (bestForBrand > (best ? best.score : 0)) {
        best = { brand, score: bestForBrand };
      }
    });

    if (best && best.score >= 70) {
      return {
        brand: best.brand.name,
        officialUrl: best.brand.official,
        similarityScore: best.score,
      };
    }
    return null;
  }

  return { similarity, findImpersonation, REGISTRY };
})();
