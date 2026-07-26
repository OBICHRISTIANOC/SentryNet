/**
 * impersonation.js — detects likely brand impersonation via string
 * similarity against a small trusted-domain database, and suggests the
 * real official site.
 *
 * In production this table would be a maintained brand/domain registry
 * (or a third-party feed); here it covers commonly-spoofed brands for
 * demo purposes.
 */

const Impersonation = (function () {
  'use strict';

  const TRUSTED_DOMAINS = [
    { brand: 'PayPal', domain: 'paypal.com', official: 'https://www.paypal.com' },
    { brand: 'Facebook', domain: 'facebook.com', official: 'https://facebook.com' },
    { brand: 'Instagram', domain: 'instagram.com', official: 'https://instagram.com' },
    { brand: 'Google', domain: 'google.com', official: 'https://www.google.com' },
    { brand: 'Apple', domain: 'apple.com', official: 'https://www.apple.com' },
    { brand: 'Microsoft', domain: 'microsoft.com', official: 'https://www.microsoft.com' },
    { brand: 'Amazon', domain: 'amazon.com', official: 'https://www.amazon.com' },
    { brand: 'Netflix', domain: 'netflix.com', official: 'https://www.netflix.com' },
    { brand: 'GTBank', domain: 'gtbank.com', official: 'https://gtbank.com' },
    { brand: 'Access Bank', domain: 'accessbankplc.com', official: 'https://www.accessbankplc.com' },
    { brand: 'Zenith Bank', domain: 'zenithbank.com', official: 'https://www.zenithbank.com' },
    { brand: 'First Bank', domain: 'firstbanknigeria.com', official: 'https://www.firstbanknigeria.com' },
    { brand: 'LinkedIn', domain: 'linkedin.com', official: 'https://www.linkedin.com' },
    { brand: 'Twitter / X', domain: 'x.com', official: 'https://x.com' },
    { brand: 'GitHub', domain: 'github.com', official: 'https://github.com' },
    { brand: 'Dropbox', domain: 'dropbox.com', official: 'https://www.dropbox.com' },
    { brand: 'iCloud', domain: 'icloud.com', official: 'https://www.icloud.com' },
    { brand: 'Chase Bank', domain: 'chase.com', official: 'https://www.chase.com' },
    { brand: 'Bank of America', domain: 'bankofamerica.com', official: 'https://www.bankofamerica.com' },
    { brand: 'WhatsApp', domain: 'whatsapp.com', official: 'https://www.whatsapp.com' },
  ];

  /* Levenshtein edit distance */
  function editDistance(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
      }
    }
    return dp[m][n];
  }

  function similarity(a, b) {
    const longer = Math.max(a.length, b.length);
    if (longer === 0) return 1;
    return 1 - editDistance(a, b) / longer;
  }

  /**
   * Finds the closest trusted brand for a given hostname.
   * Returns null if nothing is close enough to flag, or if the
   * hostname IS the trusted domain (exact match = legitimate).
   */
  function findClosestBrand(hostname) {
    const host = (hostname || '').toLowerCase().replace(/^www\./, '');

    const exact = TRUSTED_DOMAINS.find((t) => t.domain === host);
    if (exact) return { match: exact, score: 1, exact: true };

    let best = null;
    let bestScore = 0;

    TRUSTED_DOMAINS.forEach((t) => {
      const brandCore = t.domain.split('.')[0];
      const hostCore = host.split('.')[0];
      const score = similarity(hostCore, brandCore);
      if (score > bestScore) {
        bestScore = score;
        best = t;
      }
    });

    if (best && bestScore >= 0.55 && bestScore < 1) {
      return { match: best, score: bestScore, exact: false };
    }
    return null;
  }

  return { TRUSTED_DOMAINS, similarity, findClosestBrand };
})();
