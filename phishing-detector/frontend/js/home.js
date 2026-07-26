/**
 * home.js — drives the hero "live scan feed" console.
 * Purely presentational/demo data; the real scanner page hits the API.
 */

(function () {
  'use strict';

  const body = document.getElementById('consoleBody');
  const ringFg = document.getElementById('ringFg');
  const ringLabel = document.getElementById('ringLabel');
  const metaSub = document.getElementById('consoleMetaSub');
  if (!body) return;

  const SAMPLE_SCANS = [
    { url: 'secure-paypal-verify.tk/login', verdict: 'danger', score: 94 },
    { url: 'github.com/anthropic', verdict: 'safe', score: 3 },
    { url: 'update-icloud-account.co/reset', verdict: 'danger', score: 88 },
    { url: 'accounts.google.com', verdict: 'safe', score: 2 },
    { url: 'bank0famerica-secure.net', verdict: 'danger', score: 91 },
    { url: 'wikipedia.org/wiki/Phishing', verdict: 'safe', score: 4 },
    { url: '192.168.44.2/wp-login.verify', verdict: 'warn', score: 61 },
    { url: 'amazon-order-confirm123.info', verdict: 'danger', score: 97 },
  ];

  const CIRC = 163;
  const VERDICT_META = {
    safe:   { label: 'SAFE',    className: 'chip-safe',   color: 'var(--green)' },
    warn:   { label: 'WARN',    className: 'chip-warn',   color: 'var(--orange)' },
    danger: { label: 'PHISH',   className: 'chip-danger', color: 'var(--red)' },
  };

  const MAX_LINES = 6;
  let i = 0;

  function pushLine(scan) {
    const meta = VERDICT_META[scan.verdict];
    const line = document.createElement('div');
    line.className = 'console-line';
    line.innerHTML =
      '<span class="url">' + scan.url + '</span>' +
      '<span class="chip ' + meta.className + ' verdict">' + meta.label + '</span>';
    body.appendChild(line);

    while (body.children.length > MAX_LINES) {
      body.removeChild(body.firstChild);
    }

    if (ringFg && ringLabel) {
      const offset = CIRC - (CIRC * scan.score) / 100;
      ringFg.style.stroke = meta.color;
      ringFg.style.strokeDashoffset = String(offset);
      ringLabel.textContent = scan.score + '%';
    }
    if (metaSub) {
      metaSub.textContent =
        scan.verdict === 'safe' ? 'No threat indicators found' :
        scan.verdict === 'warn' ? 'Mixed signals — flagged for review' :
        'High-confidence phishing pattern';
    }
  }

  function tick() {
    pushLine(SAMPLE_SCANS[i % SAMPLE_SCANS.length]);
    i++;
  }

  tick();
  setInterval(tick, 2200);

  /* ============================================================
     Recent Threats widget — reads real scan history from this
     browser (written by the URL Scanner page).
     ============================================================ */
  (function renderRecentThreats() {
    const listEl = document.getElementById('threatsList');
    const emptyEl = document.getElementById('threatsEmpty');
    if (!listEl) return;

    let history = [];
    try {
      history = JSON.parse(localStorage.getItem('sentrynet_scan_history') || '[]');
    } catch (e) { /* ignore */ }

    const threats = history
      .filter((h) => h.verdict === 'phishing' || h.verdict === 'suspicious')
      .sort((a, b) => b.time - a.time)
      .slice(0, 5);

    if (!threats.length) {
      emptyEl.hidden = false;
      return;
    }

    listEl.innerHTML = threats.map((t) => {
      const isPhishing = t.verdict === 'phishing';
      const icon = isPhishing
        ? '<path d="M12 9v4m0 4h.01M10.3 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L14.7 3.86a2 2 0 00-3.4 0z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>'
        : '<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.7"/><path d="M12 8v5M12 16h.01" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>';
      const timeAgo = (() => {
        const s = Math.floor((Date.now() - t.time) / 1000);
        if (s < 60) return 'just now';
        if (s < 3600) return Math.floor(s / 60) + 'm ago';
        if (s < 86400) return Math.floor(s / 3600) + 'h ago';
        return Math.floor(s / 86400) + 'd ago';
      })();
      return (
        '<div class="threat-row' + (isPhishing ? '' : ' threat-suspicious') + '">' +
          '<span class="t-icon"><svg viewBox="0 0 24 24" fill="none">' + icon + '</svg></span>' +
          '<span class="t-url">' + escapeHtml(t.url) + '</span>' +
          '<span class="t-score">' + t.riskScore + '% risk</span>' +
          '<span class="t-time">' + timeAgo + '</span>' +
        '</div>'
      );
    }).join('');
  })();
})();
