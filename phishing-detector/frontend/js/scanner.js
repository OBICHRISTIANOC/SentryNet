/**
 * scanner.js — URL Scanner page controller.
 */

(function () {
  'use strict';

  const urlInput = document.getElementById('urlInput');
  const clearIconBtn = document.getElementById('clearIconBtn');
  const analyseBtn = document.getElementById('analyseBtn');
  const pasteBtn = document.getElementById('pasteBtn');
  const clearBtn = document.getElementById('clearBtn');
  const scanError = document.getElementById('scanError');

  const loadingPanel = document.getElementById('loadingPanel');
  const loaderStep = document.getElementById('loaderStep');
  const resultPanel = document.getElementById('resultPanel');

  const resultChip = document.getElementById('resultChip');
  const resultFavicon = document.getElementById('resultFavicon');
  const printReportBtn = document.getElementById('printReportBtn');
  const printReportMeta = document.getElementById('printReportMeta');
  const resultHeadline = document.getElementById('resultHeadline');
  const resultSub = document.getElementById('resultSub');
  const resultUrl = document.getElementById('resultUrl');
  const signalList = document.getElementById('signalList');
  const newScanBtn = document.getElementById('newScanBtn');
  const copyReportBtn = document.getElementById('copyReportBtn');

  const meterNeedle = document.getElementById('meterNeedle');
  const meterRiskValue = document.getElementById('meterRiskValue');
  const meterLevelChip = document.getElementById('meterLevelChip');

  const statStatus = document.getElementById('statStatus');
  const statThreatLevel = document.getElementById('statThreatLevel');
  const statRiskScore = document.getElementById('statRiskScore');
  const statConfidence = document.getElementById('statConfidence');
  const statSecurity = document.getElementById('statSecurity');
  const statResponseTime = document.getElementById('statResponseTime');
  const statTimestamp = document.getElementById('statTimestamp');

  const impersonationBanner = document.getElementById('impersonationBanner');
  const impersonationText = document.getElementById('impersonationText');
  const impersonationLink = document.getElementById('impersonationLink');

  const reasonsList = document.getElementById('reasonsList');
  const breakdownList = document.getElementById('breakdownList');

  const devModeToggle = document.getElementById('devModeToggle');
  const devModeToggleLabel = document.getElementById('devModeToggleLabel');
  const devModePanel = document.getElementById('devModePanel');
  const devGrid = document.getElementById('devGrid');

  const historySection = document.getElementById('historySection');
  const historyList = document.getElementById('historyList');

  const HISTORY_KEY = 'sentrynet_scan_history';
  const HISTORY_CAP = 200;
  const LOADER_STEPS = [
    'Parsing URL structure…',
    'Extracting lexical features…',
    'Checking host reputation signals…',
    'Scoring with Random Forest model…',
    'Compiling report…',
  ];

  let lastResult = null;

  /** Inline icon paths for the "why this is risky" reason rows. */
  const REASON_ICONS = {
    lock: '<path d="M6 11V8a6 6 0 1112 0v3M5 11h14a1 1 0 011 1v8a1 1 0 01-1 1H5a1 1 0 01-1-1v-8a1 1 0 011-1z" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    keyword: '<path d="M4 7h16M4 12h10M4 17h7" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/>',
    redirect: '<path d="M4 7h11a4 4 0 014 4v0a4 4 0 01-4 4H7m0 0l3-3m-3 3l3 3" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>',
    ruler: '<path d="M3 8h18v8H3z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M7 8v3M11 8v3M15 8v3" stroke="currentColor" stroke-width="1.6"/>',
    brand: '<path d="M12 2l2.5 6.5L21 9l-5 4.5L17.5 21 12 17l-5.5 4L8 13.5 3 9l6.5-.5z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>',
    entropy: '<circle cx="6" cy="7" r="1.6" fill="currentColor"/><circle cx="16" cy="6" r="1.6" fill="currentColor"/><circle cx="11" cy="12" r="1.6" fill="currentColor"/><circle cx="18" cy="15" r="1.6" fill="currentColor"/><circle cx="7" cy="17" r="1.6" fill="currentColor"/>',
    calendar: '<rect x="3.5" y="5" width="17" height="16" rx="2" stroke="currentColor" stroke-width="1.6"/><path d="M3.5 10h17M8 3v4M16 3v4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    ip: '<rect x="4" y="7" width="16" height="10" rx="2" stroke="currentColor" stroke-width="1.6"/><path d="M8 11h.01M12 11h.01M16 11h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>',
    hyphen: '<path d="M5 12h14" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>',
    at: '<circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="1.6"/><path d="M16 12v1.5a2.5 2.5 0 005 0V12a9 9 0 10-4 7.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    tld: '<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M3 12h18M12 3a14 14 0 010 18a14 14 0 010-18z" stroke="currentColor" stroke-width="1.6"/>',
    check: '<path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  };

  devModeToggle.addEventListener('click', () => {
    const showing = !devModePanel.hidden;
    devModePanel.hidden = showing;
    devModeToggleLabel.textContent = showing ? 'Show Technical Analysis' : 'Hide Technical Analysis';
  });


  function updateClearIcon() {
    clearIconBtn.hidden = urlInput.value.trim().length === 0;
  }

  function showError(msg) {
    scanError.textContent = msg;
    scanError.hidden = false;
    urlInput.classList.add('invalid');
  }

  function hideError() {
    scanError.hidden = true;
    urlInput.classList.remove('invalid');
  }

  function isPlausibleUrl(value) {
    const v = value.trim();
    if (!v) return false;
    const withProto = /^https?:\/\//i.test(v) ? v : 'http://' + v;
    try {
      const u = new URL(withProto);
      return u.hostname.includes('.') || /^(\d{1,3}\.){3}\d{1,3}$/.test(u.hostname);
    } catch (e) {
      return false;
    }
  }

  urlInput.addEventListener('input', () => {
    updateClearIcon();
    if (!scanError.hidden) hideError();
  });

  urlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') runAnalysis();
  });

  clearIconBtn.addEventListener('click', () => resetToIdle(true));
  clearBtn.addEventListener('click', () => resetToIdle(true));

  pasteBtn.addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        urlInput.value = text.trim();
        updateClearIcon();
        hideError();
        urlInput.focus();
      }
    } catch (err) {
      urlInput.focus();
      showError('Clipboard access was blocked — paste manually with Ctrl/Cmd + V.');
    }
  });

  document.querySelectorAll('.scan-chip-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      urlInput.value = btn.dataset.url;
      updateClearIcon();
      hideError();
      runAnalysis();
    });
  });

  analyseBtn.addEventListener('click', runAnalysis);
  newScanBtn.addEventListener('click', () => resetToIdle(true));

  printReportBtn.addEventListener('click', () => {
    if (!lastResult) return;
    printReportMeta.textContent =
      'Target: ' + lastResult.url + '  \u00b7  Scanned: ' + formatTimestamp(lastResult.scannedAt) +
      '  \u00b7  Verdict: ' + lastResult.verdict.toUpperCase() + '  \u00b7  Risk score: ' + lastResult.riskScore + '%';
    window.print();
  });

  copyReportBtn.addEventListener('click', async () => {
    if (!lastResult) return;
    const lines = [
      'SentryNet Scan Report',
      'URL: ' + lastResult.url,
      'Status: ' + lastResult.verdict.toUpperCase(),
      'Threat level: ' + lastResult.threatLevel.toUpperCase(),
      'Risk score: ' + lastResult.riskScore + '%',
      'Confidence score: ' + lastResult.confidenceScore + '%',
      'Security score: ' + lastResult.securityScore + '/100',
      'Response time: ' + lastResult.responseTimeMs + 'ms',
      'Scanned: ' + formatTimestamp(lastResult.scannedAt),
      'Model: ' + lastResult.model,
      '',
      'Signals:',
      ...lastResult.features.map((f) => '- ' + f.name + ': ' + f.detail),
    ];
    try {
      await navigator.clipboard.writeText(lines.join('\n'));
      const original = copyReportBtn.innerHTML;
      copyReportBtn.innerHTML = 'Copied to clipboard';
      setTimeout(() => (copyReportBtn.innerHTML = original), 1800);
    } catch (err) {
      /* silent — clipboard permission denied */
    }
  });

  /* ============================================================
     Analysis flow
     ============================================================ */
  function resetToIdle(clearInput) {
    if (clearInput) urlInput.value = '';
    updateClearIcon();
    hideError();
    loadingPanel.hidden = true;
    resultPanel.hidden = true;
    resultFavicon.hidden = true;
    setNeedle(0, true);
    urlInput.focus();
  }

  async function runAnalysis() {
    const value = urlInput.value.trim();

    if (!value) {
      showError('Enter a URL to analyse.');
      return;
    }
    if (!isPlausibleUrl(value)) {
      showError('That doesn\u2019t look like a valid URL. Try including the domain, e.g. example.com');
      return;
    }
    hideError();

    resultPanel.hidden = true;
    loadingPanel.hidden = false;
    analyseBtn.disabled = true;
    setNeedle(0, true);

    let stepIndex = 0;
    loaderStep.textContent = LOADER_STEPS[0];
    const stepTimer = setInterval(() => {
      stepIndex = Math.min(stepIndex + 1, LOADER_STEPS.length - 1);
      loaderStep.textContent = LOADER_STEPS[stepIndex];
    }, 480);

    const minWait = new Promise((resolve) => setTimeout(resolve, 2200));
    const [result] = await Promise.all([SentryAPI.scanUrl(value), minWait]);

    clearInterval(stepTimer);
    loadingPanel.hidden = true;
    analyseBtn.disabled = false;

    lastResult = result;
    renderResult(result);
    saveToHistory(result);
  }

  /* ============================================================
     Rendering
     ============================================================ */
  const VERDICT_UI = {
    safe: {
      chipClass: 'chip-safe',
      headline: 'This link looks safe',
      sub: 'No meaningful phishing indicators were found in the URL structure or host.',
    },
    suspicious: {
      chipClass: 'chip-warn',
      headline: 'Proceed with caution',
      sub: 'Some signals are inconsistent with typical legitimate sites. Verify the sender before entering any details.',
    },
    phishing: {
      chipClass: 'chip-danger',
      headline: 'This link looks like phishing',
      sub: 'Multiple high-risk signals match known phishing patterns. Do not enter credentials or personal data.',
    },
  };

  const THREAT_LEVEL_UI = {
    low:      { label: 'Low',      chipClass: 'chip-safe',   toneClass: 'tone-safe' },
    medium:   { label: 'Medium',   chipClass: 'chip-warn',   toneClass: 'tone-warn' },
    high:     { label: 'High',     chipClass: 'chip-danger', toneClass: 'tone-danger' },
    critical: { label: 'Critical', chipClass: 'chip-danger', toneClass: 'tone-danger' },
  };

  function setNeedle(riskScore, instant) {
    const angle = -90 + (Math.min(Math.max(riskScore, 0), 100) / 100) * 180;
    if (instant) meterNeedle.style.transition = 'none';
    meterNeedle.style.transform = 'rotate(' + angle + 'deg)';
    if (instant) {
      // Force reflow so the next transform change re-enables the transition.
      void meterNeedle.offsetWidth;
      meterNeedle.style.transition = '';
    }
  }

  function formatTimestamp(ts) {
    return new Date(ts).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'medium',
    });
  }

  function renderResult(result) {
    const ui = VERDICT_UI[result.verdict] || VERDICT_UI.suspicious;
    const levelUi = THREAT_LEVEL_UI[result.threatLevel] || THREAT_LEVEL_UI.medium;
    result.scannedAt = Date.now();

    resultChip.textContent = result.verdict.toUpperCase();
    resultChip.className = 'chip ' + ui.chipClass;
    resultHeadline.textContent = ui.headline;
    resultSub.textContent = ui.sub;
    resultUrl.textContent = result.url;

    /* Favicon (best-effort — served by Google's public favicon endpoint) */
    try {
      const hostname = new URL(result.url).hostname;
      resultFavicon.src = 'https://www.google.com/s2/favicons?domain=' + hostname + '&sz=64';
      resultFavicon.hidden = false;
      resultFavicon.onerror = () => { resultFavicon.hidden = true; };
    } catch (e) {
      resultFavicon.hidden = true;
    }

    /* Notification for dangerous URLs */
    if (result.verdict === 'phishing') {
      window.SentryToast && window.SentryToast.show(
        'Dangerous URL detected',
        result.url + ' scored ' + result.riskScore + '% risk. Avoid entering any information.',
        'danger'
      );
    } else if (result.verdict === 'suspicious') {
      window.SentryToast && window.SentryToast.show(
        'Suspicious URL',
        result.url + ' has some inconsistent signals — proceed carefully.',
        'warn'
      );
    }

    /* Threat meter */
    meterLevelChip.textContent = levelUi.label.toUpperCase();
    meterLevelChip.className = 'chip ' + levelUi.chipClass;
    meterRiskValue.textContent = result.riskScore + '%';
    requestAnimationFrame(() => setNeedle(result.riskScore, false));

    /* Stats grid */
    statStatus.textContent = ui === VERDICT_UI.safe ? 'Safe' : result.verdict === 'suspicious' ? 'Suspicious' : 'Phishing';
    statStatus.className = 'stat-value ' + levelUi.toneClass;
    statThreatLevel.textContent = levelUi.label;
    statThreatLevel.className = 'stat-value ' + levelUi.toneClass;
    statRiskScore.textContent = result.riskScore + '%';
    statConfidence.textContent = result.confidenceScore + '%';
    statSecurity.innerHTML = result.securityScore + '<span class="stat-unit">/100</span>';
    statResponseTime.innerHTML = result.responseTimeMs + '<span class="stat-unit">ms</span>';
    statTimestamp.textContent = formatTimestamp(result.scannedAt);

    /* Official website suggestion */
    if (result.impersonation) {
      impersonationBanner.hidden = false;
      impersonationText.textContent =
        'This domain closely resembles ' + result.impersonation.brand +
        ' (' + result.impersonation.similarityScore + '% name similarity). It does not appear to be the official site.';
      impersonationLink.textContent = result.impersonation.officialUrl;
      impersonationLink.href = result.impersonation.officialUrl;
    } else {
      impersonationBanner.hidden = true;
    }

    /* Why this website is risky */
    reasonsList.innerHTML = '';
    const isAllClear = result.riskReasons.length === 1 && result.riskReasons[0].icon === 'check';
    result.riskReasons.forEach((r) => {
      const li = document.createElement('li');
      li.className = 'reason-row';
      const iconPath = REASON_ICONS[r.icon] || REASON_ICONS.check;
      li.innerHTML =
        '<span class="reason-icon' + (isAllClear ? ' icon-ok' : '') + '"><svg viewBox="0 0 24 24" fill="none">' + iconPath + '</svg></span>' +
        '<span class="reason-text">' + r.text + '</span>';
      reasonsList.appendChild(li);
    });

    /* URL breakdown */
    breakdownList.innerHTML = '';
    const partOrder = [
      ['protocol', 'Protocol'],
      ['subdomain', 'Subdomain'],
      ['domain', 'Domain'],
      ['tld', 'Top-level domain'],
      ['path', 'Path'],
      ['query', 'Query'],
      ['fragment', 'Fragment'],
    ];
    partOrder.forEach(([key, label]) => {
      const part = result.urlParts[key];
      if (!part) return;
      const risky = !!part.risky || part.safe === false;
      const row = document.createElement('div');
      row.className = 'breakdown-row' + (risky ? ' risky' : '');
      row.innerHTML =
        '<span class="breakdown-label">' + label + '</span>' +
        '<div>' +
          '<div class="breakdown-value">' + part.value + '</div>' +
          (part.reason ? '<div class="breakdown-reason">' + part.reason + '</div>' : '') +
        '</div>';
      breakdownList.appendChild(row);
    });

    /* Developer mode grid */
    devGrid.innerHTML = '';
    result.technicalAnalysis.forEach((item) => {
      const card = document.createElement('div');
      card.className = 'dev-card impact-' + item.impact;
      const impactLabel = item.impact === 'increased' ? 'Increased risk' : item.impact === 'reduced' ? 'Reduced risk' : 'Neutral';
      const impactChipClass = item.impact === 'increased' ? 'chip-danger' : item.impact === 'reduced' ? 'chip-safe' : 'chip-neutral';
      card.innerHTML =
        '<div class="dev-card-top">' +
          '<div>' +
            '<div class="dev-card-label">' + item.label + '</div>' +
            '<div class="dev-card-value">' + item.value + '</div>' +
          '</div>' +
          '<span class="chip ' + impactChipClass + '">' + impactLabel + '</span>' +
        '</div>' +
        '<p class="dev-card-why">' + item.why + '</p>';
      devGrid.appendChild(card);
    });
    devModePanel.hidden = true;
    devModeToggleLabel.textContent = 'Show Technical Analysis';

    signalList.innerHTML = '';
    result.features.forEach((f) => {
      const row = document.createElement('div');
      row.className = 'signal-row';
      row.innerHTML =
        '<span class="signal-name">' + f.name + '</span>' +
        '<div class="signal-bar-track"><div class="signal-bar-fill ' + f.status + '" style="width:' + f.weight + '%"></div></div>' +
        '<span class="chip chip-' + (f.status === 'danger' ? 'danger' : f.status === 'warn' ? 'warn' : 'safe') + ' signal-flag">' + f.status.toUpperCase() + '</span>' +
        '<span class="signal-detail">' + f.detail + '</span>';
      signalList.appendChild(row);
    });

    resultPanel.hidden = false;
    resultPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  /* ============================================================
     History (localStorage)
     ============================================================ */
  function loadHistory() {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    } catch (e) {
      return [];
    }
  }

  function saveToHistory(result) {
    const history = loadHistory();
    history.unshift({
      url: result.url,
      verdict: result.verdict,
      threatLevel: result.threatLevel,
      riskScore: result.riskScore,
      confidenceScore: result.confidenceScore,
      time: Date.now(),
    });
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, HISTORY_CAP)));
    renderHistory();
  }

  function renderHistory() {
    const history = loadHistory();
    if (!history.length) {
      historySection.hidden = true;
      return;
    }
    historySection.hidden = false;
    historyList.innerHTML = '';
    history.slice(0, 8).forEach((item) => {
      const chipClass = item.verdict === 'safe' ? 'chip-safe' : item.verdict === 'phishing' ? 'chip-danger' : 'chip-warn';
      const row = document.createElement('div');
      row.className = 'history-item';
      row.innerHTML =
        '<span class="chip ' + chipClass + '">' + item.verdict.toUpperCase() + '</span>' +
        '<span class="h-url">' + escapeHtml(item.url) + '</span>' +
        '<span class="h-time">' + timeAgo(item.time) + '</span>';
      historyList.appendChild(row);
    });
  }

  function timeAgo(ts) {
    const s = Math.floor((Date.now() - ts) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  /* ---- Init ---- */
  updateClearIcon();
  renderHistory();
})();
