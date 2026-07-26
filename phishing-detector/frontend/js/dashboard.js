/**
 * dashboard.js — Dashboard page controller.
 * Reads scan history from localStorage (written by scanner.js) and
 * renders stat cards, a bar chart, a pie chart, and a history table.
 */

(function () {
  'use strict';

  const HISTORY_KEY = 'sentrynet_scan_history';

  const emptyState = document.getElementById('emptyState');
  const dashContent = document.getElementById('dashContent');

  const cardTotal = document.getElementById('cardTotal');
  const cardSafe = document.getElementById('cardSafe');
  const cardSuspicious = document.getElementById('cardSuspicious');
  const cardPhishing = document.getElementById('cardPhishing');
  const cardAvgRisk = document.getElementById('cardAvgRisk');
  const cardAvgConfidence = document.getElementById('cardAvgConfidence');
  const cardToday = document.getElementById('cardToday');
  const cardWeek = document.getElementById('cardWeek');
  const cardMonth = document.getElementById('cardMonth');

  const barChart = document.getElementById('barChart');
  const pieChart = document.getElementById('pieChart');
  const pieLegend = document.getElementById('pieLegend');

  const tableSearch = document.getElementById('tableSearch');
  const tableFilter = document.getElementById('tableFilter');
  const tableBody = document.getElementById('tableBody');
  const tableEmpty = document.getElementById('tableEmpty');
  const exportCsvBtn = document.getElementById('exportCsvBtn');
  const deleteHistoryBtn = document.getElementById('deleteHistoryBtn');

  function loadHistory() {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
    } catch (e) {
      return [];
    }
  }

  function riskBand(riskScore) {
    if (riskScore <= 15) return 'safe';
    if (riskScore <= 25) return 'lowrisk';
    if (riskScore <= 50) return 'medium';
    if (riskScore <= 75) return 'high';
    return 'critical';
  }

  function formatDate(ts) {
    return new Date(ts).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }
  function formatTime(ts) {
    return new Date(ts).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }

  /* ============================================================
     Stat cards
     ============================================================ */
  function renderStats(history) {
    const total = history.length;
    const safe = history.filter((h) => h.verdict === 'safe').length;
    const suspicious = history.filter((h) => h.verdict === 'suspicious').length;
    const phishing = history.filter((h) => h.verdict === 'phishing').length;
    const avgRisk = total ? Math.round(history.reduce((s, h) => s + (h.riskScore || 0), 0) / total) : 0;
    const avgConfidence = total ? Math.round(history.reduce((s, h) => s + (h.confidenceScore || 0), 0) / total) : 0;

    const now = Date.now();
    const DAY = 86400000;
    const today = history.filter((h) => now - h.time < DAY).length;
    const week = history.filter((h) => now - h.time < DAY * 7).length;
    const month = history.filter((h) => now - h.time < DAY * 30).length;

    cardTotal.textContent = total;
    cardSafe.textContent = safe;
    cardSuspicious.textContent = suspicious;
    cardPhishing.textContent = phishing;
    cardAvgRisk.textContent = avgRisk + '%';
    cardAvgConfidence.textContent = avgConfidence + '%';
    cardToday.textContent = today;
    cardWeek.textContent = week;
    cardMonth.textContent = month;
  }

  /* ============================================================
     Bar chart — threat level distribution
     ============================================================ */
  function renderBarChart(history) {
    const bands = [
      { key: 'safe', label: 'Safe' },
      { key: 'lowrisk', label: 'Low Risk' },
      { key: 'medium', label: 'Medium Risk' },
      { key: 'high', label: 'High Risk' },
      { key: 'critical', label: 'Critical' },
    ];
    const counts = bands.map((b) => history.filter((h) => riskBand(h.riskScore) === b.key).length);
    const max = Math.max(...counts, 1);

    barChart.innerHTML = bands.map((b, i) => {
      const heightPct = Math.round((counts[i] / max) * 100);
      return (
        '<div class="bar-col bar-count-' + b.key + '">' +
          '<div class="bar-track"><div class="bar-fill" data-count="' + counts[i] + '" style="height:0%" data-target="' + heightPct + '"></div></div>' +
          '<span class="bar-label">' + b.label + '</span>' +
        '</div>'
      );
    }).join('');

    requestAnimationFrame(() => {
      barChart.querySelectorAll('.bar-fill').forEach((el) => {
        el.style.height = el.dataset.target + '%';
      });
    });
  }

  /* ============================================================
     Pie chart — verdict distribution (SVG donut)
     ============================================================ */
  function renderPieChart(history) {
    const total = history.length || 1;
    const segments = [
      { key: 'safe', label: 'Safe', color: 'var(--green)', count: history.filter((h) => h.verdict === 'safe').length },
      { key: 'suspicious', label: 'Suspicious', color: 'var(--orange)', count: history.filter((h) => h.verdict === 'suspicious').length },
      { key: 'phishing', label: 'Phishing', color: 'var(--red)', count: history.filter((h) => h.verdict === 'phishing').length },
    ];

    const R = 50;
    const CIRC = 2 * Math.PI * R;
    let offsetAcc = 0;

    const circles = segments.map((s) => {
      const frac = s.count / total;
      const dash = frac * CIRC;
      const circle =
        '<circle cx="60" cy="60" r="' + R + '" fill="none" stroke="' + s.color + '" stroke-width="16" ' +
        'stroke-dasharray="' + dash + ' ' + (CIRC - dash) + '" stroke-dashoffset="' + (-offsetAcc) + '" transform="rotate(-90 60 60)"/>';
      offsetAcc += dash;
      return circle;
    }).join('');

    pieChart.innerHTML = total > 1 || segments.some(s=>s.count>0)
      ? circles + '<circle cx="60" cy="60" r="' + (R - 16) + '" fill="var(--bg-raised)"/>'
      : '<circle cx="60" cy="60" r="' + R + '" fill="none" stroke="var(--border-soft)" stroke-width="16"/>';

    pieLegend.innerHTML = segments.map((s) =>
      '<div class="pie-legend-row"><span class="pie-dot" style="background:' + s.color + '"></span>' +
      s.label + '<span class="pie-val">' + s.count + ' &middot; ' + Math.round((s.count / total) * 100) + '%</span></div>'
    ).join('');
  }

  /* ============================================================
     History table
     ============================================================ */
  function renderTable(history) {
    const query = tableSearch.value.trim().toLowerCase();
    const filter = tableFilter.value;

    const rows = history.filter((h) => {
      const matchesQuery = !query || h.url.toLowerCase().includes(query);
      const matchesFilter = filter === 'all' || h.verdict === filter;
      return matchesQuery && matchesFilter;
    });

    tableBody.innerHTML = '';
    tableEmpty.hidden = rows.length !== 0;

    rows.forEach((h) => {
      const chipClass = h.verdict === 'safe' ? 'chip-safe' : h.verdict === 'phishing' ? 'chip-danger' : 'chip-warn';
      const levelLabel = (h.threatLevel || '').charAt(0).toUpperCase() + (h.threatLevel || '').slice(1);
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td class="td-url" title="' + escapeHtml(h.url) + '">' + escapeHtml(h.url) + '</td>' +
        '<td><span class="chip ' + chipClass + '">' + h.verdict.toUpperCase() + '</span></td>' +
        '<td>' + (levelLabel || '—') + '</td>' +
        '<td>' + (h.confidenceScore != null ? h.confidenceScore + '%' : '—') + '</td>' +
        '<td>' + h.riskScore + '%</td>' +
        '<td>' + formatDate(h.time) + '</td>' +
        '<td>' + formatTime(h.time) + '</td>';
      tableBody.appendChild(tr);
    });
  }

  /* ============================================================
     CSV export
     ============================================================ */
  function exportCsv(history) {
    const header = ['URL', 'Prediction', 'Threat Level', 'Confidence', 'Risk Score', 'Date', 'Time'];
    const lines = [header.join(',')];
    history.forEach((h) => {
      const row = [
        '"' + h.url.replace(/"/g, '""') + '"',
        h.verdict,
        h.threatLevel || '',
        (h.confidenceScore ?? '') + '%',
        h.riskScore + '%',
        formatDate(h.time),
        formatTime(h.time),
      ];
      lines.push(row.join(','));
    });
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentrynet_scan_history.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /* ============================================================
     Init / render pipeline
     ============================================================ */
  function renderAll() {
    const history = loadHistory().sort((a, b) => b.time - a.time);

    if (!history.length) {
      emptyState.hidden = false;
      dashContent.hidden = true;
      return;
    }
    emptyState.hidden = true;
    dashContent.hidden = false;

    renderStats(history);
    renderBarChart(history);
    renderPieChart(history);
    renderTable(history);
  }

  tableSearch.addEventListener('input', () => renderTable(loadHistory().sort((a, b) => b.time - a.time)));
  tableFilter.addEventListener('change', () => renderTable(loadHistory().sort((a, b) => b.time - a.time)));

  exportCsvBtn.addEventListener('click', () => {
    const history = loadHistory().sort((a, b) => b.time - a.time);
    if (history.length) exportCsv(history);
  });

  deleteHistoryBtn.addEventListener('click', () => {
    if (!loadHistory().length) return;
    const confirmed = window.confirm('Delete all scan history? This cannot be undone.');
    if (!confirmed) return;
    localStorage.removeItem(HISTORY_KEY);
    renderAll();
  });

  renderAll();
})();
