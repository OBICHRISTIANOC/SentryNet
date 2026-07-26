/**
 * history-store.js — shared scan history persistence + aggregation.
 * Used by scanner.js (writes) and dashboard.js (reads/aggregates/exports).
 */

const HistoryStore = (function () {
  'use strict';

  const KEY = 'sentrynet_scan_history_v2';
  const MAX_ENTRIES = 500;

  function getAll() {
    try {
      const raw = JSON.parse(localStorage.getItem(KEY) || '[]');
      return Array.isArray(raw) ? raw : [];
    } catch (e) {
      return [];
    }
  }

  function add(result) {
    const entry = {
      id: 'scan_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8),
      url: result.url,
      verdict: result.verdict,
      threatLevel: result.threatLevel,
      riskScore: result.riskScore,
      confidenceScore: result.confidenceScore,
      securityScore: result.securityScore,
      responseTimeMs: result.responseTimeMs,
      time: result.scannedAt || Date.now(),
    };
    const all = getAll();
    all.unshift(entry);
    localStorage.setItem(KEY, JSON.stringify(all.slice(0, MAX_ENTRIES)));
    return entry;
  }

  function removeById(id) {
    const all = getAll().filter((e) => e.id !== id);
    localStorage.setItem(KEY, JSON.stringify(all));
  }

  function clear() {
    localStorage.setItem(KEY, JSON.stringify([]));
  }

  /* Risk-score bucket used only for the dashboard bar chart —
     a finer-grained view than the 3-state verdict. */
  function barBucket(riskScore) {
    if (riskScore <= 10) return 'safe';
    if (riskScore <= 30) return 'low';
    if (riskScore <= 55) return 'medium';
    if (riskScore <= 80) return 'high';
    return 'critical';
  }

  function isWithinDays(time, days) {
    const cutoff = Date.now() - days * 86400000;
    return time >= cutoff;
  }

  function isToday(time) {
    const d = new Date(time);
    const now = new Date();
    return d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth() && d.getDate() === now.getDate();
  }

  function stats() {
    const all = getAll();
    const total = all.length;
    const safe = all.filter((e) => e.verdict === 'safe').length;
    const suspicious = all.filter((e) => e.verdict === 'suspicious').length;
    const phishing = all.filter((e) => e.verdict === 'phishing').length;

    const avgRisk = total ? Math.round(all.reduce((s, e) => s + (e.riskScore || 0), 0) / total) : 0;
    const avgConfidence = total ? Math.round(all.reduce((s, e) => s + (e.confidenceScore || 0), 0) / total) : 0;

    const today = all.filter((e) => isToday(e.time)).length;
    const weekly = all.filter((e) => isWithinDays(e.time, 7)).length;
    const monthly = all.filter((e) => isWithinDays(e.time, 30)).length;

    const buckets = { safe: 0, low: 0, medium: 0, high: 0, critical: 0 };
    all.forEach((e) => { buckets[barBucket(e.riskScore || 0)]++; });

    return { total, safe, suspicious, phishing, avgRisk, avgConfidence, today, weekly, monthly, buckets };
  }

  function toCSV() {
    const rows = [['URL', 'Prediction', 'Threat Level', 'Confidence', 'Risk Score', 'Date', 'Time']];
    getAll().forEach((e) => {
      const d = new Date(e.time);
      rows.push([
        e.url,
        e.verdict,
        e.threatLevel,
        e.confidenceScore + '%',
        e.riskScore + '%',
        d.toLocaleDateString(),
        d.toLocaleTimeString(),
      ]);
    });
    return rows
      .map((row) => row.map((cell) => '"' + String(cell).replace(/"/g, '""') + '"').join(','))
      .join('\n');
  }

  return { getAll, add, removeById, clear, stats, toCSV, barBucket };
})();
