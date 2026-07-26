/**
 * admin.js — Admin Panel dashboard controller.
 * Every data operation goes through AdminAuth.apiFetch (see
 * admin-auth.js), which attaches the Bearer token and redirects to
 * admin-login.html on a 401.
 */

(function () {
  'use strict';

  if (!AdminAuth.isLoggedIn()) {
    window.location.href = 'admin-login.html';
    return;
  }

  const globalError = document.getElementById('globalError');
  const backendStatus = document.getElementById('backendStatus');

  document.getElementById('adminUsername').textContent = AdminAuth.getUsername() || 'admin';
  document.getElementById('adminAvatar').textContent = (AdminAuth.getUsername() || 'A').slice(0, 2).toUpperCase();
  document.getElementById('logoutBtn').addEventListener('click', AdminAuth.logout);

  function showError(message) {
    globalError.textContent = message;
    globalError.hidden = false;
  }
  function clearError() {
    globalError.hidden = true;
  }

  async function safeCall(fn, errorPrefix) {
    try {
      clearError();
      return await fn();
    } catch (err) {
      showError((errorPrefix ? errorPrefix + ': ' : '') + err.message);
      return null;
    }
  }

  /* ============================================================
     Tab navigation
     ============================================================ */
  const PANEL_META = {
    overview: { title: 'Overview', sub: 'A snapshot of everything SentryNet has seen.' },
    users: { title: 'Manage Users', sub: 'Administrator accounts with access to this panel.' },
    history: { title: 'Scan History', sub: 'Every URL analysed through the live API.' },
    domains: { title: 'Trusted Domains', sub: 'The brand registry used for impersonation detection.' },
    model: { title: 'Dataset & Model', sub: 'Upload training data and retrain the classifier.' },
    logs: { title: 'System Logs', sub: 'Authentication, security, and error events.' },
    reports: { title: 'Reports', sub: 'Export scan data for offline analysis.' },
  };

  const navButtons = document.querySelectorAll('.admin-nav-btn');
  const panels = document.querySelectorAll('.admin-panel');
  const topbarTitle = document.getElementById('topbarTitle');
  const topbarSub = document.getElementById('topbarSub');
  const sidebar = document.getElementById('adminSidebar');

  const LOADERS = {
    overview: loadOverview,
    users: loadUsers,
    history: loadHistory,
    domains: loadDomains,
    model: loadDatasets,
    logs: loadLogs,
  };

  function switchPanel(name) {
    navButtons.forEach((b) => b.classList.toggle('active', b.dataset.panel === name));
    panels.forEach((p) => p.classList.toggle('active', p.id === 'panel-' + name));
    const meta = PANEL_META[name];
    if (meta) {
      topbarTitle.textContent = meta.title;
      topbarSub.textContent = meta.sub;
    }
    sidebar.classList.remove('open');
    if (LOADERS[name]) LOADERS[name]();
  }

  navButtons.forEach((btn) => btn.addEventListener('click', () => switchPanel(btn.dataset.panel)));

  const sidebarToggle = document.getElementById('sidebarToggle');
  if (sidebarToggle) sidebarToggle.addEventListener('click', () => sidebar.classList.toggle('open'));

  /* ============================================================
     Backend health check
     ============================================================ */
  async function checkBackend() {
    try {
      const res = await fetch('http://127.0.0.1:5000/api/health');
      const data = await res.json();
      backendStatus.className = 'admin-backend-status ok';
      backendStatus.innerHTML = '<span class="dot"></span> Backend online' + (data.modelLoaded ? '' : ' (model not trained)');
    } catch (e) {
      backendStatus.className = 'admin-backend-status down';
      backendStatus.innerHTML = '<span class="dot"></span> Backend unreachable';
    }
  }

  /* ============================================================
     Overview
     ============================================================ */
  async function loadOverview() {
    const data = await safeCall(() => AdminAuth.apiFetch('/dashboard'), 'Overview');
    if (!data) return;
    document.getElementById('ovTotal').textContent = data.totalScans;
    document.getElementById('ovSafe').textContent = data.byVerdict.safe || 0;
    document.getElementById('ovSuspicious').textContent = data.byVerdict.suspicious || 0;
    document.getElementById('ovPhishing').textContent = data.byVerdict.phishing || 0;
    document.getElementById('ovUsers').textContent = data.totalUsers;
    document.getElementById('ovDomains').textContent = data.totalTrustedDomains;
    document.getElementById('ovModel').textContent = data.modelLoaded ? 'Loaded' : 'Not trained';
    document.getElementById('ovApi').textContent = 'Online';
  }

  /* ============================================================
     Users
     ============================================================ */
  async function loadUsers() {
    const users = await safeCall(() => AdminAuth.apiFetch('/users'), 'Users');
    const tbody = document.getElementById('usersBody');
    if (!users) return;
    tbody.innerHTML = users.map((u) => (
      '<tr><td class="mono">' + escapeHtml(u.username) + '</td><td>' + escapeHtml(u.role) + '</td>' +
      '<td>' + escapeHtml(u.created_at) + '</td>' +
      '<td><button class="row-action" data-del-user="' + u.id + '" title="Delete"><svg viewBox="0 0 24 24" fill="none" width="16" height="16"><path d="M4 7h16M9 7V5a1 1 0 011-1h4a1 1 0 011 1v2m2 0v12a2 2 0 01-2 2H8a2 2 0 01-2-2V7h12z" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg></button></td></tr>'
    )).join('');
  }

  document.getElementById('userForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('newUsername').value.trim();
    const password = document.getElementById('newPassword').value;
    const result = await safeCall(() => AdminAuth.apiFetch('/users', {
      method: 'POST', body: JSON.stringify({ username, password }),
    }), 'Add user');
    if (result) {
      e.target.reset();
      loadUsers();
      loadOverview();
    }
  });

  document.getElementById('usersBody').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-del-user]');
    if (!btn) return;
    if (!confirm('Delete this admin user?')) return;
    await safeCall(() => AdminAuth.apiFetch('/users/' + btn.dataset.delUser, { method: 'DELETE' }), 'Delete user');
    loadUsers();
    loadOverview();
  });

  /* ============================================================
     Scan history
     ============================================================ */
  async function loadHistory() {
    const rows = await safeCall(() => AdminAuth.apiFetch('/history'), 'History');
    const tbody = document.getElementById('historyBody');
    const empty = document.getElementById('historyEmpty');
    if (!rows) return;
    empty.hidden = rows.length !== 0;
    tbody.innerHTML = rows.map((r) => {
      const chipClass = r.verdict === 'safe' ? 'chip-safe' : r.verdict === 'phishing' ? 'chip-danger' : 'chip-warn';
      return (
        '<tr><td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escapeHtml(r.url) + '">' + escapeHtml(r.url) + '</td>' +
        '<td><span class="chip ' + chipClass + '">' + escapeHtml(r.verdict.toUpperCase()) + '</span></td>' +
        '<td>' + escapeHtml(r.threat_level || '—') + '</td>' +
        '<td>' + r.risk_score + '%</td>' +
        '<td class="mono">' + escapeHtml(r.ip_address || '—') + '</td>' +
        '<td>' + escapeHtml(r.created_at) + '</td>' +
        '<td><button class="row-action" data-del-scan="' + r.id + '" title="Delete"><svg viewBox="0 0 24 24" fill="none" width="16" height="16"><path d="M4 7h16M9 7V5a1 1 0 011-1h4a1 1 0 011 1v2m2 0v12a2 2 0 01-2 2H8a2 2 0 01-2-2V7h12z" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg></button></td></tr>'
      );
    }).join('');
  }

  document.getElementById('historyBody').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-del-scan]');
    if (!btn) return;
    await safeCall(() => AdminAuth.apiFetch('/history/' + btn.dataset.delScan, { method: 'DELETE' }), 'Delete scan');
    loadHistory();
    loadOverview();
  });

  document.getElementById('clearHistoryBtn').addEventListener('click', async () => {
    if (!confirm('Delete ALL scan history? This cannot be undone.')) return;
    await safeCall(() => AdminAuth.apiFetch('/history', { method: 'DELETE' }), 'Clear history');
    loadHistory();
    loadOverview();
  });

  /* ============================================================
     Trusted domains
     ============================================================ */
  async function loadDomains() {
    const domains = await safeCall(() => AdminAuth.apiFetch('/trusted-domains'), 'Trusted domains');
    const tbody = document.getElementById('domainsBody');
    if (!domains) return;
    tbody.innerHTML = domains.map((d) => (
      '<tr><td>' + escapeHtml(d.brand) + '</td><td class="mono">' + escapeHtml(d.domain) + '</td>' +
      '<td class="mono">' + escapeHtml(d.official_url) + '</td><td>' + escapeHtml(d.aliases) + '</td>' +
      '<td><button class="row-action" data-del-domain="' + d.id + '" title="Delete"><svg viewBox="0 0 24 24" fill="none" width="16" height="16"><path d="M4 7h16M9 7V5a1 1 0 011-1h4a1 1 0 011 1v2m2 0v12a2 2 0 01-2 2H8a2 2 0 01-2-2V7h12z" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg></button></td></tr>'
    )).join('');
  }

  document.getElementById('domainForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const body = {
      brand: document.getElementById('dBrand').value.trim(),
      domain: document.getElementById('dDomain').value.trim(),
      officialUrl: document.getElementById('dOfficial').value.trim(),
      aliases: document.getElementById('dAliases').value.trim(),
    };
    const result = await safeCall(() => AdminAuth.apiFetch('/trusted-domains', { method: 'POST', body: JSON.stringify(body) }), 'Add domain');
    if (result) {
      e.target.reset();
      loadDomains();
      loadOverview();
    }
  });

  document.getElementById('domainsBody').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-del-domain]');
    if (!btn) return;
    await safeCall(() => AdminAuth.apiFetch('/trusted-domains/' + btn.dataset.delDomain, { method: 'DELETE' }), 'Delete domain');
    loadDomains();
    loadOverview();
  });

  /* ============================================================
     Dataset upload + retrain
     ============================================================ */
  const dropzone = document.getElementById('dropzone');
  const datasetFile = document.getElementById('datasetFile');
  const dropzoneLabel = document.getElementById('dropzoneLabel');
  const datasetSelect = document.getElementById('datasetSelect');

  dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
      datasetFile.files = e.dataTransfer.files;
      uploadDataset(e.dataTransfer.files[0]);
    }
  });
  datasetFile.addEventListener('change', () => {
    if (datasetFile.files.length) uploadDataset(datasetFile.files[0]);
  });

  async function uploadDataset(file) {
    dropzoneLabel.textContent = 'Uploading ' + file.name + '…';
    const formData = new FormData();
    formData.append('file', file);
    const result = await safeCall(() => AdminAuth.apiFetch('/dataset/upload', { method: 'POST', body: formData }), 'Upload');
    dropzoneLabel.textContent = result
      ? 'Uploaded ' + result.filename + ' (' + result.rows + ' rows). Click to upload another.'
      : 'Click to choose a .csv file, or drag one here';
    if (result) loadDatasets();
  }

  async function loadDatasets() {
    const files = await safeCall(() => AdminAuth.apiFetch('/dataset'), 'Datasets');
    if (!files) return;
    datasetSelect.innerHTML = '<option value="">Synthetic default dataset</option>' +
      files.map((f) => '<option value="' + escapeHtml(f) + '">' + escapeHtml(f) + '</option>').join('');
  }

  document.getElementById('retrainBtn').addEventListener('click', async () => {
    const btn = document.getElementById('retrainBtn');
    const statusEl = document.getElementById('retrainStatus');
    const metricsGrid = document.getElementById('metricsGrid');
    btn.disabled = true;
    const original = btn.innerHTML;
    btn.innerHTML = 'Training… this can take a moment';
    statusEl.innerHTML = '';
    metricsGrid.hidden = true;

    const dataset = datasetSelect.value || null;
    const result = await safeCall(() => AdminAuth.apiFetch('/retrain', {
      method: 'POST', body: JSON.stringify({ dataset }),
    }), 'Retrain');

    btn.disabled = false;
    btn.innerHTML = original;

    if (result) {
      const m = result.metadata.metrics;
      statusEl.innerHTML = '<div class="admin-alert success">Model retrained and reloaded — ' + result.metadata.n_samples + ' samples, ' + result.metadata.train_time_seconds + 's training time.</div>';
      document.getElementById('mAccuracy').textContent = Math.round(m.accuracy * 100) + '%';
      document.getElementById('mPrecision').textContent = Math.round(m.precision * 100) + '%';
      document.getElementById('mRecall').textContent = Math.round(m.recall * 100) + '%';
      document.getElementById('mF1').textContent = Math.round(m.f1_score * 100) + '%';
      metricsGrid.hidden = false;
      loadOverview();
    }
  });

  /* ============================================================
     Logs
     ============================================================ */
  async function loadLogs() {
    const logs = await safeCall(() => AdminAuth.apiFetch('/logs'), 'Logs');
    const list = document.getElementById('logsList');
    const empty = document.getElementById('logsEmpty');
    if (!logs) return;
    empty.hidden = logs.length !== 0;
    list.innerHTML = logs.map((l) => (
      '<div class="log-row"><span class="log-level ' + escapeHtml(l.level) + '">' + escapeHtml(l.level) + '</span>' +
      '<span class="log-msg">' + escapeHtml(l.message) + '</span>' +
      '<span class="log-time">' + escapeHtml(l.created_at) + '</span></div>'
    )).join('');
  }

  /* ============================================================
     Reports
     ============================================================ */
  document.getElementById('exportReportBtn').addEventListener('click', async () => {
    try {
      const blob = await AdminAuth.apiFetch('/reports/export');
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'sentrynet_report.csv';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      showError('Export failed: ' + err.message);
    }
  });

  /* ---- Init ---- */
  checkBackend();
  loadOverview();
})();
