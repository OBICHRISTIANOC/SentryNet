/**
 * admin-login.js — Admin login page controller.
 */

(function () {
  'use strict';

  if (AdminAuth.isLoggedIn()) {
    window.location.href = 'admin.html';
    return;
  }

  const form = document.getElementById('loginForm');
  const usernameInput = document.getElementById('loginUsername');
  const passwordInput = document.getElementById('loginPassword');
  const errorEl = document.getElementById('loginError');
  const loginBtn = document.getElementById('loginBtn');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorEl.hidden = true;

    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    if (!username || !password) {
      errorEl.textContent = 'Enter both a username and password.';
      errorEl.hidden = false;
      return;
    }

    loginBtn.disabled = true;
    const original = loginBtn.innerHTML;
    loginBtn.innerHTML = 'Signing in…';

    try {
      await AdminAuth.login(username, password);
      window.location.href = 'admin.html';
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.hidden = false;
      loginBtn.disabled = false;
      loginBtn.innerHTML = original;
    }
  });
})();
