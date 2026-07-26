/**
 * admin-auth.js — shared session-token handling for the Admin Panel.
 * Loaded before admin-login.js / admin.js on their respective pages.
 */

const AdminAuth = (function () {
  'use strict';

  const API_BASE = (function () {
    if (typeof window !== 'undefined' && window.SENTRYNET_API_URL) {
      return window.SENTRYNET_API_URL.replace(/\/$/, '') + '/admin';
    }
    if (typeof window !== 'undefined' && window.location && window.location.protocol.startsWith('http')) {
      return window.location.origin + '/api/admin';
    }
    return 'http://127.0.0.1:5000/api/admin';
  })();
  const TOKEN_KEY = 'sentrynet_admin_token';
  const USER_KEY = 'sentrynet_admin_user';


  function saveSession(token, username) {
    sessionStorage.setItem(TOKEN_KEY, token);
    sessionStorage.setItem(USER_KEY, username);
  }

  function getToken() {
    return sessionStorage.getItem(TOKEN_KEY);
  }

  function getUsername() {
    return sessionStorage.getItem(USER_KEY);
  }

  function clearSession() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
  }

  function isLoggedIn() {
    return !!getToken();
  }

  async function login(username, password) {
    const res = await fetch(API_BASE + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || 'Login failed.');
    saveSession(data.token, data.username);
    return data;
  }

  function logout() {
    clearSession();
    window.location.href = 'admin-login.html';
  }

  /** Authenticated fetch — redirects to login on 401, throws on other errors. */
  async function apiFetch(path, options) {
    options = options || {};
    const headers = Object.assign({}, options.headers, { Authorization: 'Bearer ' + getToken() });
    if (options.body && !(options.body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
    }
    let res;
    try {
      res = await fetch(API_BASE + path, Object.assign({}, options, { headers }));
    } catch (networkErr) {
      throw new Error('Could not reach the backend API. Please check your backend connection.');
    }
    if (res.status === 401) {
      clearSession();
      window.location.href = 'admin-login.html';
      throw new Error('Session expired.');
    }
    const contentType = res.headers.get('Content-Type') || '';
    const data = contentType.includes('application/json') ? await res.json().catch(() => ({})) : await res.blob();
    if (!res.ok) throw new Error((data && data.error) || 'Request failed.');
    return data;
  }

  return { login, logout, apiFetch, isLoggedIn, getUsername, API_BASE };
})();
