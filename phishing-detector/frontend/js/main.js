/**
 * main.js — shared behaviors across all pages
 * Nav scroll state, mobile menu toggle, scroll-reveal animations.
 */

(function () {
  'use strict';

  /* ---- Global HTML escaping — every spot that renders a user-supplied
     URL via innerHTML (history tables, threat widgets, chat) must run
     it through this first to prevent stored XSS from a URL containing
     markup, e.g. "http://evil.com/<script>...". ---- */
  window.escapeHtml = function (str) {
    const div = document.createElement('div');
    div.textContent = str == null ? '' : String(str);
    return div.innerHTML;
  };

  /* ---- Animated counters (used by hero stats, dashboard cards, etc) ---- */
  window.animateCounter = function (el, target, opts) {
    opts = opts || {};
    const duration = opts.duration || 1200;
    const decimals = opts.decimals || 0;
    const suffix = opts.suffix || '';
    const prefix = opts.prefix || '';
    const start = performance.now();
    const from = 0;

    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out-cubic
      const value = from + (target - from) * eased;
      el.textContent = prefix + value.toFixed(decimals) + suffix;
      if (progress < 1) requestAnimationFrame(tick);
      else el.textContent = prefix + target.toFixed(decimals) + suffix;
    }
    requestAnimationFrame(tick);
  };

  // Auto-run on any element flagged with data-counter="target" when it
  // scrolls into view, so pages can opt in with markup alone.
  const counterEls = document.querySelectorAll('[data-counter]');
  if (counterEls.length && 'IntersectionObserver' in window) {
    const counterIo = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        const el = entry.target;
        const target = parseFloat(el.dataset.counter);
        window.animateCounter(el, target, {
          decimals: el.dataset.decimals ? parseInt(el.dataset.decimals, 10) : 0,
          suffix: el.dataset.suffix || '',
          prefix: el.dataset.prefix || '',
        });
        counterIo.unobserve(el);
      });
    }, { threshold: 0.5 });
    counterEls.forEach((el) => counterIo.observe(el));
  }

  /* ---- Toast notifications (global API: window.SentryToast.show) ---- */
  function ensureToastContainer() {
    let el = document.querySelector('.toast-container');
    if (!el) {
      el = document.createElement('div');
      el.className = 'toast-container';
      document.body.appendChild(el);
    }
    return el;
  }

  const TOAST_ICONS = {
    danger: '<path d="M12 9v4m0 4h.01M10.3 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L14.7 3.86a2 2 0 00-3.4 0z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
    warn: '<path d="M12 9v4m0 4h.01M10.3 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L14.7 3.86a2 2 0 00-3.4 0z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
    safe: '<path d="M5 13l4 4L19 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  };

  window.SentryToast = {
    show(title, message, type) {
      type = type in TOAST_ICONS ? type : 'safe';
      const container = ensureToastContainer();
      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.innerHTML =
        '<span class="toast-icon"><svg viewBox="0 0 24 24" fill="none">' + TOAST_ICONS[type] + '</svg></span>' +
        '<div class="toast-body"><div class="toast-title">' + title + '</div><div class="toast-msg">' + message + '</div></div>' +
        '<button class="toast-close" aria-label="Dismiss"><svg viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg></button>';

      const remove = () => {
        toast.classList.add('toast-leaving');
        setTimeout(() => toast.remove(), 300);
      };
      toast.querySelector('.toast-close').addEventListener('click', remove);
      container.appendChild(toast);
      setTimeout(remove, 6000);
    },
  };

  /* ---- Page loader dismissal ---- */
  const pageLoader = document.getElementById('pageLoader');
  if (pageLoader) {
    const dismiss = () => {
      pageLoader.classList.add('loader-hidden');
      setTimeout(() => pageLoader.remove(), 600);
    };
    // Small minimum-visible delay so the loader doesn't just flicker on
    // fast local loads, but never blocks longer than the page actually needs.
    const minDelay = new Promise((resolve) => setTimeout(resolve, 320));
    const ready = new Promise((resolve) => {
      if (document.readyState === 'complete') resolve();
      else window.addEventListener('load', resolve, { once: true });
    });
    Promise.all([minDelay, ready]).then(dismiss);
  }

  /* ---- Theme toggle (dark/light) ---- */
  const THEME_KEY = 'sentrynet_theme';
  const themeToggle = document.getElementById('themeToggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      const next = isLight ? 'dark' : 'light';
      if (next === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
      } else {
        document.documentElement.removeAttribute('data-theme');
      }
      try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* storage unavailable */ }
    });
  }

  /* ---- Navbar scroll state ---- */
  const navbar = document.querySelector('.navbar');
  const onScroll = () => {
    if (!navbar) return;
    navbar.classList.toggle('scrolled', window.scrollY > 12);
  };
  document.addEventListener('scroll', onScroll, { passive: true });
  onScroll();

  /* ---- Mobile nav toggle ---- */
  const toggle = document.querySelector('.nav-toggle');
  const links = document.querySelector('.nav-links');
  if (toggle && links) {
    toggle.addEventListener('click', () => {
      toggle.classList.toggle('open');
      links.classList.toggle('open');
    });
    links.querySelectorAll('a').forEach((a) =>
      a.addEventListener('click', () => {
        toggle.classList.remove('open');
        links.classList.remove('open');
      })
    );
  }

  /* ---- Scroll-reveal ---- */
  const revealEls = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window && revealEls.length) {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('in-view');
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15, rootMargin: '0px 0px -40px 0px' }
    );
    revealEls.forEach((el) => io.observe(el));
  } else {
    revealEls.forEach((el) => el.classList.add('in-view'));
  }
})();
