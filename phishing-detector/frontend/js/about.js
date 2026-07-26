/**
 * about.js — lightweight scrollspy for the About page's table of contents.
 */

(function () {
  'use strict';

  const sections = document.querySelectorAll('.about-section[id]');
  const tocLinks = document.querySelectorAll('#tocNav a');
  if (!sections.length || !tocLinks.length) return;

  const linkFor = (id) => document.querySelector('#tocNav a[href="#' + id + '"]');

  const io = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        tocLinks.forEach((a) => a.classList.remove('active'));
        const link = linkFor(entry.target.id);
        if (link) link.classList.add('active');
      });
    },
    { rootMargin: '-20% 0px -70% 0px', threshold: 0 }
  );

  sections.forEach((s) => io.observe(s));
})();
