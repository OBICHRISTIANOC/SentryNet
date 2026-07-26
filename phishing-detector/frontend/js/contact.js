/**
 * contact.js — Contact form validation + simulated submit.
 * No backend endpoint exists yet, so this validates client-side and
 * shows a success state rather than actually sending mail.
 */

(function () {
  'use strict';

  const form = document.getElementById('contactForm');
  const nameInput = document.getElementById('cName');
  const emailInput = document.getElementById('cEmail');
  const messageInput = document.getElementById('cMessage');
  const errName = document.getElementById('errName');
  const errEmail = document.getElementById('errEmail');
  const errMessage = document.getElementById('errMessage');
  const submitBtn = document.getElementById('contactSubmitBtn');
  const formSuccess = document.getElementById('formSuccess');

  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  function setError(input, errorEl, message) {
    if (message) {
      input.classList.add('invalid');
      errorEl.textContent = message;
    } else {
      input.classList.remove('invalid');
      errorEl.textContent = '';
    }
  }

  function validate() {
    let valid = true;

    if (!nameInput.value.trim()) {
      setError(nameInput, errName, 'Enter your name.');
      valid = false;
    } else {
      setError(nameInput, errName, '');
    }

    if (!emailInput.value.trim()) {
      setError(emailInput, errEmail, 'Enter your email.');
      valid = false;
    } else if (!EMAIL_RE.test(emailInput.value.trim())) {
      setError(emailInput, errEmail, 'Enter a valid email address.');
      valid = false;
    } else {
      setError(emailInput, errEmail, '');
    }

    if (!messageInput.value.trim()) {
      setError(messageInput, errMessage, 'Enter a message.');
      valid = false;
    } else if (messageInput.value.trim().length < 10) {
      setError(messageInput, errMessage, 'Message is a little short — add a few more details.');
      valid = false;
    } else {
      setError(messageInput, errMessage, '');
    }

    return valid;
  }

  [nameInput, emailInput, messageInput].forEach((el) => {
    el.addEventListener('input', () => {
      if (el.classList.contains('invalid')) validate();
    });
  });

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    formSuccess.hidden = true;
    if (!validate()) return;

    submitBtn.disabled = true;
    const originalHtml = submitBtn.innerHTML;
    submitBtn.innerHTML = 'Sending…';

    setTimeout(() => {
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalHtml;
      formSuccess.hidden = false;
      form.reset();
    }, 900);
  });
})();
