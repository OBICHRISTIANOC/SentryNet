/**
 * assistant.js — SentryNet AI Assistant.
 * A rule-based knowledge base (no external LLM call) that answers
 * common phishing/ML questions, and can reference the most recent
 * scan stored by the URL Scanner page for a contextual answer.
 */

(function () {
  'use strict';

  const HISTORY_KEY = 'sentrynet_scan_history';

  const chatBody = document.getElementById('chatBody');
  const chatForm = document.getElementById('chatForm');
  const chatInput = document.getElementById('chatInput');
  const resetChatBtn = document.getElementById('resetChatBtn');
  const suggestions = document.getElementById('chatSuggestions');

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function lastScan() {
    try {
      const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
      return history[0] || null;
    } catch (e) {
      return null;
    }
  }

  /* ============================================================
     Knowledge base — ordered; first matching pattern wins.
     ============================================================ */
  const KNOWLEDGE_BASE = [
    {
      patterns: [/what is phishing/i, /^phishing\??$/i, /define phishing/i],
      answer:
        '<p><strong>Phishing</strong> is a social-engineering attack where someone impersonates a trusted entity — a bank, a colleague, a well-known brand — to trick a person into handing over credentials, payment details, or other sensitive information.</p>' +
        '<p>It usually arrives as an email, text, or link that leads to a fake website built to look identical to the real one. The giveaway is almost never the design — it\u2019s the URL, the certificate, and small structural details, which is exactly what this scanner is built to catch.</p>',
    },
    {
      patterns: [/why is this url dangerous/i, /why.*dangerous/i, /why.*risky/i, /why.*flagged/i],
      answer: () => {
        const scan = lastScan();
        if (!scan) {
          return '<p>I don\u2019t have a recent scan to reference yet. Run a URL through the <strong>Scanner</strong> first, then ask me again and I\u2019ll explain exactly why it was flagged.</p>';
        }
        const verdictLabel = scan.verdict === 'safe' ? 'safe' : scan.verdict === 'suspicious' ? 'suspicious' : 'a likely phishing site';
        return (
          '<p>Your most recent scan was <strong>' + escapeHtml(scan.url) + '</strong>, classified as <strong>' + verdictLabel + '</strong> ' +
          'with a risk score of <strong>' + scan.riskScore + '%</strong> and threat level <strong>' + (scan.threatLevel || 'n/a') + '</strong>.</p>' +
          '<p>Open the scanner and expand <strong>Developer Mode</strong> or the <strong>Why this website is risky</strong> panel on that result — it lists the exact signals (HTTPS status, entropy, brand similarity, and more) that drove this specific verdict, rather than just the label.</p>'
        );
      },
    },
    {
      patterns: [/random forest/i, /how does.*model work/i, /how.*classifier work/i],
      answer:
        '<p>A <strong>Random Forest</strong> is an ensemble of many decision trees, each trained on a random subset of the data and features. Individually, a single tree can overfit or make brittle calls — but a forest of a few hundred trees, each voting independently, tends to average out those mistakes.</p>' +
        '<p>For a given URL, every tree looks at its feature vector (URL length, entropy, HTTPS status, brand similarity, and so on) and votes <em>phishing</em> or <em>legitimate</em>. The final prediction probability is simply the fraction of trees that voted phishing — which is exactly the <strong>Risk Score</strong> you see after a scan.</p>',
    },
    {
      patterns: [/what is https/i, /^https\??$/i, /difference.*http.*https/i],
      answer:
        '<p><strong>HTTPS</strong> is HTTP wrapped in TLS encryption. It does two things: it encrypts traffic between your browser and the server, and it requires the site to present a certificate proving it controls the domain it claims to be.</p>' +
        '<p>HTTPS on its own doesn\u2019t mean a site is trustworthy — attackers can and do get valid certificates for phishing domains — but its <em>absence</em> on a page asking for a password is a strong red flag, which is why it\u2019s one of the highest-weighted signals in the model.</p>',
    },
    {
      patterns: [/how do attackers create fake websites/i, /how.*fake website/i, /how.*clone.*website/i, /how.*build.*phishing site/i],
      answer:
        '<p>Most phishing sites are built the same way:</p>' +
        '<ul>' +
        '<li>The real site\u2019s HTML/CSS is copied or scraped almost pixel-for-pixel</li>' +
        '<li>A lookalike domain is registered — a hyphen, a swapped letter, or an unusual TLD</li>' +
        '<li>A form is wired up to capture whatever is typed and send it to the attacker</li>' +
        '<li>The link is distributed through email, SMS, or social media, often with urgency ("verify your account now")</li>' +
        '</ul>' +
        '<p>Because the visual copy is near-perfect, detection has to focus on things that are hard to fake at scale: the domain string itself, certificate details, and how recently the domain was registered.</p>',
    },
    {
      patterns: [/entropy score/i, /explain entropy/i, /what is entropy/i],
      answer:
        '<p><strong>Entropy</strong> measures how random a string looks. It\u2019s calculated with Shannon\u2019s formula, which looks at how evenly characters are distributed across the string.</p>' +
        '<p>Real brand names ("paypal", "facebook") are short, structured, and have low entropy. Auto-generated or randomly padded phishing domains ("xk29-secure-paypaI") mix cases, digits, and hyphens more chaotically, which pushes entropy higher. A high entropy score doesn\u2019t prove a domain is malicious on its own, but combined with other signals it\u2019s a useful tell.</p>',
    },
    {
      patterns: [/feature importance/i, /explain feature/i, /which features matter/i],
      answer:
        '<p><strong>Feature importance</strong> tells you which inputs actually moved the model\u2019s decision for a given prediction, rather than just showing you a black-box score.</p>' +
        '<p>In a Random Forest, this is typically estimated by how much each feature reduces impurity across all the splits it\u2019s used in, averaged across every tree. In the scanner\u2019s results, the top contributing features are surfaced directly in the <strong>Developer Mode</strong> panel so you can see exactly what pushed a URL toward "phishing" instead of just trusting the label.</p>',
    },
    {
      patterns: [/^hi$|^hello$|^hey$/i],
      answer: '<p>Hey — I\u2019m the SentryNet assistant. Ask me about phishing, how the detection model works, or why your last scan came back the way it did.</p>',
    },
    {
      patterns: [/thank/i],
      answer: '<p>Anytime. Stay safe out there — and when in doubt, run the link through the scanner first.</p>',
    },
  ];

  const FALLBACK_ANSWER =
    '<p>I\u2019m built to answer questions about phishing, this detection engine, and your recent scans specifically — try one of the suggestions below, or ask things like <em>"What is phishing?"</em> or <em>"How does Random Forest work?"</em></p>';

  function findAnswer(question) {
    const entry = KNOWLEDGE_BASE.find((k) => k.patterns.some((p) => p.test(question)));
    if (!entry) return FALLBACK_ANSWER;
    return typeof entry.answer === 'function' ? entry.answer() : entry.answer;
  }

  /* ============================================================
     Rendering
     ============================================================ */
  function scrollToBottom() {
    chatBody.scrollTop = chatBody.scrollHeight;
  }

  function addUserMessage(text) {
    const el = document.createElement('div');
    el.className = 'msg msg-user';
    el.innerHTML =
      '<span class="msg-avatar">You</span>' +
      '<div class="msg-bubble">' + escapeHtml(text) + '</div>';
    chatBody.appendChild(el);
    scrollToBottom();
  }

  function addBotMessageHtml(html) {
    const el = document.createElement('div');
    el.className = 'msg msg-bot';
    el.innerHTML =
      '<span class="msg-avatar"><svg viewBox="0 0 24 24" fill="none" style="width:16px;height:16px"><path d="M12 2L4 5v6c0 5.2 3.4 9.9 8 11 4.6-1.1 8-5.8 8-11V5l-8-3z" fill="currentColor"/></svg></span>' +
      '<div class="msg-bubble">' + html + '</div>';
    chatBody.appendChild(el);
    scrollToBottom();
  }

  function addTypingIndicator() {
    const el = document.createElement('div');
    el.className = 'msg msg-bot';
    el.id = 'typingIndicator';
    el.innerHTML =
      '<span class="msg-avatar"><svg viewBox="0 0 24 24" fill="none" style="width:16px;height:16px"><path d="M12 2L4 5v6c0 5.2 3.4 9.9 8 11 4.6-1.1 8-5.8 8-11V5l-8-3z" fill="currentColor"/></svg></span>' +
      '<div class="msg-bubble"><span class="typing-dots"><span></span><span></span><span></span></span></div>';
    chatBody.appendChild(el);
    scrollToBottom();
  }

  function removeTypingIndicator() {
    const el = document.getElementById('typingIndicator');
    if (el) el.remove();
  }

  function handleQuestion(question) {
    if (!question.trim()) return;
    addUserMessage(question);
    chatInput.value = '';
    addTypingIndicator();

    const delay = 500 + Math.random() * 500;
    setTimeout(() => {
      removeTypingIndicator();
      addBotMessageHtml(findAnswer(question));
    }, delay);
  }

  chatForm.addEventListener('submit', (e) => {
    e.preventDefault();
    handleQuestion(chatInput.value);
  });

  suggestions.querySelectorAll('.scan-chip-btn').forEach((btn) => {
    btn.addEventListener('click', () => handleQuestion(btn.dataset.q));
  });

  resetChatBtn.addEventListener('click', () => {
    chatBody.innerHTML = '';
    addBotMessageHtml(
      '<p>Hi, I\u2019m the SentryNet assistant. Ask me anything about phishing, how this detection engine works, or your most recent scan.</p>'
    );
  });

  /* ---- Init ---- */
  addBotMessageHtml(
    '<p>Hi, I\u2019m the SentryNet assistant. Ask me anything about phishing, how this detection engine works, or your most recent scan.</p>'
  );
})();
