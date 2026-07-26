# SentryNet — Machine Learning-Based Phishing Website Detection System

A final year project: a Random Forest classifier for phishing URL detection,
served over a Flask REST API, with a vanilla HTML/CSS/JS frontend and a
full Admin Panel.

## Project structure

```
phishing-detector/
├── frontend/               Static site — HTML, CSS, vanilla JS only
│   ├── index.html            Landing page
│   ├── scanner.html          URL scanner (Developer Mode, URL breakdown, risk reasons)
│   ├── dashboard.html        Analytics dashboard (charts, history table)
│   ├── assistant.html        Rule-based AI security assistant
│   ├── about.html / contact.html / 404.html
│   ├── admin-login.html      Admin authentication
│   ├── admin.html            Admin Panel (users, history, domains, retrain, logs, reports)
│   ├── css/                  One stylesheet per page + main.css design system
│   └── js/                   One script per page + shared modules (api.js, main.js, admin-auth.js)
│
└── backend/                 Flask API + ML pipeline
    ├── app.py                 Application entry point
    ├── config.py
    ├── requirements.txt
    ├── routes/
    │   ├── scan.py             POST /api/scan, GET /api/health
    │   └── admin.py            Admin Panel API (auth-protected)
    ├── ml/
    │   ├── feature_extraction.py  19-feature extractor (lexical + host-based)
    │   ├── generate_dataset.py    Synthetic training-data generator
    │   ├── train_model.py         Train/test split, RandomForestClassifier, persistence
    │   ├── predict.py              Loads model.pkl ONCE at import — never retrains on startup
    │   ├── report.py               Builds the rich UI report (breakdown, reasons, impersonation)
    │   ├── trusted_domains.py      Brand registry + Levenshtein similarity matching
    │   └── model.pkl                The trained model (already included — see below)
    ├── utils/
    │   ├── db.py                SQLite persistence (parameterized queries only)
    │   └── security.py          Validation, sanitization, rate limiting, token auth
    └── data/sentrynet.db        Created automatically on first run
```

## Running it

### Frontend only (demo mode)

Every page works standalone by opening `frontend/index.html` directly in a
browser — no backend required. `frontend/js/api.js` detects that the Flask
API isn't reachable and transparently falls back to an equivalent local
heuristic scorer, so the Scanner, Dashboard, and AI Assistant are all fully
functional without any setup. The **Admin Panel requires the real backend**
(it manages a real database and a real model), so `admin.html` will show a
"backend unreachable" state until the API is running.

### Full stack (real ML backend)

```bash
cd backend
pip install -r requirements.txt
python app.py
```

The API starts on `http://127.0.0.1:5000`. A trained `model.pkl` is already
included in this repo, so scanning works immediately — **you do not need to
train anything to try the project**. Then open `frontend/index.html` (or
serve the `frontend/` folder with any static file server) — `api.js` will
automatically start using the live backend instead of the local heuristic.

Default admin login: `admin` / `ChangeMe123!` — change this via the
`SENTRYNET_ADMIN_PASSWORD` environment variable before any real deployment.

### Retraining the model

The model is **never** retrained automatically — not on `python app.py`,
not on a schedule. It's retrained in exactly two ways:

1. From the command line: `python ml/train_model.py` (optionally `--csv path.csv`
   to train on your own labelled dataset instead of the bundled synthetic one)
2. From the Admin Panel's **Dataset & Model** tab — upload a CSV, click
   "Retrain now", and the running server hot-reloads the new `model.pkl`
   without restarting.

### About the bundled dataset

This sandbox has no network access to pull a real phishing corpus (e.g.
PhishTank + Tranco), so `ml/generate_dataset.py` synthesizes 5,000 URLs that
follow the same *structural* patterns real phishing/legitimate URLs do
(typosquatting, suspicious TLDs, raw IPs, credential-lure keywords, vs.
ordinary domains and paths). The trained model reaches very high accuracy on
this synthetic data, which is expected — real-world corpora are noisier and
would realistically land in the 92–97% range. Swap in a real labelled CSV via
`--csv` for production use.

## Security features implemented

- **SQL injection** — every database query uses parameterized `?`
  placeholders (`backend/utils/db.py`); no string-formatted SQL anywhere.
- **XSS** — the API only returns JSON; the frontend escapes every
  user-supplied value (scanned URLs, etc.) before inserting it into the DOM
  via `escapeHtml()` in `main.js`.
- **Input validation & URL sanitization** — `backend/utils/security.py`
  rejects malformed URLs, disallowed schemes, oversized input, and control
  characters before they ever reach feature extraction.
- **Rate limiting** — in-memory sliding-window limiter per IP per route
  (30/min on `/api/scan`, 5/min on `/api/admin/login`).
- **Suspicious activity logging** — rejected input, failed logins, and rate
  limit hits are written to the `logs` table, visible in the Admin Panel.
- **Auth** — admin routes require a signed, expiring Bearer token
  (`itsdangerous`); passwords are hashed with `werkzeug.security`.

## Notes on WHOIS/DNS/redirect features

`ml/feature_extraction.py` attempts real WHOIS, DNS, and redirect-chain
lookups at inference time and degrades gracefully to a deterministic
simulated value if the network call fails or times out (or if `python-whois`
/ `requests` aren't installed — they're optional, see `requirements.txt`).
During training these are always simulated for speed and full offline
reproducibility.
