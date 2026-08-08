# Requirements

**PhisDetect — environment & dependency requirements**

This document lists everything required to build, run, train and extend
PhisDetect: the Python runtime, the pinned Python packages, the frontend
dependencies, the generated model artifacts, and the external network services
the scanner talks to at runtime. It is the companion to
[`structure.md`](structure.md) (what files exist) and
[`backendlogic.md`](backendlogic.md) (how the backend uses them).

> **Note on the file location:** the project's *only* functional dependency
> manifest is `model/requirements.txt` (a pip file, not a doc). This document
> explains *why* every entry is there and what else the project needs on top of
> it. Do not delete `model/requirements.txt` — `python -m pip install -r` depends on it.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Runtime environment](#2-runtime-environment)
3. [Python dependencies](#3-python-dependencies)
4. [Frontend dependencies](#4-frontend-dependencies)
5. [Data & model artifacts](#5-data--model-artifacts)
6. [External network services](#6-external-network-services)
7. [Setting up the environment](#7-setting-up-the-environment)
8. [Installed-but-unused packages](#8-installed-but-unused-packages)

---

## 1. Overview

PhisDetect has **three components**, and each has different requirements:

| Component | Tech | Has its own dependency file? |
|-----------|------|------------------------------|
| `backend/server.py` | Python (Flask) | No — uses `model/requirements.txt` |
| `model/src/*` (training + feature extraction) | Python | Yes — `model/requirements.txt` |
| `frontend/*` | Static HTML/CSS/JS | No — **no npm, no build step**; a few CDN libs |

Because `server.py` imports the feature extractors straight out of `model/src`
(`extract_features`, `email_text_features`, `url_text_features`), the **backend
and the model share one Python dependency set**. `model/requirements.txt` is
therefore the manifest for the whole Python side of the project.

---

## 2. Runtime environment

| Requirement | Value | Notes |
|-------------|-------|-------|
| OS | Linux (developed/tested), any OS with Python | No OS-specific code; DNS/WHOIS calls are cross-platform |
| Python | **3.14.x** (developed/tested on 3.14.6) | The pinned packages were chosen to support 3.14 |
| Disk | ~400 MB free | The three trained `.joblib` files total ≈ 396 MB (`385 + 6.2 + 4.5` on disk) |
| RAM | ~1–2 GB | Loading the 385 MB Random Forest + `pandas`/`scikit-learn` at startup |
| Network | Outbound DNS + HTTPS + WHOIS | See [§6](#6-external-network-services) |
| Ports | 3000 (backend, loopback only) | `app.run(host="127.0.0.1", port=3000)` |

The server binds to **127.0.0.1 only** — it is reachable from the machine it
runs on and must not be exposed directly to the internet without a
reverse proxy (there is no authentication layer).

---

## 3. Python dependencies

### 3.1 The pinned manifest

`model/requirements.txt` — all nine entries are **pinned with `==`** so installs
are reproducible:

| Package | Version | Why it is needed | Used by |
|---------|---------|------------------|---------|
| `Flask` | 3.1.3 | Web framework — serves the 5 JSON API endpoints | backend |
| `flask-cors` | 6.0.5 | CORS headers so the static frontend can call the API cross-origin | backend |
| `joblib` | 1.5.3 | Save/load the `.joblib` model artifacts | backend + training |
| `pandas` | 3.0.5 | Builds the feature DataFrame row in `predict_url`; the training tables | backend + training |
| `scikit-learn` | 1.9.0 | The ML estimators — **needed at runtime to unpickle the models**, and to train them | backend + training |
| `dnspython` | 2.8.0 | DNS lookups: URL feature extraction, DNSBL checks, SPF/DMARC/DKIM probes | backend + training |
| `requests` | 2.34.2 | HTTP: page fetch, redirect check, LanguageTool API | backend |
| `python-whois` | 0.9.6 | WHOIS lookup for domain-age enrichment | backend |
| `pyspellchecker` | 0.9.0 | English spell-checking in the email grammar analysis | backend |

> `scikit-learn` is easy to forget because `server.py` never imports it directly —
> but the loaded `phishing_model.joblib` **is** a `CalibratedClassifierCV`
> (RandomForest) object, and unpickling it requires the `sklearn` module
> present. Without it the app crashes at startup.

### 3.2 Direct vs transitive

The nine entries pull in their own dependencies automatically. The important
transitive ones (already in the venv, not pinned in `requirements.txt`):

| Transitive package | Comes with | Used by |
|--------------------|-----------|---------|
| `numpy` | pandas / scikit-learn | `train.py` imports it directly |
| `urllib3` | requests | `server.py` imports it (and disables its warnings) |
| `scipy`, `threadpoolctl` | scikit-learn | estimator internals |
| `Werkzeug`, `Jinja2`, `click`, `itsdangerous`, `blinker`, `MarkupSafe` | Flask | web framework internals |
| `python-dateutil`, `pytz`, `narwhals` | pandas 3.x | DataFrame internals |

### 3.3 Runtime vs training split

Not every package is needed for every job:

| Job | Packages required |
|-----|-------------------|
| **Run the backend** (`python backend/server.py`) | all nine |
| **Train the models** (`train.py`, `train_url_text_model.py`, `train_email_text_model.py`) | `joblib`, `pandas`, `scikit-learn`, `numpy`, `dnspython` (feature extraction does live DNS) |
| **Refresh the lists** (`update_lists.py`) | stdlib only (`urllib.request`) — no extra deps |
| **Rebuild the email dataset** (`update_email_data.py`) | stdlib only (`mailbox`, `gzip`, `tarfile`) |

Installing the full `requirements.txt` satisfies every job, so the split above
only matters for minimal offline deployments.

---

## 4. Frontend dependencies

The frontend is **pure static HTML/CSS/JS** — there is **no `package.json`, no
Node.js, no bundler, and nothing to `npm install`**. It is served as-is (any
static file server works; `python -m http.server` in `frontend/` is enough).

The only third-party code is loaded from CDNs at page load, so the browser
needs internet access to those hosts:

| Library | Purpose | Source |
|---------|---------|--------|
| **jsQR 1.4.0** | Decodes QR codes in the camera-based URL scanner (`scanner.js` calls `jsQR(...)`) | `cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js` |
| **Font Awesome 6.5.1** | Icons across all pages | `cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css` |
| **Google Fonts** | Inter + JetBrains Mono typefaces | `fonts.googleapis.com` / `fonts.gstatic.com` |

All local behaviour (theme, profile, minigames, dashboard) is hand-written JS
under `frontend/js/` with zero external dependencies.

---

## 5. Data & model artifacts

The backend needs these files present at startup. They live under `model/` and
are **not** committed to git (see `.gitignore`) — a fresh clone must retrain or
re-download them.

| File | Size | Required? | Behaviour if missing |
|------|------|-----------|----------------------|
| `model/trained/phishing_model.joblib` | ~385 MB | **Yes** | **App crashes at startup** |
| `model/trained/features.txt` | 1.8 KB | **Yes** | **App crashes at startup** |
| `model/trained/url_text_model.joblib` | ~6.2 MB | No | URL-text scoring silently disabled (`None`) |
| `model/trained/email_text_model.joblib` | ~4.5 MB | No | Email-text scoring silently disabled (`None`) |
| `model/lists/tranco_top1m.txt` | ~1 M lines | No | Allowlist = empty set → trusted-domain gate disabled (more false positives) |
| `model/lists/openphish_hosts.txt` | 267 lines | No | Blocklist = empty set → blocklist signal disabled |

The two "optional" model files and the two lists degrade gracefully; the main
model + feature list do not. Regenerate them with the training scripts (see
[`model.md`](model.md) for the full retraining guide).

---

## 6. External network services

Even with all packages installed, the scanner makes **live network calls** at
scan time. These are required for full functionality (all degrade to neutral
defaults when unreachable):

| Service | Protocol | Used for | Used when |
|---------|----------|----------|-----------|
| Default system DNS resolvers | DNS (UDP/TCP 53) | URL feature extraction (via `extract_features.extract`), DNSBL + SPF/DMARC/DKIM probes | every URL/email scan |
| `multi.surbl.org`, `dbl.spamhaus.org` | DNS | DNSBL blacklist check | every URL scan |
| WHOIS servers | WHOIS (TCP 43) | domain-age enrichment | every URL scan |
| `api.languagetool.org/v2/check` | HTTPS | grammar / style analysis | every email scan |
| The scanned target itself | HTTP/HTTPS | page fetch + redirect check | every URL scan (page scan) |
| Frontend CDNs (see §4) | HTTPS | UI assets | page load |

Offline behaviour: DNS-dependent signals (model features, RBL, SPF/DMARC/DKIM)
fall back to their neutral defaults, so the scanner keeps working but becomes
effectively heuristic-only.

---

## 7. Setting up the environment

From a fresh clone (the heavy `.joblib` files and `venv/` are git-ignored):

```bash
# 1. Create and populate the Python environment (single root-level venv/)
python3.14 -m venv venv
venv/bin/python -m pip install -r model/requirements.txt

# 2. (Fresh clone only) generate the model artifacts
venv/bin/python model/src/train.py                  # phishing_model.joblib + features.txt
venv/bin/python model/src/train_url_text_model.py   # url_text_model.joblib
venv/bin/python model/src/train_email_text_model.py # email_text_model.joblib
# Optionally refresh the lists:
venv/bin/python model/src/update_lists.py

# 3. Start the API
venv/bin/python backend/server.py        # listens on 127.0.0.1:3000

# 4. Serve the frontend (any static server works; CORS is already enabled)
python3 -m http.server -d frontend 8000        # open http://localhost:8000
```

---

## 8. Installed-but-unused packages

The venv currently contains three packages that are **not** in
`requirements.txt` and **not referenced anywhere in the source**
(`backend/server.py`, `model/src/*`):

| Package | Version |
|---------|---------|
| `qrcode` | 8.2 |
| `pillow` | 12.3.0 |
| `selenium` | 4.46.0 (+ its deps: `trio`, `websocket-client`, `h11`, `outcome`, `sniffio`, `sortedcontainers`, `attrs`, `PySocks`, ...) |

These are development leftovers (likely from earlier QR/dataset experiments).
They are harmless but can be uninstalled to keep the environment clean; the
project does not use them.
