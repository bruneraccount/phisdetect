# PhisDetect

A phishing detector that runs on your own computer. Paste a suspicious URL or
email, or scan a QR code, and PhisDetect tells you how likely it is to be a
phishing attack — and, importantly, **why**.

PhisDetect combines **three trained AI models** with a long list of
**rule-based checks** (look-alike domains, suspicious keywords, brand names
hiding in subdomains, new domains, blacklists, and more). Every scan ends with a
clear verdict and a list of readable reasons — it never just says "maybe".

---

## What it does

| Feature | What it does |
|---------|--------------|
| **URL scanner** | Paste any web address and get a phishing risk verdict with explanations. |
| **Email scanner** | Paste the text of a suspicious email; the links inside are scored and the wording, grammar, and urgency clues are analysed. |
| **QR scanner** | Point your camera at a QR code (or upload a picture of one) and the URL inside is decoded and scanned automatically. |
| **Dashboard** | A terminal-style overview of your scan history, threats found, reports submitted, and points earned. |
| **Minigames** | Three short training games — **Phish or Legit**, **Link Dismantler**, and **Threat Hunt** — that teach you to spot phishing tricks. |
| **Profile** | Your name, points, and threat reports, saved privately in your browser. |

---

## How it works

### Scanning a URL

1. **Pre-checks.** The URL is compared against a list of known phishing sites
   and a list of the top 1 million legitimate domains, and checked for link
   shorteners and data: URIs.
2. **Rule-based checks.** The scanner looks for the classic tricks: an IP
   address used instead of a domain name, suspicious keywords in the domain,
   homoglyph characters that impersonate a brand, a real brand name hiding in a
   subdomain, too many subdomains, unusual top-level domains, and so on.
3. **The main model.** 103 hand-built features of the URL are fed to a Random
   Forest model, which outputs a phishing probability.
4. **Enrichment.** Live lookups add more evidence: DNS blacklists, the domain's
   age (via WHOIS), and SPF / DMARC / DKIM sender records.
5. **Page scan.** If the URL points to a real page, it is fetched and checked
   for redirects and for links whose text hides where they really go.
6. **Verdict.** The probability is turned into a risk level and a confidence
   score, and the reasons are collected into a readable report.

### The verdicts

| Verdict | What it means | Model probability |
|---------|---------------|-------------------|
| **Safe** | Looks legitimate | below 35 % |
| **Suspicious** | Some warning signs — double-check it | 35–60 % |
| **Threat** | Strong signs of phishing — do **not** enter any details | 60–80 % |
| **Critical** | Almost certainly phishing — treat as dangerous | above 80 % |

Every verdict also comes with a **confidence percentage**, and the report lists
each contributing reason so you can decide for yourself.

### Scanning an email

1. Every link found in the email is scored with the full URL pipeline; the
   worst-scoring link drives the email's overall risk.
2. A dedicated email-text model reads the wording of the subject and body.
3. A grammar check (via the LanguageTool service) and heuristic flags for
   urgency, password / personal-info requests, and similar tells add more
   evidence.

---

## The AI models

Three scikit-learn models power the scanner. They are trained locally from the
data included in the repository (see the model documentation for the full
retraining guide).

| Model | Reads | Type | Approx. size |
|-------|-------|------|--------------|
| Main phishing model | 103 hand-crafted URL features | Random Forest + calibration | ~385 MB |
| URL text model | The raw URL string as text | TF-IDF + Logistic Regression | ~6 MB |
| Email text model | The email's subject + body | TF-IDF + Logistic Regression | ~4.5 MB |

---

## Points, reports, and the leaderboard

- Your **profile** (name, points, reports, rank) is saved in the browser — no
  account or server login needed.
- **Report a threat:** when a scan flags a threat, click **Report threat** to
  earn **+10 points** and add one to your reports counter.
- **Minigames:** each game has a round of 10 questions. Every correct answer is
  worth **10 points × difficulty multiplier**:

  | Difficulty | Multiplier | Points per correct answer |
  |------------|------------|---------------------------|
  | Easy | ×1 | 10 |
  | Normal | ×2 | 20 |
  | Hard | ×3 | 30 |

  Points earned in minigames go into the same profile pool as threat reports.
- **Leaderboard:** the top 5 scores for each game and difficulty are saved by
  the backend to `backend/data/minigame_scores.json` and shown on the minigames
  page.

---

## Getting started

You need **Python 3.14** and an internet connection for the one-time setup.
A complete, beginner-friendly walkthrough lives in
[`intel/installguide.md`](intel/installguide.md) — it covers downloading the
files, installing packages, building the models, and running everything.

The short version:

```bash
python -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
python -m pip install -r model/requirements.txt

python model/src/train.py
python model/src/train_url_text_model.py
python model/src/train_email_text_model.py

python backend/server.py            # terminal 1 — the scanner API on port 3000
cd frontend && python -m http.server 8000   # terminal 2 — the web app
# then open http://localhost:8000 in your browser
```

The trained models are too large for GitHub (the main one is ~385 MB), so they
are rebuilt on your machine from the included training data — that is the slow
part, and it only happens once.

---

## Project structure

```
backend/      The Python (Flask) server — all scanning logic and the API
frontend/     The web app — plain HTML/CSS/JS, no build step
model/        The AI models, training scripts, and data
intel/        Project documentation (see below)
```

`backend/server.py` is the heart of the app: it loads the models, runs every
scan, and serves the API that the frontend calls at `http://localhost:3000`.

---

## Documentation (the `intel/` folder)

The `intel/` folder is the project's knowledge base. Each file explains one
slice of the project in plain language:

| File | What it explains |
|------|------------------|
| [`intel/installguide.md`](intel/installguide.md) | How to install and run PhisDetect on your own computer, step by step. |
| [`intel/structure.md`](intel/structure.md) | A map of every folder and file in the project and what it does. |
| [`intel/backendlogic.md`](intel/backendlogic.md) | How the backend works: every scan step, rule, and API endpoint. |
| [`intel/model.md`](intel/model.md) | The three AI models: what they learn, how they were trained, and how to retrain. |
| [`intel/requirements.md`](intel/requirements.md) | Every dependency the project needs and why it is there. |

---

## Tech stack

- **Backend:** Python, Flask, scikit-learn, pandas, dnspython, python-whois
- **Frontend:** static HTML/CSS/JS (no npm), with jsQR for QR decoding
- **Live services used at scan time:** DNS, DNS blacklists, WHOIS, and the
  LanguageTool grammar API — all of them degrade gracefully when offline

---

## A note on responsible use

PhisDetect is a security-education and analysis tool. Scan only addresses and
emails you are allowed to inspect, and treat its verdicts as guidance — when in
doubt, a cautious human is still the best defence.
