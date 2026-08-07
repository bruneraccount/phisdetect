# PhisDetect — Tier 2 Improvement Plan (NLP & Model Upgrades)

> **PURPOSE:** This doc survives session compaction. If you (the assistant) are continuing this
> project from a fresh/compacted context, read this file FIRST, then `model.md`, `logic.md`, and
> `server.py` before touching anything. It contains everything needed to implement Tier 2 with no
> prior conversation memory.

---

## STATUS (updated 2026-08-06)

- **TIER 2 ITEM 6, PART B (Email corpus expansion + modern-benign retrain) — DONE.**
  The text model's FP root cause was 2002-era training data (SpamAssassin easy_ham vs old
  phish mboxes): modern legit emails with sign-in/security/verification vocabulary scored high.
  `update_email_data.py` now generates 9 modern benign templates (brand sign-in reviews, 2FA
  verification codes, password-change confirmations, order confirmations, receipts,
  conference invites, internal team email, newsletters, blocked-attempt alerts — with name/device/
  city/code/brand variations, seeded `random.Random(42)`) and 9 modern phish templates
  (account suspended/verify, payment-details update, unusual-activity, lottery prize, package
  redelivery, DocuSign signature, HR benefits, crypto-wallet verify, overdue invoice) — 4,000 of
  each. Corpus now 6,187 phish / 6,187 benign. Retrained `email_text_model.joblib`: holdout
  99.35%, macro f1 0.99. Production checks: `msalerts` legit 0.11 (was ~0.5+ FP), sarah clean
  0.08, user MS phish 0.90, modern benign sign-in 0.02/2FA 0.02, modern phish 0.99. Verified
  end-to-end via `/api/scan/email`: all 6 modern benign cases safe (68–80%), all 3 modern phish
  critical 99% with spoof + DNS indicators.
- **EMAIL FP FIXES (same session).** (1) `spell_mistakes()` no longer flags Title-Case tokens
  (proper nouns like `Aditya`, `Toronto`, `Windows`) — they were counted as spelling errors and
  drove the grammar prob up to 0.39. (2) Enrichment timeout hardening in `scan_url()`:
  `fut_enrich.result()`/`fut_page.result()` now caught with fallback dicts and the executor uses
  `shutdown(wait=False)` — a hung WHOIS socket previously raised `TimeoutError` → HTTP 500
  (`amazoon.com.org` reproduced the crash; now returns danger 67% normally). Same pattern applied
  inside `enrich()` (inner per-key timeout 15s→12s, `shutdown(wait=False)`).
- **BROWSER E2E (same session, pass).** Full end-to-end in headless Firefox 153 + geckodriver 0.36
  (installed to `/tmp/opencode/geckodriver`, `selenium` 4.46 into the model venv — node harness was
  not available). Frontend served via `python -m http.server 8090` on `Code/frontend`. Harness:
  `/tmp/opencode/e2e.py` (execute_script calls MUST use explicit `return` or results come back
  `None`). Results: URL phish `paypol-verify.com` → Threat 67% w/ verify-keyword indicator; URL
  clean youtube → Safe 76%; email phish (paypal-verify.com) → Critical 99% with brand-spoof +
  generic-greeting + NXDOMAIN + no-SPF indicators rendered; email clean → Safe 80%.
- **QR DETECTOR VERIFIED (same session).** QR tab decodes the uploaded QR image client-side with
  jsQR, extracts the URL, and reuses `/api/scan/url` (no backend change needed). Found + fixed one
  gap: the QR results panel had NO `qrIndicators` container, so indicators never rendered for QR
  scans (the generic `renderIndicators('qr', ...)` silently returned). Added
  `<div id="qrIndicators"></div>` to `index.html` after the QR stat rows. Browser-verified with
  generated QR images: `paypol-verify.com` QR → Threat 67% + verify-keyword indicator rendered;
  youtube QR → Safe 75%, no indicators. (Test images `qr_phish.png`/`qr_clean.png` via the `qrcode`
  + `pillow` pip packages.)
- **TIER 2 ITEM 6, PART A (RF calibration) — DONE.** See §6. `train.py` now reports OOF Brier +
  reliability bins + 20% holdout raw-vs-calibrated comparison, fits `CalibratedClassifierCV`
  (isotonic, cv=5) on all data, saves `phishing_model.joblib`. Brier 0.0476→0.0464; mid-bin
  reliability fixed (0.4–0.6 bin: predicted 0.497 vs actual 0.508); smoker probs flattened
  (youtube 0.242, paypol 0.008). Full URL battery green after the `_page_target_trusted()`
  gate fixed a bare-`roblox.ly`→`roblox.com` legit-redirect FP (see ITEM 5 note below).

- **TIER 2 ITEM 5 (Landing-page content scan) — DONE.** See §5. `fetch_page()` + `page_scan()`
  fetch non-allowlisted URL targets in parallel with DNS/whois enrichment and detect credential-
  harvesting phish kits: credential `<input>` fields, cross-site form `action`, meta-refresh / JS /
  HTTP redirects to another site, brand-mismatched `<title>`, very-short-form phish-kit pattern.
  Bumps additive (cap +0.40), enrichment veto still applies after. New `pageSignals` response field
  (also appended to `indicators`). Verified with a local phish-kit server → critical 93% in browser;
  benign page safe; no regression on URL/email battery.
  **Post-hoc gate:** page-signal bumps (cross-site redirect/meta/JS/form-action) only fire when the
  *target* site is itself untrusted (`_page_target_trusted()` = allowlisted). Bare
  `https://roblox.ly` → legit `roblox.com` redirect was FP'd medium 56%; now safe 71%.

- **EMAIL BRAND-SPOOF DETECTION — DONE.** `spoof_detected()` previously only checked header
  mechanics: From/Reply-To mismatch + service-word local parts (`security@`, `support@`...). It
  never inspected the From *domain*, so `From: account-alert@microsoft-securityverify.com` showed
  `spoofingDetected: No`. Added `_domain_brand_spoof_reason()` — reuses the URL brand machinery
  (BRANDS dict, `_edit_distance`, `normalize`) on the From domain: brand as a label of an unrelated
  domain, close resemblance (≤2 edits), or embedded brand (`microsoft-`-prefix, digits). Real brand
  domains and subdomains (`microsoft.com`, `login.microsoft.com`) are exempt. `spoof_detected` now
  returns Yes for brand-squat From domains, and the specific reason is shown as the indicator.
  Also tightened the service-word local-part check: it only fires when the From domain is NOT
  trusted (not allowlisted, not a real brand domain) — fixes FP `support@outlook.com` → No.
  Verified: user's MS phish critical 99% spoof=Yes (reason shown), netflix/paypal phish spoof=Yes,
  legit `msalerts@microsoft.com` / `sarah@example.com` / `gmail.com` spoof=No.
- **TRUSTED-SENDER TEXT CLAMP (same session).** Legit email from a trusted sender
  (`msalerts@microsoft.com`) scored danger 67% because the text model scores security/sign-in
  vocabulary high (trained mostly on 2002-era phish). When the From domain is trusted (real brand
  or top-1M) and no explicit signal is ≥0.5, the text contribution is capped at 0.34 (mirrors the
  URL allowlist clamp). msalerts now safe 66% (text=67% still shown, verdict capped). Untrusted
  senders keep full text contribution (phish still critical 99%).

- **TIER 2 ITEM 4 (SPF/DKIM/DMARC) — DONE.** `sender_auth()` checks SPF TXT on the sender domain,
  DMARC on `_dmarc.` + DKIM on common `_domainkey.` selectors in a 3-thread pool (~4s bound);
  returns `present|absent|domain_missing|unknown` (DNS errors = `unknown`, never penalized).
  `domain_missing` (NXDOMAIN sender) → +0.20 unconditional; missing SPF/DMARC/DKIM only flagged
  when other signals already exist (`prob >= 0.5` guard). Cached per domain 3600s. Response gains
  `senderDomain`, `spfStatus`, `dmarcStatus`, `dkimStatus`. Also fixed a text-model FP family:
  mid-range text scores (0.34–0.5) alone no longer flip benign emails to medium (text contributes
  fully only ≥0.5, else capped at 0.34). Verified: phish critical 99% with NXDOMAIN + no-SPF
  indicators, clean safe, frontend renders new indicators (headless Firefox, 5 items).

- **ACCURACY PASS — DONE.** Fixes an FP family where `www.youtube.com/watch?v=f3DoKx_R1_s`
  flagged suspicious (RF 0.36 via params_length/underscore/live-DNS features):
  1. **Allowlist gate in `score_url()`** — trusted (top-1M suffix) hosts are safe unless a hard
     heuristic fires; learned models suppressed (clamped ≤0.25). Only brand-resemblance prefix /
     TLD-trick / punycode heuristics can override (amazoon.com.org still danger 67%).
  2. **Combiner** — blocklist → heuristic → allowlist gate → else **0.6·RF + 0.4·text** blend for
     untrusted hosts (one overconfident scorer can no longer win alone); heuristic path keeps
     `max(RF, heur, text)` so text-model recall is preserved (paypal spoof back to 99%).
  3. **Enrichment veto** — `_established_domain()` (age ≥2y, string "X years") + valid SSL
     downgrades model-only flags (to 0.34 safe / 0.55 medium). Reuses cached enrich(); no extra
     latency. Rule/blocklist flags always win over the veto.
  4. **Realistic benign retrain** — `augment_dataset.py` generates ~3k benign URLs with real
     query/path shapes (watch?v=, ?q=, /products?id=, underscore tokens) from 600 Tranco domains;
     train.py upgraded to 5-fold stratified CV. New model: CV acc 93.5%, FP 6.6%, FN 6.3%.
  5. Thresholds unchanged; verified with 20-case battery + browser e2e (youtube safe, paypol
     critical, email critical/safe unchanged).

- **TIER 2 ITEM 3 (Email body TF-IDF model) — DONE.** `email_text_features.py` (shared
  `clean_email`: strips HTML tags/entities, collapses URLs→` URL `, emails→` EMAIL `, numbers→
  ` NUM `, removes quoted-reply lines, lowercases — identical at train AND serve time),
  `update_email_data.py` (Nazario phishing0-3.mbox from monkey.org — 4.5k phish after dedup —
  vs SpamAssassin easy_ham 2.5k benign; Enron CMU is 404, easy_ham is the benign source;
  synthetic fallback if downloads fail), `train_email_text_model.py` → `email_text_model.joblib`
  (TfidfVectorizer word (1,2)ngram min_df=2 max_features=200k sublinear_tf + LogisticRegression
  balanced). Holdout 99%; more meaningful: production-style tests phish 0.94 / clean 0.23 / 0.16.
  Wired: `email_text_prob()` in server, `prob = max(link, grammar, heuristic, text)`,
  new `textModelRisk` response field (nothing removed). Regression green (phish critical 99%,
  clean safe 77-80%).

- **ALLOWLIST PREFIX CHECK — DONE.** Bug: `amazoon.com.org` was safe because `com.org` (a real
  top-1M domain) matched the ALLOW suffix, short-circuiting heuristic before brand checks.
  Fix: `_allowlist_suffix_len()` + new allowlisted branch in `heuristic_risk` — prefix labels
  (before the trusted suffix) still get brand-resemblance/edit-distance, TLD-word, and punycode
  checks (prob 0.62+0.05*n). Exact-brand-subdomain rule, phrases, offensive/black-market checks
  deliberately NOT run on allowlisted hosts (avoids FPs like `login.microsoftonline.com`).
  Verified: `amazoon.com.org`→danger 67%; `signin.aws.amazon.com`→safe 99%; full battery green.

- **CONFIDENCE CAP — DONE.** `confidence_from_prob()` (server.py) = `min(99, round(max(prob,1-prob)*100))`,
  applied in URL scan, email per-link, and email scan. No score can ever display 100%.

- **TIER 2 ITEM 1 (URL-text model) — DONE.** `train_url_text_model.py` + `url_text_features.py`
  (shared tokenizer) + `url_text_model.joblib` (a tuple `(TfidfVectorizer, LogisticRegression)`).
  Corpus: OpenPhish feed + mitchellkrogza Phishing.Database `phishing-domains-ACTIVE.txt`
  (391k phish domains) vs Tranco top-1M with realistic URL variants (www, `/login`, `/account`,
  `/products?id=5`, ...). ~94% holdout accuracy. The benign data MUST look like real URLs
  (paths/params/www) or the model learns URL *structure* instead of *content* and overflags
  clean domains (google scored 1.00 phish with bare-domain benign data).
- **EMAIL SIDE — DONE.** `grammar_issues()` (greeting, lowercase starts, missing-space
  punctuation), `spell_mistakes()` (pyspellchecker), `languagetool_issues()` (LT API, cached
  1800s, 8s timeout, `text[:4000]`), `grammar_report()` (Minor/Moderate/Heavy → prob 0.25/0.45/0.75
  + 0.07 per issue; `None` → 0.25), `extract_anchors()` (`[label](url)` + `<a href>`), 
  `link_text_mismatch()` (brand-vs-target = high severity), `scan_email()`. Missing-space regex
  runs on text with emails/URLs sanitized to placeholders (avoids `example.com` FP).
- **FRONTEND EMAIL RENDERING — DONE.** `scanner.js` now has `renderIndicators()` (URL + email
  panels, `#urlIndicators`/`#emailIndicators` in index.html, scanner.js bumped `?v=19`). URL
  panel lists `result.indicators`; email panel lists indicators + per-link breakdown (verdict
  badge + host + top indicator). All text runs through `escapeHtml()` to prevent XSS from
  phishing content. Verified headless-Firefox: phish email → Critical 100%, grammar Moderate,
  link mismatch + spoof shown; clean email → safe 80%, grammar None.
- Wired into `server.score_url()` via `url_text_prob()`: `prob = max(model, heuristic, text)`.
  Guards: skipped for allowlisted hosts (exact/subdomain) and IP literals. Covers
  `niggersforsale.com` (0.87), `nigga.org.xyz` (0.93), `amazoon.com.org.xyz` (0.99),
  paypal spoof (1.00). Legit set stays safe. Verified via curl battery + `e2e.js`.
- Stopgap dictionaries added in Tier 1: `OFFENSIVE_WORDS`, `BLACK_MARKET_WORDS`,
  `SUSPICIOUS_PHRASES` (+ `sale`/`forsale`/commerce words). These run in `heuristic_risk()`
  and their indicators appear in the API response.
- Do NOT retrain or change `url_text_features.py` without checking both training AND server
  prediction paths stay identical (same `url_text` + `analyzer`).
- Remaining Tier 2 items 2–6 (email NLP, SPF/DMARC, landing-page scan, ensemble/calibration)
  are NOT started.

---

## 0. Project snapshot (state at time of writing)

- **Backend:** `/home/aditya/AI project/model/server.py` — Flask app, runs `127.0.0.1:3000`.
  - `model = joblib.load("phishing_model.joblib")`, features in `features.txt` (103 cols).
  - Endpoints: `POST /api/scan/url`, `POST /api/scan/email` (both return JSON with `risk`,
    `confidence`, `verdict`, plus details/indicators).
  - Heuristic layer: `heuristic_risk()` (brand typosquat, TLD-word checks) + `score_url()`
    (`prob = max(model_prob, heuristic_prob)`).
  - Live enrichment in `enrich()`: WHOIS domain age, TLS check, redirect check, DNSBL
    (SURBL/Spamhaus DBL). All cached in the `CACHE` dict with TTLs.
- **Feature extraction:** `/home/aditya/AI project/model/extract_features.py`
  - `FEATURES`: 98 lexical (counts of `.`,`-`,`_`,`/`... per URL/domain/directory/file/params) +
    5 DNS (`qty_ip_resolved`, `qty_nameservers`, `qty_mx_servers`, `ttl_hostname`, `domain_spf`).
  - `extract(url, with_dns=True)` → dict keyed by feature name. `predict_url` builds a
    DataFrame from `feature_cols` and calls `model.predict_proba`.
- **Training:** `train.py` — reads `dataset_small.csv` (columns = FEATURES + `phishing` label),
  RandomForest(100), 93.02% test accuracy, dumps `phishing_model.joblib` + `features.txt`.
- **Model blind spot (known, partially fixed by Tier 1 heuristics):** no brand/NLP knowledge.
  `nigga.org.xyz` → 98% safe. DNS walk-up `_walk_up()` resolves the TLD nameservers, making
  dead domains look like they have DNS infrastructure. Path features are `-1` for bare hosts.
- **Frontend:** `/home/aditya/AI project/Code/frontend/` (vanilla JS, `scanner.js?v=18`,
  `status.css?v=18`). Calls the backend via fetch; renders verdict card + detail fields +
  `indicators` list. **Frontend must NOT be broken when adding fields — add new response
  fields, don't remove existing ones.**

### Tier 1 (already done — do not redo, but keep the helpers)
- Parser fix: `heuristic_risk()` now also flags `registrable in TLD_WORDS` when the TLD is a
  cheap/abuse TLD (set `CHEAP_TLDS`). Fixes the `X.org.xyz` pattern.
- Homoglyph normalization: `normalize()` maps Cyrillic/Greek confusables + fullwidth + common
  digit-for-letter swaps to ASCII; used inside `_edit_distance`/brand comparison.
- Suspicious-phrase dictionary: `SUSPICIOUS_PHRASES` matched against host labels
  (hyphen-split); guarded by allowlist.
- Allow/block lists: `lists/tranco_top1m.txt` (single `ALLOW` set, loaded into memory, used for
  both exact-match and subdomain-suffix allowlist via `_allowlisted()`), `lists/openphish_hosts.txt`
  (blocklist, 268 hosts at last update). `update_lists.py` re-downloads them.
- Exact blocklist match → prob 0.95 (critical). Allowlist (exact or `host.endswith("."+entry)`)
  → skip phrase/TLD-word/brand heuristics to avoid false positives (e.g. `signin.aws.amazon.com`).
- Punycode label (`xn--`) → indicator.

---

## 1. Tier 2 overview

Goal: real NLP + a second ML model, combined with the existing RF. Everything must stay
**pure Python, sklearn, no transformers/LLMs** (student project, offline-friendly, explainable).

Order of implementation (recommended):
1. **URL token TF-IDF model** (fast win, directly attacks the `nigga.org.xyz` class of misses).
2. **Email body TF-IDF model** (the "NLP for emails").
3. **Email header/domain verification** (SPF/DKIM/DMARC via dnspython — already installed).
4. **Landing-page content scan** (optional, async, last because of latency).
5. **Ensemble + calibration + retrain pipeline** (combines everything).

---

## 2. URL token TF-IDF model

### Concept
Tokenize a URL's *text* (host labels + path + query) into words, build a vocabulary, and train
a small Logistic Regression on phishing vs benign URLs. The model's `predict_proba` becomes a
new **feature** for the existing RF, OR is combined directly with the RF score. This is
"classic bag-of-words NLP" — no embeddings needed.

### Data sources (public, free, no keys)
- **Phishing:** OpenPhish feed — `https://openphish.com/feed.txt` (one URL per line, ~1000/day,
  real phishing URLs). Download the *latest* snapshot each training run.
- **Phishing (backup / bulk):** URLhaus CSV — `https://urlhaus.abuse.ch/downloads/csv/`
  (large; column 2 = URL). PhishTank `http://data.phishtank.com/data/online-valid.csv` now
  requires a free API key — skip unless needed.
- **Benign:** Tranco — `https://tranco-list.eu/download/Z28ZM/1000000` (top-1M, CSV, first column
  is rank, second is domain). Also generate benign URLs from these domains by appending
  common paths (`/login`, `/account`, `/` ...) so the model sees real-world benign shapes.
- **Label sanity:** dedupe, lowercase, strip scheme, keep host + path + query text. Remove
  entries that are also in the phishing set. Balance classes (equal counts) or the LR will
  just predict the majority class.

### Implementation sketch
```python
# scripts/train_url_text_model.py
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

def url_text(u):
    # strip scheme, keep host+path+query lowercased, split tokens on non-alnum
    import re
    u = re.sub(r"^[a-z]+://", "", u.lower().strip())
    return " ".join(re.findall(r"[a-z0-9]+", u))

# Build X (list of url_text strings) and y (0/1) from sources above.
X, y = ...  # balanced
pipe = make_pipeline(
    TfidfVectorizer(ngram_range=(1, 3), analyzer="word",
                    min_df=2, max_features=200000, sublinear_tf=True),
    LogisticRegression(C=1.0, max_iter=1000),
)
pipe.fit(X, y)
joblib.dump(pipe, "url_text_model.joblib")
```

### Wiring into `server.py`
```python
url_text_model = joblib.load("url_text_model.joblib")

def url_text_prob(url):
    # same tokenizer as training — MUST match exactly
    return float(url_text_model.predict_proba([url_text(url)])[0][1])
```
Then in `score_url()`:
```python
prob, feats = predict_url(url)          # existing RF
rule = heuristic_risk(host)             # existing heuristics (Tier 1)
text_prob = url_text_prob(url)          # new
prob = max(prob, text_prob, rule[0] if rule else 0.0)
```
- **Feature consistency warning:** if instead you add `text_prob` as an RF *feature*, you must
  add the column to `dataset_small.csv` and retrain. The `max()` approach avoids retraining the
  RF. Use `max()` first; treat "as a feature + retrain" as optional.
- Latency: TF-IDF + LR over 200k terms is ~1–3 ms. Fine.
- **Never** let `text_prob` dominate legit sites: exact allowlist match (Tier 1) must still skip it.

---

## 3. Email body TF-IDF model

### Concept
Same bag-of-words approach on raw email text (headers + body). Emails have much richer text
than URLs, so this is where NLP shines most: urgency/impersonation phrases, brand names in
body, spoofed "From", etc.

### Data sources
- **Phishing:** Nazario phishing corpus — `https://monkey.org/~jose/phishing/phishing0.mbox`
  (a mbox file of real phish emails; there are several `phishingN.mbox` files). Parse mbox →
  list of full raw emails.
- **Benign:** Enron email dataset (public, e.g. `https://www.cs.cmu.edu/~./enron/` or GitHub
  mirrors as .mbox / .txt). Take a random subset.
- Fallback if downloads fail: train on synthetic samples using the existing `URGENT_PHRASES`
  + generated phish-y sentences vs plain English paragraphs. Works, less accurate.

### Implementation sketch
```python
# scripts/train_email_text_model.py
import re, mailbox, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

def clean(raw_email):
    # lower, strip header line-wrapping, remove URLs/emails (keep? decide: yes keep "click here"
    # wording but strip long base64/attachments)
    text = raw_email.lower()
    return text

X, y = [], []   # balanced phish vs benign
pipe = make_pipeline(
    TfidfVectorizer(ngram_range=(1, 2), analyzer="word", min_df=2,
                    max_features=200000, sublinear_tf=True),
    LogisticRegression(C=1.0, max_iter=1000),
)
pipe.fit(X, y)
joblib.dump(pipe, "email_text_model.joblib")
```

### Wiring into `scan_email()`
```python
email_text_model = joblib.load("email_text_model.joblib")
...
text_prob = float(email_text_model.predict_proba([content])[0][1])
prob = max(max_link_prob, heuristic_prob(content), text_prob)
```
- Prefer `max()` over blending at first (simple, explainable). Can later switch to a weighted
  blend: `0.5*link + 0.3*text + 0.2*heuristic`.
- Add `textModelRisk` to the `/api/scan/email` response as a new field ONLY (don't remove
  `suspiciousLinks`, `suspiciousAttachments`, `grammarManipulation`, `spoofingDetected`).

---

## 4. Email header/domain verification (SPF/DKIM/DMARC)

### Status: DONE — 2026-08-05
- `sender_auth(domain)` → `{'spf','dmarc','dkim'}` with values `present|absent|domain_missing|unknown`
  (DNS errors/timeouts → `unknown`, so they never false-flag). SPF/DMARC/DKIM lookups run in a 3-thread
  pool bounded to ~4s total (`ThreadPoolExecutor.shutdown(wait=False)` so lingering lookups never block).
  DKIM probes common selectors (`default, google, selector1, selector2, k1`) under `_domainkey.`.
- `from_domain(content)` parses the `From:` address domain (reuses spoof logic).
- `auth_signals(auth, domain, prob)` adds indicators + prob bump:
  - `spf == domain_missing` (sender domain does not resolve at all) → indicator + **+0.20 unconditional**
    (NXDOMAIN sender = genuine spoof signal; verified `budget.wa.gov` really is NXDOMAIN).
  - Missing SPF/DMARC/DKIM only flagged when **other signals already present** (`prob >= 0.5` guard):
    ≥2 absent → +0.20 indicator; 1 absent → +0.10 indicator. `unknown` never counts as missing.
  - Cache via `cached(f"auth:{domain}", 3600, ...)`.
- Response adds `senderDomain`, `spfStatus`, `dmarcStatus`, `dkimStatus` (existing fields untouched).
- **Text-model FP fix (same session):** mid-range text scores alone (0.34–0.5) flipped benign emails to
  medium. Text score now contributes fully only when `text >= 0.5` or another explicit signal `>= 0.5`;
  otherwise capped at `0.34` (mirrors the URL allowlist clamp). Phish still caught (0.91–0.94 text), clean
  emails back to safe.
- Verified: paypal-spoof phish critical 99% (NXDOMAIN + no-SPF indicators), netflix phish critical 99%
  (text 93%, weak grammar), clean sarah safe 66%, fabricated-domain email medium (correct). Frontend
  renders all new indicators (headless-Firefox: 5 items, Critical 99%).

### Concept
Real phish spoof the `From:` domain. Query the actual DNS records of the sender domain:
- **SPF:** TXT record contains `v=spf1`.
- **DMARC:** TXT record on `_dmarc.<domain>`.
- **DKIM:** hard to check without a selector; optional — check common `default` selector or skip.
- Also: **sender domain age** via existing `domain_age()` (young domain + phishy content = strong).

### Implementation sketch (in `server.py`)
```python
def sender_auth(domain, timeout=4):
    spf = dmarc = None
    try:
        txts = dns.resolver.resolve(domain, "TXT", lifetime=timeout)
        spf = any("v=spf1" in r.to_text() for r in txts)
    except Exception:
        spf = False
    try:
        txts = dns.resolver.resolve("_dmarc." + domain, "TXT", lifetime=timeout)
        dmarc = any("v=dmarc1" in r.to_text() for r in txts)
    except Exception:
        dmarc = False
    return spf, dmarc
```
- In `scan_email()`, parse `From:` domain (reuse `spoof_detected` logic), call `sender_auth`,
  and add `0.2` to prob if the domain has no SPF/DMARC **and** content is already suspicious.
- **Do not** flag every domain without SPF — many small legit sites lack DMARC. Only push the
  score when *other* signals already exist (guard with `prob >= 0.5`).
- Cache results by domain (`cached("spf:" + domain, 3600, ...)`).

---

## 5. Landing-page content scan (optional / async)

### Status: DONE — 2026-08-05
- `fetch_page(url)` — requests GET (verify=False, 4s timeout, 1MB cap) with redirects allowed so the
  final URL + redirect history are visible; returns None on any failure (never penalizes).
- `page_scan(url, host, prob, rule)` — runs **in parallel** with `enrich()` in `scan_url()` (shared
  ThreadPoolExecutor, so no added latency beyond the existing whois window). Skips allowlisted hosts
  and already-critical results. Signals (bump additive, capped +0.40):
  - Redirect chain to a *different registrable site* (+0.15) — same-site `www.` redirects benign.
  - Meta-refresh / JS redirect to another site (+0.15 each).
  - Credential fields `<input type="password">` / `name="password|card_number|cvv|ssn"` (+0.25),
    else credential text + form (+0.15), else very-short page with form (phish-kit pattern, +0.10).
  - Form `action=` posting to a different site than the visible page (+0.20).
  - `<title>` mentioning a brand whose domain is not the host (+0.15).
  - `_page_site()` normalizes to a clean site label (strips port, IPs returned whole) so the
    messages shown to users are readable (`evilcollector.net`, not `evilcollector`).
- Response adds `pageSignals` and appends them to `indicators` (frontend renders automatically —
  reads `result.indicators`). Enrichment veto still runs after the bump, so established+valid-SSL
  sites stay capped regardless of page signals.
- Verified via local phish-kit server: credential form posting to `evilcollector.net` + meta-refresh
  → critical 93% with all 3 signals shown in the browser; benign page safe 80%; full URL/email
  battery unchanged (youtube safe, paypol critical, github/login safe). Latency: google 0.7s,
  unreachable host 0.1s (page fetch bounded 4s, parallel to whois).

### Concept
For URL scans only: fetch the target page (requests already available), extract signals:
- Presence of `<input type="password">`, `name="password"`, `ssn`, `card`, `cvv`.
- Page `<title>` similarity (edit distance) to the apparent brand.
- Forms with hidden fields / `action` pointing to a different domain than the visible one.
- Meta refresh / JS redirect to a different host.
- HTML entropy / very short pages with a form (typical phish kit output).

### Wiring
- Run **asynchronously** after the fast response (thread pool) so the verdict isn't slowed.
  The frontend currently reads results in one fetch; either (a) block briefly (page fetch +
  3s timeout), or (b) expose a second endpoint `/api/scan/url/content` the frontend calls after
  the first verdict. Option (a) is simplest but adds ~0.5–3s to every http URL scan.
- Only fetch `http://` URLs where `https` failed, and only for hosts not in the allowlist.

---

## 6. Ensemble + calibration + retrain pipeline

### Status: DONE — 2026-08-06
- **Calibration (part A):** `train.py` upgraded: StratifiedKFold OOF prediction to report Brier
  score + reliability bins (predicted vs actual per 0.1 bin), a 20% holdout comparing raw RF
  probabilities vs the calibrated ones, then fits `CalibratedClassifierCV(estimator, method="isotonic",
  cv=5)` on the FULL dataset and saves `phishing_model.joblib`. OOF Brier 0.0476; post-cal Brier
  0.0464. The mid-bin overconfidence (0.4–0.6 predicted vs ~0.6 actual) is fixed → cleaner
  0.35/0.60/0.80 tier boundaries. Server reads the calibrated `predict_proba` unchanged (scikit
  exposes `.predict_proba` on the calibrated estimator). Top features readable via
  `model.calibrated_classifiers_[0].estimator.feature_importances_`.
- **Email corpus modernization (part B):** `update_email_data.py` added 9 modern benign templates
  (sign-in review, verification code, password-change confirm, order shipped, receipt, conference,
  internal team, newsletter, blocked-attempt) + 9 modern phish templates (suspended/verify,
  payment update, unusual activity, lottery, package redelivery, DocuSign, HR benefits, crypto
  wallet, overdue invoice), 4,000 each, seeded RNG for reproducibility. Corpus now 6,187/6,187.
  Retrained `email_text_model.joblib` → holdout 99.35%. This fixes the msalerts-type FP (root
  cause: 2002-era training data). See STATUS for the full verification numbers.
- **FP + robustness fixes landed during verification:** proper-noun spelling FP in
  `spell_mistakes()` (Title-Case tokens no longer counted as misspellings) and enrich-timeout
  crash in `scan_url()`/`enrich()` (hung WHOIS socket no longer → HTTP 500; graceful fallbacks).

### Concept
Combine RF (lexical) + URL-text LR + email-text LR + heuristics into one score, then calibrate.

### Approaches (pick one)
1. **Weighted max/vote (simplest):**
   `prob = max(model_prob * 1.0, text_prob * 1.0, heuristic_prob * 1.0)` with optional weights
   tuned on a small labeled set. Already the pattern used everywhere.
2. **Meta-model (better):** build a small dataset of scans → `(model_prob, text_prob,
   heuristic_prob, [detail fields])` → `label`, train `LogisticRegression` on those *scores*.
   This is "stacking" — the meta-model learns when to trust which expert.
3. **Calibration:** `sklearn.calibration.CalibratedClassifierCV` on the RF's probabilities
   (isotonic). Produces truer probabilities → cleaner 0.35/0.60/0.80 tier boundaries.

### Retrain workflow (add a `retrain.sh` / extend `train.py`)
1. `update_lists.py` — refresh lists + corpora.
2. `build_dataset.py` — merge `dataset_small.csv` + newly extracted features (if new features
   were added to `FEATURES`, regenerate CSVs with `extract()`).
3. `train.py` — retrain RF, dump model + features.txt.
4. Re-run `scripts/train_url_text_model.py` and `scripts/train_email_text_model.py`.
5. Restart server, run `e2e.js` (see Tier 1 verification below).

### Golden rules
- **Features must be identical at train & predict time.** If you change `extract_features.py`,
  you MUST retrain. Never change feature extraction live without retraining.
- **Never remove response fields the frontend reads.** Add new ones.
- **Restart pattern:** kill by explicit PID (`kill <pid>`, find via `ss -tlnp | grep 3000`),
  then `nohup setsid ./venv/bin/python server.py < /dev/null > server.log 2>&1 & disown`.
  Model load is ~8s. **Never `pkill -f "python server.py"`.**
- Verify with the browser harness in `/tmp/opencode/webdriver/` (`e2e.js`, `check-threat-card.js`)
  and with `curl` against `127.0.0.1:3000`.

---

## 7. Verification checklist after any Tier 2 change
1. `curl POST /api/scan/url` with `{"url":"https://www.google.com"}` → `safe`, high confidence.
2. `... {"url":"http://amazoon.com.org.xyz"}` → not safe (heuristic still catches).
3. `... {"url":"https://nigga.org.xyz"}` → not safe (this is the Tier 1 + text-model target).
4. `... {"url":"http://paypal.com.secure-login-verify.xyz/account/confirm.php?id=98213"}`
   → `danger`/`critical`.
5. Legit: `signin.aws.amazon.com`, `info.com`, `192.168.1.1`, `shop.amazon.co.uk` → safe.
6. `curl POST /api/scan/email` with the paypal spoof sample → `danger`/`critical`.
7. Run `/tmp/opencode/webdriver/e2e.js` (needs geckodriver in that dir; Firefox headless).
8. If a Tier 2 model is added, verify its latency stayed under ~50ms per scan (log timings).

## 8. Files you will create/modify for Tier 2
- NEW `/home/aditya/AI project/model/scripts/train_url_text_model.py`
- NEW `/home/aditya/AI project/model/scripts/train_email_text_model.py`
- NEW `/home/aditya/AI project/model/build_dataset.py` (optional)
- MOD `/home/aditya/AI project/model/server.py` (load new models, wire scores into
  `score_url()` / `scan_email()`, add `sender_auth()`)
- NEW `/home/aditya/AI project/model/url_text_model.joblib` (generated)
- NEW `/home/aditya/AI project/model/email_text_model.joblib` (generated)
- MOD `train.py` (if adding features) — only with full retrain
- Update `model.md` (architecture) + `logic.md` (scoring explanation) after each change.
