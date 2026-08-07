# PhisDetect — URL Detection: Complete Reference

> Everything about how a URL gets scanned: the two ML models, the heuristic layer,
> the allowlist/blocklist gates, live DNS/WHOIS/SSL enrichment, the landing-page
> content scan, the calibration pipeline, and the API contract.
>
> Code lives in `/home/aditya/AI project/model/`. All function names below match
> `server.py` / `extract_features.py` / `train*.py` exactly so you can jump to them.

---

## 1. The one-minute summary

Scanning one URL produces **one probability** `prob ∈ [0, 1]` that the URL is phishing,
plus a list of human-readable **indicators**. The probability is computed by `score_url()`
(`server.py`) by combining, in priority order:

1. **Blocklist hit** (OpenPhish hosts) → `prob = max(prob, 0.95)` — hard kill, immediate return.
2. **Heuristic rules** (brand typosquat, cheap-TLD tricks, suspicious/offensive/black-market
   keywords, punycode) → `prob = max(prob, heuristic_prob)`.
3. **Allowlist gate** (Tranco top-1M suffix) → trusted sites are clamped to `≤ 0.25` unless a
   hard heuristic fired.
4. **Learned models blend** for everything else: `prob = 0.6 · RF + 0.4 · URL-text`.

Then a **parallel enrichment pass** (WHOIS domain age, TLS cert, redirect check, DNSBL) runs,
plus an optional **landing-page scan** (fetch the HTML, look for credential-harvesting / phish-kit
patterns). These can push `prob` up by at most `+0.40` — or *down* via the **enrichment veto**
(a 2+ year-old domain with a valid SSL cert flagged only by the models is downgraded to at most
medium).

The final number is mapped to a **verdict tier** and a **confidence percentage** (never 100%).

---

## 2. Risk model: tiers, thresholds, confidence

Defined in `server.py`.

| `prob` | `risk`    | Verdict label | Frontend badge | Conclusion shown to user |
|--------|-----------|---------------|----------------|--------------------------|
| `< 0.35`  | `safe`    | Safe          | green          | "No significant phishing indicators detected." |
| `[0.35, 0.60)` | `medium` | Suspicious | amber          | "Some suspicious signals found. Review carefully…" |
| `[0.60, 0.80)` | `danger` | Threat     | red            | "Strong indicators of phishing. Do not enter any credentials." |
| `≥ 0.80` | `critical` | Critical    | dark red       | "High-confidence phishing URL. Blocked." |

```python
def risk_from_prob(prob):            # server.py
    if prob < 0.35:  return "safe"
    if prob < 0.60:  return "medium"
    if prob < 0.80:  return "danger"
    return "critical"

def confidence_from_prob(prob):
    return min(99, round(max(prob, 1 - prob) * 100))
```

**Confidence is never 100%.** It is `max(prob, 1-prob) * 100`, capped at 99. So a `critical`
URL at `prob = 0.95` shows 95%, and a very safe URL at `prob = 0.05` also shows 95% (confidence
in the *verdict*, not a probability). This cap is deliberate — no score ever displays 100%.

The `verdict` field in the API is `build_verdict(risk)` → `{label, color, conclusion}` from
`VERDICT_COLORS` / `VERDICT_LABELS` / `VERDICT_CONCLUSIONS`.

---

## 3. Pipeline overview

```
URL input
  │
  ▼
score_url(url) ───────────────────────────────  (fast, synchronous)
  ├─ 1. predict_url(url)      → RF lexical prob  (extract_features.py + phishing_model.joblib)
  ├─ 2. blocklist check       → 0.95 hard kill   (lists/openphish_hosts.txt)
  ├─ 3. heuristic_risk(host)  → heuristic prob + reasons (brand/TLD/phrase rules)
  ├─ 4. allowlist gate        → clamp ≤ 0.25 unless heuristic fired
  ├─ 5. url_text_prob(url)    → TF-IDF text prob  (url_text_model.joblib)
  └─ 6. combine               → max() or 0.6·RF + 0.4·text
  │
  ▼
scan_url() ────────────────────────────────────  (parallel, up to ~20s wall)
  ├─ ThreadPoolExecutor(max_workers=2)
  │   ├─ enrich(url, host, https)   → domainAge, sslStatus, redirection, blacklist
  │   └─ page_scan(url, host, prob, rule) → pageSignals + bump (cap +0.40)
  ├─ prob = min(prob + page_bump, 0.99)
  ├─ enrichment veto  (established domain + valid SSL + model-only flag → cap 0.34/0.55)
  └─ JSON response (risk, confidence, verdict, indicators, enrichment fields)
```

`score_url()` is pure computation (no network) — the RF and text models plus heuristics.
The network-heavy enrichment and page fetch happen in `scan_url()` in parallel so the two slow
operations overlap instead of adding up.

---

## 4. Layer 1 — Random-Forest lexical model (the "RF")

### 4.1 Features (`extract_features.py`)

103 features, all counting *structure*, not meaning:

- **URL-global** (17): `qty_dot_url`, `qty_hyphen_url`, `qty_underline_url`, `qty_slash_url`,
  `qty_questionmark_url`, `qty_equal_url`, `qty_at_url`, `qty_and_url`, `qty_exclamation_url`,
  `qty_space_url`, `qty_tilde_url`, `qty_comma_url`, `qty_plus_url`, `qty_asterisk_url`,
  `qty_hashtag_url`, `qty_dollar_url`, `qty_percent_url`, plus `qty_tld_url` (how many TLD-ish
  strings appear, via `count_tld()` against `tlds.txt`, 1390 entries) and `length_url`.
- **Domain** (17 char-counts + 4 extras): same counting characters applied to the host, plus
  `qty_vowels_domain`, `domain_length`, `domain_in_ip` (is the host an IP literal), and
  `server_client_domain` (host contains "server" or "client").
- **Directory** (17 + 1) and **File** (17 + 1): the same counters on `path` and on the basename
  of `path`. When there is no path, these are all set to `-1` (a sentinel the tree can split on).
- **Params** (17 + 3): counters on the query string, plus `params_length`,
  `tld_present_params` (a TLD string appears inside the query), and `qty_params`
  (from `urllib.parse.parse_qs`).
- **Misc** (2): `email_in_url` (an email pattern appears in the URL), `url_shortened`
  (host is in `shorteners.txt`, 443 entries like `0rz.tw`, `1-url.net`, `126.am`).
- **DNS** (5): `qty_ip_resolved`, `ttl_hostname`, `qty_nameservers`, `qty_mx_servers`,
  `domain_spf`. Computed by `_dns_features()`, which resolves live DNS:
  - `A` record → count of IPs + TTL.
  - Nameserver/MX counts use `_walk_up()` — if the exact host has no NS/MX it walks up the labels
    (host → parent domain → …) so even dead subdomains report the parent's infrastructure. This is
    why a bare dead domain can *look* like it has DNS — one of the model's known blind spots that
    the heuristic layer compensates for.
  - `domain_spf` = 1 if a TXT record with `v=spf1` exists on the host or a parent label, 0 if
    present without SPF, `-1` on lookup failure.
  - **Train-time vs serve-time mismatch warning:** `_dns_features()` is live DNS, but training uses
    `extract(url, with_dns=False)` (DNS features = `-1/-1/0/0/-1`) in `augment_dataset.py`. So the
    RF learns the DNS columns mostly as "missing" — fine, the columns still exist at serve time.

`extract(url)` returns a dict keyed exactly by `FEATURES`; `predict_url()` (`server.py`) wraps it
in a DataFrame ordered by `features.txt` and calls `model.predict_proba`.

### 4.2 Training (`train.py`)

- Reads `dataset_augmented.csv` (61,705 rows: 31,058 benign / 30,647 phish).
- Reports **5-fold StratifiedKFold** CV (accuracy, confusion matrix totals, FP/FN rates) and an
  **out-of-fold Brier score** plus **reliability bins** (predicted vs actual per 0.1 bin) — this
  is how we caught the mid-range overconfidence.
- Runs a **20% holdout** comparison of raw RF vs calibrated probabilities.
- Fits the final model as `CalibratedClassifierCV(estimator=RandomForestClassifier(n_estimators=100),
  method="isotonic", cv=5)` on **all** data and saves `phishing_model.joblib` + `features.txt`.
- Prints the top-15 `feature_importances_` from
  `model.calibrated_classifiers_[0].estimator.feature_importances_`.

**Calibration results (2026-08-06):** OOF Brier 0.0476 → calibrated Brier 0.0464. The mid-bin
overconfidence (prob 0.4–0.6 predicted, ~0.5–0.6 actual) is fixed, which made the 0.35/0.60/0.80
tier boundaries meaningfully more trustworthy. Smoker-probe probabilities flattened dramatically
(e.g. `youtube.com` RF ≈ 0.24, `paypol-verify.com` ≈ 0.01).

### 4.3 Known behavior / blind spots

- RF alone flags *realistic* benign URLs (watch?v=, ?q=, /products?id=5, underscores) as
  suspicious — that's exactly why the **allowlist gate** (§7) and the **benign retrain**
  (`augment_dataset.py`, §9) exist.
- RF has no concept of brands or words — `nigga.org.xyz` scored ~98% safe before the text model
  and heuristics were added.

---

## 5. Layer 2 — URL-text TF-IDF model

### 5.1 Tokenizer (`url_text_features.py`)

`url_text(u)`:
1. lowercase, strip scheme after `://`, cut at whitespace/quotes.
2. drop fragment and query (`#` and `?`).
3. replace every run of non-alphanumerics with a single space → a bag of words.

`analyzer(text)`: yields each word (length 2–24), **plus** all 3-, 4-, 5-grams of every word ≥ 3
chars. The character n-grams let the model recognize *morphological* tricks like
`paypol`, `amazoon`, `verify-login` even when the exact token is unseen.

### 5.2 Training (`train_url_text_model.py`)

- **Phishing:** OpenPhish feed (`openphish.com/feed.txt`) + mitchellkrogza Phishing.Database
  `phishing-domains-ACTIVE.txt` (≈391k hosts), deduped, capped at 150k random samples.
- **Benign:** Tranco top-1M — first 5,000 guaranteed + random sample to match phish count, each
  domain expanded into **realistic variants**: bare domain, `www.`, `/login`, `/index.html`,
  `/about`, `/account/settings`, `/products?id=5`. (Critical design point: benign data must look
  like *real* URLs. With bare domains only, the model learned "URL *structure*" instead of
  "URL *content*" and scored `google.com` as 1.00 phish.)
- Pipeline: `TfidfVectorizer(analyzer=analyzer, ngrams via analyzer, min_df=2, max_features=150000,
  sublinear_tf=True)` + `LogisticRegression(C=1.0, solver="liblinear", class_weight="balanced")`.
- Saved as a **tuple** `(vec, clf)` → `url_text_model.joblib`. Holdout accuracy ≈ 94%.

### 5.3 Serving (`url_text_prob` in server.py)

```python
def url_text_prob(url, host):
    if url_text_vec is None or url_text_clf is None: return None
    if _allowlisted(host) or valid_ip(host): return None    # gate + IPs skipped
    return float(url_text_clf.predict_proba(url_text_vec.transform([url_text(url)]))[0][1])
```

The tokenizer **must be byte-identical at train and serve time** (both import `url_text` /
`analyzer` from `url_text_features`). Never edit that file without retraining both.

---

## 6. Layer 3 — Heuristics (`heuristic_risk(host)`, server.py)

The explainable rules layer. Returns `(prob, [reasons])` or `None`. Base prob is
`0.62 + 0.05 · min(len(reasons), 3)`, capped at 0.80. Every reason becomes an API indicator.

### 6.1 Brand-spoof detection

`BRANDS` maps brand name → real domain (28 brands: amazon, paypal, google, microsoft, netflix,
apple, icloud, coinbase, binance, metamask, …). For every brand it inspects each host label:

- **Exact brand as a subdomain of an unrelated domain** — `paypal.com.secure-login-verify.xyz`.
- **Close resemblance** — Levenshtein `_edit_distance(norm_label, brand) <= 2` (e.g.
  `amazoon`, `paypol`). The distance is computed on the **homoglyph-normalized** label.
- **Embedded brand** — label contains the brand plus `-` prefix/suffix/`-brand-` infix or any
  digit: `microsoft-securityverify.com`, `paypal-verify.com`.
- **Homoglyph normalization** (`normalize()`): maps Cyrillic/Greek confusables (а→a, р→p, ο→o,
  ѕ→s, …), full-width Latin (ａ→a), and common digit-swaps (1→l, 0→o, 3→e, 4→a, 5→s, 7→t).
  So `arnazon.com`, `paypa1.com`, `mіcrosoft.com` (Cyrillic і) are all caught.
- Real brand domains and their subdomains are **exempt** (`low == real or low.endswith("." + real)`).

### 6.2 TLD / structure tricks

- `TLD_WORDS = {com, net, org, co, info, biz, io}` used as a **subdomain label**
  → "TLD-like word used as a subdomain label" (`amazoon.com.org.xyz` → `com` is a label).
- `registrable in TLD_WORDS and tld in CHEAP_TLDS` → "TLD-like word used before a cheap TLD".
  `CHEAP_TLDS` = abuse-prone zones: `xyz top club online site live click link icu vip fun work
  space store buzz cyou rest token ga gq ml tk cf`.
- Punycode `xn--` label → "IDN/punycode encoded domain label".
- `_allowlist_suffix_len()` handles the **allowlisted-with-brand-prefix** case (§7).

### 6.3 Keyword dictionaries

- `SUSPICIOUS_PHRASES` (~40): `account, signin, login, verify, confirmation, password,
  secure-login, banking, billing, invoice, payment, wallet, crypto, bitcoin, giftcard, prize,
  giveaway, claim, suspended, locked, urgent, action-required, …` plus sale/e-commerce words
  (`sale, forsale, deals, auction, outlet, …`). Substring match on the whole host.
- `OFFENSIVE_WORDS`: slurs and shock terms (`nigger, faggot, cunt, rape, nazi, hitler, kkk,
  spic, …`) — the `nigga.org.xyz` / `niggersforsale.com` class of URLs.
- `BLACK_MARKET_WORDS`: `drugs, cocaine, heroin, fentanyl, viagra, xanax, poker, casino,
  gambling, payday, bitcoin, crypto, porn, escrow, …`.

### 6.4 Allowlisted hosts (the "prefix check")

When a host is allowlisted, only the **prefix labels** (before the trusted suffix) are inspected,
and only for brand-resemblance / TLD-word / punycode — deliberately NOT phrases or offensive/
black-market lists (those would false-positive on `login.microsoftonline.com`). This fixed
`amazoon.com.org` (safe because `com.org` is a real top-1M domain) → now danger 67%.

---

## 7. Layer 4 — Allowlist & blocklist gates

### 7.1 Allowlist (`ALLOW`, `lists/tranco_top1m.txt`)

- Loaded into a `set` at startup. `_allowlisted(host)` returns True if the host **or any suffix**
  of it is in the set (`foo.shop.amazon.co.uk` → checks `amazon.co.uk`, `co.uk`, …).
- **Gate in `score_url()`:** if allowlisted and no heuristic fired → `prob = min(prob, 0.25)`
  (learned models suppressed → realistic benign URLs stay safe). If a heuristic fired (e.g. a
  brand-resembling prefix like `paypol.secure-site.com`) → `prob = max(prob, heuristic_prob)` and
  the heuristic wins.
- `_allowlist_suffix_len()` returns how many trailing labels match, so `heuristic_risk()` knows
  exactly which labels are the untrusted prefix.

### 7.2 Blocklist (`BLOCK`, `lists/openphish_hosts.txt`)

- Hosts harvested from the OpenPhish feed by `update_lists.py` (last update ≈ hundreds of hosts).
- Match is exact or on the registrable domain: `host in BLOCK or registrable in BLOCK`.
- Hit → `prob = max(prob, 0.95)`, indicator "Domain listed on known phishing blocklist
  (OpenPhish)", **immediate return** (rule always wins; see veto §10).

### 7.3 The combination inside `score_url()`

```python
def score_url(url):
    prob, feats = predict_url(url)              # RF
    host = parse_url(url)["host"].lower()
    rule = None
    if host in BLOCK or registrable in BLOCK:
        prob = max(prob, 0.95); rule = blocklist; return
    heur = heuristic_risk(host)
    if _allowlisted(host):
        if heur: prob = max(prob, heur[0]); rule = heur
        else:    prob = min(prob, 0.25)
        return
    text_prob = url_text_prob(url, host)
    if heur:
        prob = max(prob, heur[0], text_prob or 0.0); rule = heur; return
    if text_prob is not None:
        prob = 0.6 * prob + 0.4 * text_prob       # blend, no rule
    return prob, feats, rule
```

Design rationale:
- **Blocklist and heuristics are "hard rules"** — they win by `max()`. The blend is only for the
  "no hard signal" path so one overconfident learned scorer can't dominate alone.
- `rule is None` distinguishes "model-only suspicion" (needed by the enrichment veto §10).

---

## 8. Live enrichment (`enrich()`)

Runs in `scan_url()` inside a `ThreadPoolExecutor(max_workers=2)`, in parallel with the page scan.
Each check is wrapped in `cached(key, ttl, fn)` (in-memory `CACHE` dict, keyed per host/url):

| Field          | Function                          | How it works | TTL |
|----------------|-----------------------------------|--------------|-----|
| `domainAge`    | `domain_age(host)`                | `python-whois` creation_date → age string | 1800s |
| `sslStatus`    | `ssl_check(host)`                 | real TLS handshake on :443, parse cert `notBefore`/`notAfter` | 300s |
| `redirection`  | `redirect_check(url)`             | `requests.get(allow_redirects=False)` → any 3xx | 300s |
| `blacklist`    | `blacklist_check(host)`           | DNS queries `host.multi.surbl.org` + `host.dbl.spamhaus.org`; any A record in `127.0.0.0/8` = flagged | 600s |

- `domain_age(host)`: WHOIS in a **1-worker thread pool with a 7s timeout** (WHOIS sockets can
  hang forever). Age string is `"N hours"` (<1d), `"N days"` (<90d), `"N months"` (<730d), or
  `"N.N years"`. Failure/None → `"Unknown"`.
- `ssl_check(host)`: only runs when the input scheme is `https://`. Any error → `"Invalid"`.
- `enrich()` itself runs its 4 checks in a pool and bounds each with a 12s `fut.result()`; on
  timeout/failure it substitutes safe defaults (`Unknown` / `Invalid` / `None` / `Clear`) so a
  hanging WHOIS can **never** crash the request. The pool uses `shutdown(wait=False)` so lingering
  sockets don't block the HTTP response. (This was a real bug: a hung WHOIS socket raised
  `TimeoutError` → HTTP 500 on `amazoon.com.org`; fixed 2026-08-06.)

`_established_domain(extra)` is derived from `domainAge`: True only when the string parses as
`float >= 2` **and** contains `"year"`.

---

## 9. Landing-page content scan (`page_scan()`)

An optional second opinion that actually **fetches the page**. Runs in parallel with enrichment;
never runs for allowlisted hosts or already-critical results (`prob >= 0.85`).

- `fetch_page(url)`: `requests.get(allow_redirects=True, verify=False, timeout=4)`, streams up to
  **1 MB**, follows redirects so the final URL + history are visible. Any failure → `None`
  (never penalizes).
- Signals (each adds a `pageSignals` entry + a bump; bumps are additive, **capped at +0.40**):

| Signal | Bump | Detection |
|--------|------|-----------|
| HTTP redirect chain to a *different registrable site* | +0.15 | `page["history"]` vs `final_url`, compared via `_page_site()` |
| `<meta http-equiv=refresh>` to another site | +0.15 | regex `PAGE_META_REFRESH_RE` |
| JS `window.location`/`document.location` redirect to another site | +0.15 | regex `PAGE_JS_REDIRECT_RE` |
| Credential `<input type=password>` or `name=password/card_number/cvv/ssn` | +0.25 | regex `PAGE_CREDENTIAL_RE` |
| Credential *words* (ssn, cvv, "card number"…) + a form | +0.15 | `CRED_WORDS` substring |
| Very short page (`< 2500` chars) that contains a form | +0.10 | phish-kit pattern |
| Form `action=` posting to a different site | +0.20 | regex `PAGE_FORM_ACTION_RE` |
| `<title>` mentions a brand whose domain isn't the host | +0.15 | `PAGE_TITLE_RE` vs `BRANDS` |

- **`_page_site(target)`** normalizes a URL/fragment to its registrable site label (last 2 labels;
  IP literals returned whole) — same rule on both sides of every comparison so detection stays
  correct; this only fixes the user-facing text (`evilcollector.net`, not `evilcollector`).
- **`_page_target_trusted(target)`** — a critical gate added during calibration: redirect / meta /
  JS / form-action signals only fire when the **target** is itself untrusted (not allowlisted).
  Otherwise a legit `roblox.ly` → `roblox.com` redirect would be flagged (was FP medium 56%;
  now safe 71%).

---

## 10. Enrichment veto (downgrade rule)

```python
if rule is None and _established_domain(extra):
    if extra.get("sslStatus") == "Valid":
        prob = min(prob, 0.34)     # → safe
    else:
        prob = min(prob, 0.55)     # → medium
```

A domain registered **≥ 2 years** with a **valid TLS certificate** that was flagged **only by the
learned models** (`rule is None` — no blocklist, no heuristic, no page signal) is very unlikely to
be phishing, so the score is capped: valid SSL → at most safe (`0.34`), no/invalid SSL → at most
medium (`0.55`). Hard rules (blocklist / heuristic) always beat the veto. This killed the
youtube/amazon FPs while keeping `paypol`-style attacks (young domain, no legit cert, hard signals)
fully flagged.

---

## 11. The API endpoint

`POST /api/scan/url` (`scan_url()`, server.py). Input:
```json
{ "url": "https://example.com/whatever" }
```
(`http://` or `https://` required — anything else → 400 `"URL must start with http:// or https://"`.)

Response:
```jsonc
{
  "risk": "safe" | "medium" | "danger" | "critical",
  "confidence": 42,                          // 0–99, never 100
  "verdict": { "label": "Safe", "color": "#22c55e", "conclusion": "..." },
  "domainAge": "3.2 years" | "5 days" | "Unknown",
  "sslStatus": "Valid" | "Invalid",
  "redirection": "None" | "Detected",
  "blacklist": "Clear" | "Flagged",
  "pageSignals": ["Page requests credentials (password / card / SSN fields)", "..."],
  "indicators": ["Domain 'amazoon' closely resembles the brand 'amazon'", "..."]
}
```

`indicators` = heuristic reasons (if any) **plus** page signals — the frontend renders this list
verbatim (through `escapeHtml()`). Enrichment fields feed the dashboard detail stats.

Latency budget: `score_url()` is ~ms (models in memory). Enrichment + page scan bound the request
to roughly the WHOIS window (~7s worst case, usually far less; both slow paths run in parallel).
The `CACHE` makes repeat scans of the same host/url nearly instant for the cached checks.

---

## 12. Data & lists

| File | Contents | Used by | Refreshed by |
|------|----------|---------|--------------|
| `lists/tranco_top1m.txt` | top-1M domains, one per line | `ALLOW` set, benign URL-text data | `update_lists.py` |
| `lists/tranco_top100k.txt` | first 100k of the above | reference / future use | `update_lists.py` |
| `lists/openphish_hosts.txt` | OpenPhish hostnames | `BLOCK` set | `update_lists.py` |
| `tlds.txt` | 1390 TLD strings | `count_tld`/`check_tld` features | static |
| `shorteners.txt` | 443 URL shortener hosts | `url_shortened` feature | static |
| `dataset_small.csv` | 58,645 rows (30,647 phish / 27,998 benign) — original RF corpus | base for augmentation | — |
| `dataset_augmented.csv` | 61,705 rows (31,058 benign / 30,647 phish) | RF training | `augment_dataset.py` |
| `phishing_model.joblib` | calibrated RF | server RF predictions | `train.py` |
| `features.txt` | the 103 feature names, one per line | column ordering at serve time | `train.py` |
| `url_text_model.joblib` | `(TfidfVectorizer, LogisticRegression)` tuple | URL-text predictions | `train_url_text_model.py` |

`update_lists.py` downloads a fresh Tranco top-1M zip + OpenPhish feed and rewrites the lists.

---

## 13. Training pipeline (end to end)

1. `update_lists.py` — refresh Tranco + OpenPhish lists.
2. `augment_dataset.py` — from `dataset_small.csv`, generate ~3k *realistic benign* URLs
   (600 random Tranco domains + 18 guaranteed mega-brands, ×5, shaped with watch?v=, ?q=,
   /products?id=, underscore tokens, subdomains like `m.`/`shop.`/`accounts.`) with
   `with_dns=False` + fake DNS defaults → `dataset_augmented.csv`.
3. `train.py` — 5-fold CV + calibration diagnostics, then fit the **calibrated** RF on all data →
   `phishing_model.joblib` + `features.txt`.
4. `train_url_text_model.py` — download phish feeds, build realistic benign variants from Tranco,
   train TF-IDF LogReg → `url_text_model.joblib`.
5. Restart the server (`kill` by PID via `ss -tlnp | grep ':3000'`, then
   `nohup setsid ./venv/bin/python server.py </dev/null > server.log 2>&1 & disown`).
   Model load is ~8s. **Never `pkill -f "python server.py"`** — it kills the shell too.

Golden rules:
- Train-time and serve-time feature extraction MUST be identical (same `extract_features.py`).
- The URL-text tokenizer MUST be identical at train and serve (`url_text_features.py`).
- Never remove API fields the frontend reads — only add.
- After any model/data change, run the verification battery (§14).

---

## 14. Verification battery (run after every change)

1. `https://www.google.com` → safe, high confidence.
2. `http://amazoon.com.org.xyz` → not safe (heuristic, TLD-word trick).
3. `https://nigga.org.xyz` → not safe (text model + offensive word).
4. `http://paypal.com.secure-login-verify.xyz/account/confirm.php?id=98213` → danger/critical.
5. `signin.aws.amazon.com`, `info.com`, `192.168.1.1`, `shop.amazon.co.uk` → safe.
6. `https://www.youtube.com/watch?v=...` and `https://www.amazon.com/product/...` → safe
   (the original FP family; allowlist gate + veto + calibration all protect these).
7. `https://paypol-verify.com/login` → danger 67% ("Suspicious keyword 'verify'").
8. `https://www.roblox.ly/login` → critical (OpenPhish blocklist); bare `https://roblox.ly` → safe
   (page-target gate prevents the legit-redirect FP).
9. Browser e2e: `/tmp/opencode/e2e.py` against headless Firefox (URL phish Threat 67%,
   URL clean Safe 76%). Note: selenium `execute_script` needs an explicit `return`.

Representative results from the 2026-08-06 session:
youtube safe 75–77%, amazon product safe 75%, paypol danger 67%, amazoon.com.org danger 67%,
`www.roblox.ly` critical 95% (blocklist), google safe 98%, random
`suspicious-login-verify.com` critical 85% (login+verify keywords, offensive-term quirk).

---

## 15. Known limitations (be honest about these)

- **WHOIS flakiness:** many registrars rate-limit or strip whois; `domainAge` frequently returns
  "Unknown", which disables the veto. The `_walk_up()` DNS feature can also over-report
  infrastructure for dead domains.
- **Blocklist is small** (only hosts from the last OpenPhish snapshot). Not a global threat intel
  feed.
- **Heuristics are English-centric** and keyword-list driven; brand coverage is 28 brands.
- **Page scan is best-effort** — sites behind JS-heavy SPAs or aggressive bot protection return no
  HTML (never penalized, but signals are missed).
- The RF's DNS columns are trained as "missing"; treat live-DNS-feature *values* as informational
  rather than heavily trusted.
- `indicator` text from a host's own content (titles, anchors) passes through the server as
  strings; the frontend HTML-escapes everything, but any future renderer must too.
