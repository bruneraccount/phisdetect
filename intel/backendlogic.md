# Backend Logic Documentation

**PhisDetect — Flask backend (`backend/server.py`)**

This document describes, in detail, every piece of backend logic that turns a
user-supplied URL or email into a risk verdict: the decision pipelines, the
rule-based heuristics, the enrichment services (WHOIS / SSL / RBL / page scan),
the scoring math, the caching layer, and the API surface. It is the companion
to [`model.md`](model.md) (what the models *are*) and [`structure.md`](structure.md)
(what files exist).

---

## Table of Contents

1. [Overview](#1-overview)
2. [Startup & global state](#2-startup--global-state)
3. [Shared building blocks](#3-shared-building-blocks)
4. [URL scan pipeline](#4-url-scan-pipeline)
5. [Enrichment services](#5-enrichment-services)
6. [Page scan](#6-page-scan)
7. [Email scan pipeline](#7-email-scan-pipeline)
8. [Minigame leaderboard persistence](#8-minigame-leaderboard-persistence)
9. [API reference](#9-api-reference)
10. [Scoring model summary](#10-scoring-model-summary)
11. [Caching & concurrency](#11-caching--concurrency)
12. [Operational & security notes](#12-operational--security-notes)

---

## 1. Overview

The backend is a single Flask application (`backend/server.py`, 1,218 lines).
There is **no database** — state is either in-memory (model artifacts, caches,
host lists) or in one small JSON file for the leaderboard. The scanner is
deliberately **defense-in-depth**: a verdict is never decided by one signal. A
scan stacks four independent layers of evidence:

| Layer | What it does | Slow? |
|-------|--------------|-------|
| **ML models** | `phishing_model` on URL features; `url_text_model` on the URL string; `email_text_model` on the email text | Fast, but the feature extractor makes live DNS lookups |
| **Rule heuristics** | Brand-spoofing, cheap TLDs, suspicious/offensive/black-market keywords, IDN tricks, phishing phrases, From/Reply-To spoofing | Fast |
| **Enrichment** | WHOIS domain age, TLS cert validity, HTTP redirect detection, RBL blacklist checks | Slow (network; parallelised) |
| **Page scan** | Fetches the target HTML and looks for redirects, credential forms, phish-kit patterns, brand mention in title | Slow (network; only for URLs) |

The two big pipelines are:

- **`POST /api/scan/url`** — `score_url()` produces a probability from the URL
  models + heuristics; then `enrich()` and `page_scan()` run in parallel and
  add bumps; an "established domain" veto can downgrade the result.
- **`POST /api/scan/email`** — every link inside the email is run through
  `score_url()`, the email text is scored by the email model + grammar/spoof
  heuristics, and sender SPF/DMARC/DKIM are queried. All scores are combined.

A third endpoint persists **minigame results** (phish-or-legit, link-dismantler,
threat-hunt) to `backend/data/minigame_scores.json` and serves leaderboards.

---

## 2. Startup & global state

### 2.1 Model loading

At import time the backend adds `model/src` to `sys.path` and imports the
feature extractors directly from the model package:

```
from extract_features import extract, parse_url, valid_ip
from email_text_features import clean_email
from url_text_features import url_text
```

It then loads the three trained artifacts from `model/trained/`:

| Global | File | On failure |
|--------|------|------------|
| `model` + `feature_cols` | `phishing_model.joblib` + `features.txt` | **fatal** — no graceful fallback |
| `url_text_vec`, `url_text_clf` | `url_text_model.joblib` (a `(vectorizer, clf)` tuple) | `None` — URL text scoring silently disabled |
| `email_text_model` | `email_text_model.joblib` | `None` — email text scoring silently disabled |

`feature_cols` is the ordered feature list used to re-slice the feature dict
into a DataFrame row at prediction time (`score_url` → `predict_url`).

### 2.2 Host lists

`_load_hosts(name)` reads `model/lists/<name>` into a set of lowercased hosts
(empty set if the file is missing):

| Global | File | Purpose |
|--------|------|---------|
| `ALLOW` | `tranco_top1m.txt` | **Allowlist** — top-1M hosts considered trusted |
| `BLOCK` | `openphish_hosts.txt` | **Blocklist** — hosts known for phishing |

> `ALLOW` and `BLOCK` are snapshots baked into the model repo; they are loaded
> once at startup and never refreshed at runtime.

### 2.3 Static knowledge tables

| Constant | Content |
|----------|---------|
| `CHEAP_TLDS` | 23 low-cost, abuse-prone TLDs: `xyz top club online site live click link icu vip fun work space store buzz cyou rest token ga gq ml tk cf` |
| `HOMOGLYPHS` | 102 char→ASCII mappings: the full lowercase Cyrillic and Greek alphabets, extra Latin look-alikes (`ſ ı ł đ ð þ ß œ æ`), fullwidth ASCII, and digit→letter swaps (`1→l 0→o 3→e 4→a 5→s 7→t`) |
| `SUSPICIOUS_PHRASES` | 71 phishing-flavoured keywords (`account, login, verify, secure, bank, invoice, wallet, bitcoin, giftcard, reward, urgent, suspended, sale, ...`) |
| `OFFENSIVE_WORDS` | slur set used to flag hate-content domains |
| `BLACK_MARKET_WORDS` | drug/gambling/porn/payday/crypto-adjacent keywords |
| `URGENT_PHRASES` | 17 pressure-phrases for emails (`urgent, act now, verify your account, click here, you have won, ...`) |
| `GREETING_PATTERNS` | 11 generic greetings (`dear user, dear customer, dear valued customer, ...`) |
| `BRANDS` | 28 well-known brands → real domains (Amazon→amazon.com, Chase→chase.com, MetaMask→metamask.io, ...) |
| `SLDS` | 39 second-level-domain suffixes (`.co.uk .com.au .co.jp .co.za ...`) so `host_parts` can locate registrable domains |
| `TLD_WORDS` | `{com, net, org, co, info, biz, io}` — words that look like TLDs |
| `BAD_EXTENSIONS` | dangerous attachment suffixes: `.exe .scr .bat .vbs .js .jar .ps1 .lnk .docm .hta` |
| `DKIM_SELECTORS` | `["default","google","selector1","selector2","k1"]` tried when probing `_domainkey` records |

`BRANDS` deserves emphasis: nearly every "is this impersonating a brand" test in
the whole backend iterates this one dict, so adding a brand here automatically
improves domain heuristics, email spoof detection, and link-text mismatch checks
at once.

### 2.4 Verdict vocabulary

```python
VERDICT_COLORS     = {"safe": "#22c55e", "medium": "#f59e0b", "danger": "#ff3b3b", "critical": "#8b0000"}
VERDICT_LABELS     = {"safe": "Safe", "medium": "Suspicious", "danger": "Threat", "critical": "Critical"}
```

Risk bands (`risk_from_prob`, shared by URL and email):

| Probability | Risk | Label | Conclusion |
|-------------|------|-------|------------|
| `< 0.35` | `safe` | Safe | No significant phishing indicators detected. |
| `< 0.60` | `medium` | Suspicious | Some suspicious signals found. Review carefully before proceeding. |
| `< 0.80` | `danger` | Threat | Strong indicators of phishing. Do not enter any credentials. |
| `>= 0.80` | `critical` | Critical | High-confidence phishing URL. Blocked. |

---

## 3. Shared building blocks

### 3.1 Probability → verdict helpers

```python
def risk_from_prob(prob):        # the four bands above
def confidence_from_prob(prob):  # min(99, round(max(prob, 1-prob) * 100))
def build_verdict(risk):         # {"label", "color", "conclusion"} for the given risk
```

`confidence_from_prob` is always **50–99** by construction: it measures how far
the probability is from the 0.5 coin-flip, so a "safe" scan with prob 0.1 is
reported as 90% confident. It is capped at 99 so no scan claims 100%.

### 3.2 `predict_url(url) -> (prob, feats)`

Runs the feature extractor `extract(url)` (which performs live DNS lookups for
the domain features), re-indexes the result to the canonical `feature_cols`
order, and returns the positive-class probability of `phishing_model` plus the
raw feature dict. Every URL scan — including every link inside an email — goes
through this once.

### 3.3 Host parsing

```python
def host_parts(host) -> (subdomains, registrable, tld)
```

Splits a host into three parts, honouring the `SLDS` table so multi-label
national TLDs (`co.uk`) are treated as the *TLD*:

| Host | subdomains | registrable | tld |
|------|-----------|-------------|-----|
| `login.chase.com` | `["login"]` | `chase` | `com` |
| `a.b.bbc.co.uk` | `["a","b"]` | `bbc` | `co.uk` |
| `localhost` | `[]` | `""` | `""` (fewer than 2 labels) |

```python
def normalize(s)       # lowercases + maps every char through HOMOGLYPHS
def _edit_distance(a,b)  # Levenshtein; fast-paths to 99 if |len(a)-len(b)| > 2
```

`_edit_distance`'s early return is important: anything off by more than 2
characters is treated as "not a look-alike", which bounds the cost of the
brand-comparison loops (28 brands × a handful of labels each).

### 3.4 Allowlist helpers

```python
def _allowlisted(host)          # True if host OR any parent suffix is in ALLOW
def _allowlist_suffix_len(host) # #labels of the matching allowlisted suffix (0 if none)
```

`_allowlisted` is used everywhere: as the trusted-domain gate in URL scoring, as
a guard that suppresses the URL-text model, to decide whether redirect targets
and form actions are "trusted", and to decide whether a sender domain is
trusted.

### 3.5 The cache

```python
CACHE = {}
def cached(key, ttl, fn):   # in-memory dict; returns cached value if stored within TTL, else recomputes + stores
```

A plain dict with no eviction or cleanup thread. Used only for the slow,
repetitive network calls (see [§11](#11-caching--concurrency) for the TTL table).

---

## 4. URL scan pipeline

### 4.1 `score_url(url) -> (prob, feats, rule)`

This is the heart of URL classification. `rule` is either `None` (no hard
rule fired) or a `(prob, [reasons])` tuple whose reasons become user-facing
"indicators". The algorithm, in order:

1. **ML baseline.** `prob, feats = predict_url(url)`, `host` from `parse_url`.

2. **Hard signal — blocklist.** If `host` or its `registrable` part is in
   `BLOCK`: `prob = max(prob, 0.95)`, rule = *"Domain listed on known phishing
   blocklist (OpenPhish)"*, return immediately. A blocklisted domain can never
   be downgraded below 0.95 (Critical).

3. **Heuristics.** `heur = heuristic_risk(host)` — may fire 0..n reasons (see
   [§4.2](#42-heuristic_risk)). 

4. **Trusted-domain gate.** If `_allowlisted(host)`:
   - heuristic fired → `prob = max(prob, heur_prob)`, rule = `heur`.
   - heuristic silent → `prob = min(prob, 0.25)` and **return**. This is the
     critical false-positive suppressor: real domains under a top-1M suffix are
     treated as safe by default, because the learned models flag realistic URL
     shapes (`?q=...`, `?v=...`, `/products?id=5`) as phish. Only a *hard*
     heuristic flag can override the gate.

5. **Untrusted, no hard rule.** Query the URL-text model
   (`url_text_prob`, disabled for allowlisted/IP hosts) and **blend**:
   - heuristic fired → `prob = max(prob, heur_prob, text_prob)`, rule = `heur`.
   - neither fired → `prob = 0.6*prob + 0.4*text_prob` (weighted blend so one
     overconfident model can't win alone).

The `rule` returned here is surfaced in the API as the URL's `indicators` and,
for email links, each link's indicators.

### 4.2 `heuristic_risk(host) -> (prob, reasons) | None`

Returns `None` when nothing suspicious is found. When it fires, the base
probability is

```
prob = 0.62 + min(num_reasons, 3) * 0.05      # 0.62 | 0.67 | 0.72 | 0.77
prob = min(prob, 0.80)                          # capped; the 0.80 cap itself sits exactly on the critical boundary (risk bands use >= 0.80)
```

So a heuristic fires at 0.62–0.77, and 4+ simultaneous reasons land at exactly
0.80 — which is already `critical` under `risk_from_prob`.

**Allowlisted branch** (host under a top-1M suffix): only the *prefix* labels
(the part before the allowlisted suffix) are examined, and only for:

| Check | Reason string |
|-------|---------------|
| `normalize(label)` is a brand name | (silently *allowed* — e.g. `login.microsoft.com` is fine) |
| edit distance to a brand ≤ 2 | "Domain 'X' closely resembles the brand 'Y'" |
| brand embedded with `-` glue or a digit | "Brand 'Y' embedded inside domain 'X'" |
| label is a TLD word | "TLD-like word 'X' used as a subdomain label" |
| label is punycode (`xn--`) | "IDN/punycode encoded domain label" |

This is what catches brand-resembling prefixes bolted onto otherwise-trusted
domains (e.g. `paypal-verify.account.apple.com`: `paypal-verify` embeds the
brand while `apple.com` is allowlisted). Suspicious phrases/offensive words are
**not** scanned here.

**Non-allowlisted branch** (the general case): examines `subdomains +
registrable` labels:

| Check | Reason string |
|-------|---------------|
| label normalizes exactly to a brand, and is a **subdomain** | "Brand 'X' appears as a subdomain of an unrelated domain" |
| edit distance to a brand ≤ 2 | "Domain 'X' closely resembles the brand 'Y'" |
| brand embedded (`-` glue or digit) | "Brand 'Y' embedded inside domain 'X'" |
| subdomain label is a TLD word | "TLD-like word 'X' used as a subdomain label" |
| registrable is a TLD word **and** TLD is cheap | "TLD-like word 'X' used before a cheap TLD 'Y'" (e.g. `paypal-com.xyz`) |
| any label is punycode | "IDN/punycode encoded domain label" |
| a `SUSPICIOUS_PHRASES` token appears in the host | "Suspicious keyword 'X' in domain name" |
| an `OFFENSIVE_WORDS` token appears | "Offensive term 'X' in domain name" |
| a `BLACK_MARKET_WORDS` token appears | "Black-market keyword 'X' in domain name" |

Exemptions: if the host *is* the brand's real domain or a suffix of it
(`amazon.com`, `sub.amazon.com`), the brand check is skipped entirely.

### 4.3 `url_text_prob(url, host) -> float | None`

`None` if the URL-text model failed to load, the host is allowlisted, or the
host is a raw IP. Otherwise runs the TF-IDF vectorizer + classifier on
`url_text(url)` and returns the positive-class probability. Failures degrade to
`None` rather than crashing the scan.

### 4.4 `scan_url` endpoint (the URL orchestration)

`POST /api/scan/url` — validates the payload, then:

1. **Core scoring.** `prob, feats, rule = score_url(url)`.
2. **Parallel slow passes.** A 2-thread pool runs `enrich()` (WHOIS/SSL/redirect/
   RBL) and `page_scan()` (HTML fetch + signal extraction) simultaneously:
   - enrich waits up to 20 s, page scan up to 8 s; each degrades to neutral
     defaults on timeout/error.
3. **Page bump.** `prob = min(prob + page_bump, 0.99)` — page signals can only
   push the probability up, capped at 0.40 total bump and 0.99 final.
4. **Established-domain veto.** If **no hard rule fired** (rule is `None`) and
   the domain is 2+ years old (`_established_domain`):
   - valid TLS cert → `prob = min(prob, 0.34)` (force Safe).
   - otherwise → `prob = min(prob, 0.55)` (force at most Suspicious).
   Rationale: an old, HTTPS-served domain flagged only by statistical models is
   very unlikely to be phishing. The veto never fires on blocklist/heuristic
   hits because those are authoritative.
5. **Response.** risk, confidence, verdict, the four enrichment fields,
   `pageSignals`, and `indicators` = heuristic reasons + page signals.

The full response shape is in [§9](#9-api-reference).

---

## 5. Enrichment services

All four are network operations, each wrapped in try/except returning a neutral
default on any failure.

### 5.1 `ssl_check(host, timeout=2) -> "Valid" | "Invalid"`

Opens a raw TLS socket to port 443, fetches the peer certificate, and compares
`notBefore`/`notAfter` against `datetime.now()`. Any failure (no TLS, expired,
host mismatch in chain, network error) → `"Invalid"`.

### 5.2 `redirect_check(url, timeout=4) -> "Detected" | "None"`

Issues a GET with `allow_redirects=False`. A 3xx response → `"Detected"`.
This is distinct from the page scan's redirect detection: this is the raw
HTTP-level first hop.

### 5.3 `blacklist_check(host, timeout=4) -> "Flagged" | "Clear"`

Queries two DNSBLs by resolving `{host}.multi.surbl.org` and
`{host}.dbl.spamhaus.org`. If any A record starts with `127.` → `"Flagged"`.
A `NXDOMAIN`/`NoAnswer` means not listed; a DNS *timeout* short-circuits to
`"Clear"` (fail-open).

### 5.4 `domain_age(host, timeout=7) -> human string`

Runs `python-whois` inside a single-thread pool with a 7 s timeout (WHOIS
servers are notoriously slow/hang-y). The `creation_date` (first element if a
list) is normalised and formatted by age:

| Age | Format |
|-----|--------|
| < 1 day | `"X hours"` |
| < 90 days | `"X days"` |
| < 730 days | `"X months"` (÷30.44) |
| else | `"X.Y years"` (÷365.25) |

Any failure or future timestamp → `"Unknown"`.

### 5.5 `_established_domain(extra) -> bool`

True only if `domainAge` is a string containing "year" whose leading number is
≥ 2. Used exclusively by the veto in `scan_url`.

### 5.6 `enrich(url, host, https) -> dict`

Runs the domain-age, redirect and RBL checks — plus the TLS check for `https://`
URLs — in a 4-thread pool, each wrapped in `cached(...)`:

| Key | Source | Default | Cache TTL |
|-----|--------|---------|-----------|
| `domainAge` | `domain_age` | `"Unknown"` | 1800 s |
| `redirection` | `redirect_check` | `"None"` | 300 s |
| `blacklist` | `blacklist_check` | `"Clear"` | 600 s |
| `sslStatus` | `ssl_check` | `"Invalid"` | 300 s (only if URL is `https://`) |

Each future gets 12 s to finish; stragglers fall back to their default.

---

## 6. Page scan

### 6.1 Fetching

`fetch_page(url, timeout=4, max_bytes=1_000_000)` GETs the URL following
redirects, with `verify=False` (to tolerate phish-kit self-signed certs) and a
Windows desktop User-Agent. Returns `{"html", "final_url", "history"}` or
`None` for any HTTP status ≥ 400 or transport error. HTML is capped at ~1 MB.

### 6.2 Site labelling

`_page_site(target)` extracts a short site label from a URL (last two labels,
port-stripped, IP hosts returned as-is). `_page_target_trusted(target)` checks
whether the target host is itself allowlisted (top-1M) — the escape hatch so a
page that redirects to `google.com` isn't flagged.

### 6.3 `page_scan(url, host, prob, rule) -> (signals, bump)`

Skipped entirely when the host is allowlisted (already gated safe) or
`prob >= 0.85` (already critical — no need to fetch). On a successful fetch it
extracts, in order:

| Signal | Condition | Bump |
|--------|-----------|------|
| Redirect chain | `history` non-empty, final site ≠ my site, final site untrusted | +0.15 |
| Meta-refresh | `http-equiv=refresh` target ≠ my site, untrusted (first only) | +0.15 |
| JS redirect | `window/document.location = "http..."` target ≠ my site, untrusted (first only) | +0.15 |
| Credential fields | `<input type=password>` or name `password/passwd/card_number/cardnumber/card-num/cvv/cvc/ssn` | +0.25 |
| Credential-harvesting form | no explicit fields, but `ssn/social security/card number/cvv/cvc/credit card details` text + a `<form>`/`<input>` | +0.15 |
| Phish-kit pattern | a form and HTML < 2,500 chars | +0.10 |
| Form action mismatch | `<form action>` submits to a different, untrusted site | +0.20 |
| Title brand impersonation | `<title>` mentions a brand while the host is neither the brand's real domain nor a subdomain of it | +0.15 |

The bump is capped at **0.40** total. Every fired signal becomes a user-facing
`pageSignals` string and is merged into `indicators`.

> The short-page heuristic catches classic phish kits — a single HTML file
> (login form, no CSS, no content) cloned to a fake domain.

---

## 7. Email scan pipeline

### 7.1 `email_urls(content) -> [url]`

Extracts every `http(s)://...` substring via regex, de-duplicates while
preserving order, and trims trailing backticks/asterisks (markdown glue from
pasted text).

### 7.2 Spoofing

`from_domain(content)` pulls the sender domain out of a `From:` header.
`spoof_detected(content) -> "Yes" | "No"` fires on any of:

1. **From/Reply-To mismatch** — the two header domains differ.
2. **Service-account impersonation** — the From domain is not trusted
   (not allowlisted, not a brand real domain) *and* the local part contains
   `security`, `support`, `admin`, `service`, or `verify`.
3. **Brand spoofing** — `_domain_brand_spoof_reason(addr_domain)` returns a
   reason.

`_domain_brand_spoof_reason(domain)` is the brand matcher for sender domains:
it exempts the real brand domain and its subdomains (`microsoft.com`,
`login.microsoft.com`), then checks every label — and every hyphen-split token
of every label — for an exact brand match, an edit-distance ≤ 2 look-alike, or
an embedded brand (`-glue` or digit). Returns a human reason string or `None`.

### 7.3 Attachments & urgency

- `grammar_hits(content)` counts how many of the 17 `URGENT_PHRASES` appear.
- `attachment_count(content)` finds `word.ext`-shaped filenames and counts those
  ending in a `BAD_EXTENSIONS` suffix (executables, scripts, `.docm`, `.hta`...).

> **Dead code:** `grammar_level(content)` (line 731) maps `grammar_hits` to a
> severity string (`None`/`Minor`/`Moderate`/`High`) but is **never called** —
> `scan_email` uses `grammar_report()["level"]` instead. It is a leftover helper
> and can be removed safely.

### 7.4 Sender authentication (SPF / DMARC / DKIM)

`sender_auth(domain)` runs three DNS probes in parallel (3-thread pool,
4 s overall):

| Record | Lookup | State |
|--------|--------|-------|
| SPF | TXT of the domain itself | `present` if any record contains `v=spf1`, else `absent` |
| DMARC | TXT of `_dmarc.<domain>` | `present` if any record contains `v=dmarc1` (case-insensitive) |
| DKIM | TXT of `<selector>._domainkey.<domain>` for 5 known selectors | `present` if any record looks like a DKIM key |

Each probe reports `unknown` on a DNS error or timeout. Only the **SPF** probe
can report `domain_missing` (the sender domain itself does not resolve —
NXDOMAIN); on a dead domain the DMARC and DKIM probes simply read `absent`. A
missing/raw-IP sender domain returns `None` (no auth checks).

`auth_signals(auth, domain, prob)` converts auth results into indicators **only
when it matters**:

- `spf == "domain_missing"` → *"Sender domain 'X' does not resolve in DNS"*,
  bump **+0.20** — this fires regardless of the email's score.
- If the email is already suspicious (`prob >= 0.5`): ≥ 2 of SPF/DMARC/DKIM
  absent → bump **+0.20**; exactly 1 absent → bump **+0.10**.
- A low-risk email with absent records gets no bump (missing auth alone isn't
  damning).

### 7.5 Grammar & manipulation analysis

Three independent grammar detectors feed `grammar_report(content)`:

**1. `grammar_issues(content)`** — hand-written checks:

| Check | Example issue string |
|-------|----------------------|
| Generic greeting (11 patterns) | "Generic greeting ('dear user') — no personalization" |
| ≥ 2 sentences starting lowercase | "N sentences start with a lowercase letter" |
| Punctuation missing a following space (emails/URLs masked first) | "N punctuation mark(s) missing a following space" |
| ≥ 2 exclamation marks | "N exclamation marks (emotional pressure)" |
| `!!` / `??` | "Multiple consecutive punctuation marks" |
| 3+ repeated chars | "Excessive character repetition (e.g. 'xxx')" |
| ALL-CAPS sentences | "N sentence(s) in ALL CAPS" |

**2. `spell_mistakes(content)`** — `pyspellchecker` on 3+-letter words; skips
words that are capitalized in the source (proper nouns), caps at 8. Only runs
on ≥ 4 words.

**3. `languagetool_issues(content)`** — posts the first 4,000 chars to the
public LanguageTool API (`en-US`), keeps only matches in Grammar / Style /
Spelling / Typographical / Punctuation / Capitalization / Semantics categories,
formats as `[Category] message`, caps at 10. Cached 30 min by content hash;
network failures degrade to `[]`.

`grammar_report(content)` merges all three:

```
total  = len(issues) + len(lt_issues)
level  = None if total==0; Minor if <=2; Moderate if <=5; High otherwise
prob   = 0.0 if level == "None" else min(0.25 + min(total, 6) * 0.07, 0.85)
```

So grammar manipulation alone can push at most 0.85 (Threat). Issue strings are
capped at 10 in the response.

### 7.6 Link-text mismatch

`extract_anchors(content)` finds markdown `[label](url)` and `<a href>` pairs,
sanitising labels to plain words. `link_text_mismatch(anchors)` flags any link
whose *visible text* mentions a brand, as long as the brand's real domain is
neither the target host nor a suffix of it (so links to `login.paypal.com` are
fine):

> "Link text says 'paypal' but the target host is 'paypal-verify.info'"

Each (brand, host) pair is reported once.

### 7.7 `heuristic_prob(content)`

A quick rule-only email score: `0.20 + min(urgent_phrase_hits, 2) * 0.15`,
plus **+0.25** if spoofing is detected, capped at 0.95.

### 7.8 `email_text_prob(content)`

The positive-class probability of `email_text_model` on
`clean_email(content)`. `None` if the model isn't loaded or prediction fails.

### 7.9 `scan_email` endpoint (the combination rule)

`POST /api/scan/email`:

1. **Links.** Every URL (capped at the first 10) is scored with `score_url` and
   added to `links` with its own risk, confidence, verdict label and indicators.
   `suspicious_links` counts links with `prob >= 0.55`; `max_link_prob` is the
   strongest single link.
2. **Independent evidence.** `attachments`, `spoof`, `grammar`, plus
   `link_text_mismatch` indicators.
3. **The email's own ML score.** `text_model_prob`.
4. **Sender trust.** `sender_domain` from the From header; `trusted_sender` if
   the domain is allowlisted or is a brand real domain (or suffix of one).
5. **Combination.** Define `explicit = max(max_link_prob, grammar.prob, heuristic_prob)`.

```
if text_model is unavailable:            prob = explicit
elif trusted_sender AND explicit < 0.5:  prob = max(explicit, min(text_model, 0.34))
elif text_model >= 0.5 OR explicit >= 0.5: prob = max(explicit, text_model)
else:                                    prob = max(explicit, min(text_model, 0.34))
```

The trusted-sender branch **caps the email text model at 0.34** — a real brand
domain writing a somewhat-odd email must not be pushed past Safe by a language
model, when no other signal is strong. The explicit evidence (a bad link,
spoofing, grammar) always wins where it's strong.

6. **Auth bump.** `auth = sender_auth(...)` (cached 1 h) → `auth_signals`
   bump → `prob = min(prob + bump, 0.99)`.
7. **Response.** risk, confidence, verdict, `suspiciousLinks`,
   `suspiciousAttachments`, `grammarManipulation` level, `spoofingDetected`,
   `grammarIssues`, `textModelRisk` (percentage string or null), `senderDomain`,
   `spfStatus`/`dmarcStatus`/`dkimStatus`, the per-link array, and the merged
   `indicators` (link-text mismatch + spoof reason + top 4 grammar issues +
   auth indicators).

---

## 8. Minigame leaderboard persistence

The three minigames (phish-or-legit, link-dismantler, threat-hunt) submit
results to `POST /api/minigame/result`, persisted to
`backend/data/minigame_scores.json`:

- Validation: `game` must be in `MINIGAME_TYPES`, `difficulty` in
  `{"easy","normal","hard"}` (default `normal`); `score`/`total`/`bestStreak`
  coerced to ints with sane floors (`score ≥ 0`, `total ≥ 1`); `name` truncated
  to 24 chars, default `"Guest"`.
- A `threading.Lock` serialises read-modify-write so concurrent submissions
  can't corrupt the file.
- Each entry is `{name, score, total, streak, ts}` with a UTC ISO timestamp.
  Entries are sorted `(-score, -streak)` and trimmed to the **top 20**.
- The response includes the 1-indexed `rank` the new score achieved against the
  *prior* leaderboard, and `top` = how many entries are kept.
- `GET /api/minigame/leaderboard` returns the top **5** of each of the 3×3
  game/difficulty buckets.

This is the only server-side state that is ever written.

---

## 9. API reference

All endpoints are served by Flask on `127.0.0.1:3000`, CORS-enabled
(`flask_cors.CORS(app)` with default permissive settings). All requests/responses
are JSON.

### 9.1 `POST /api/scan/url`

Request:
```json
{ "url": "https://myqr-hosting.xyz/login" }
```

Errors: `400 {"error":"Missing 'url' field"}` · `400 {"error":"URL must start with http:// or https://"}`

Response (a neutral, non-allowlisted domain with no heuristic/page signals, scored
by the ML models only — `risk`/`confidence` are always consistent, e.g. a
`medium` result must have confidence in 50–65):
```json
{
  "risk": "medium",
  "confidence": 58,
  "verdict": { "label": "Suspicious", "color": "#f59e0b", "conclusion": "Some suspicious signals found. Review carefully before proceeding." },
  "domainAge": "Unknown",
  "sslStatus": "Invalid",
  "redirection": "None",
  "blacklist": "Clear",
  "pageSignals": [],
  "indicators": []
}
```

### 9.2 `POST /api/scan/email`

Request:
```json
{ "content": "From: ... \n\nDear user, ..." }
```

Error: `400 {"error":"Missing 'content' field"}`

Response (a spoofed sender email with one bad link; `explicit` ≈ 0.72, the email
text model at 0.74 wins the max, and all three sender-auth records are present
so no auth bump applies):
```json
{
  "risk": "danger",
  "confidence": 74,
  "verdict": { "label": "Threat", "color": "#ff3b3b", "conclusion": "Strong indicators of phishing. Do not enter any credentials." },
  "suspiciousLinks": "1",
  "suspiciousAttachments": "0",
  "grammarManipulation": "Moderate",
  "spoofingDetected": "Yes",
  "grammarIssues": ["Generic greeting ('dear user') — no personalization", "3 exclamation marks (emotional pressure)", "1 sentence(s) in ALL CAPS"],
  "textModelRisk": "74%",
  "senderDomain": "support.paypal-verify.net",
  "spfStatus": "present",
  "dmarcStatus": "present",
  "dkimStatus": "present",
  "links": [
    {
      "url": "https://paypal-verify.net/login",
      "host": "paypal-verify.net",
      "risk": "danger",
      "confidence": 72,
      "verdict": "Threat",
      "indicators": ["Brand 'paypal' embedded inside domain 'paypal-verify'", "Suspicious keyword 'verify' in domain name"]
    }
  ],
  "indicators": ["Link text says 'paypal' but the target host is 'paypal-verify.net'", "From domain 'support.paypal-verify.net' embeds brand 'paypal' but is not 'paypal.com'", "Generic greeting ('dear user') — no personalization"]
}
```

### 9.3 `POST /api/minigame/result`

Request:
```json
{ "game": "phish-or-legit", "difficulty": "hard", "score": 9, "total": 10, "bestStreak": 9, "name": "Player1" }
```

Errors: `400 {"error":"Invalid game"}` · `400 {"error":"Invalid difficulty"}` · `400 {"error":"Invalid score fields"}`

Response: `{"ok": true, "game": "phish-or-legit", "difficulty": "hard", "rank": 2, "top": 20}`

### 9.4 `GET /api/minigame/leaderboard`

Response: `{"leaderboard": {"link-dismantler": {"easy": [ ...up to 5 entries... ], "normal": [...], "hard": [...]}, ...}}`

---

## 10. Scoring model summary

Every final probability is the outcome of monotonic bump/max/min operations —
there is no subtraction anywhere except the allowlist cap (`min(prob, 0.25)`)
and the veto caps. The caps that keep the system honest:

| Operation | Cap |
|-----------|-----|
| Heuristic probe (`heuristic_risk`) | 0.62–0.77 → 0.80 max |
| Page-scan bump | +0.40 max, summed |
| Final URL/email probability | 0.99 max |
| Veto (2+ yr domain, valid TLS) | prob ≤ 0.34 (Safe) |
| Veto (2+ yr domain, no valid TLS) | prob ≤ 0.55 (Suspicious) |
| Grammar manipulation score | 0.25 + 6×0.07 → 0.85 max |
| Email heuristic score (`heuristic_prob`) | 0.95 max |
| Trusted-sender text-model cap | 0.34 |
| Confidence | 99 max |

Bumps from page signals and missing auth records only ever *raise* risk;
heuristic/blocklist rules never get cancelled. Only the two designed
downgrades (allowlist gate, established-domain veto) can lower a score, and
neither applies when an authoritative rule (blocklist / heuristic) has fired.

---

## 11. Caching & concurrency

### 11.1 Cache TTLs (`cached`)

| Key prefix | Content | TTL |
|------------|---------|-----|
| `age:<host>` | WHOIS domain age | 1800 s |
| `redir:<url>` | first-hop redirect check | 300 s |
| `bl:<host>` | DNSBL status | 600 s |
| `ssl:<host>` | TLS cert validity | 300 s |
| `lt:<content-hash>` | LanguageTool results (md5 of text) | 1800 s |
| `auth:<domain>` | SPF/DMARC/DKIM result | 3600 s |

Cache entries are keyed with a namespace prefix and never expire beyond their
TTL, but there is **no size limit or eviction** — long-running servers will
accumulate entries (mitigated in practice by bounded domain/URL diversity).

### 11.2 Thread pools

| Call site | Pool size | Purpose |
|-----------|-----------|---------|
| `enrich` | 4 | WHOIS / SSL / redirect / RBL in parallel |
| `domain_age` | 1 | isolate a slow WHOIS call with a timeout |
| `sender_auth` | 3 | SPF / DMARC / DKIM in parallel |
| `scan_url` | 2 | enrich + page scan in parallel |
| Flask app | `threaded=True` | each HTTP request on its own thread |

### 11.3 Timeouts (all network calls)

| Call | Timeout |
|------|---------|
| `requests.get` (redirect check) | 4 s |
| `requests.get` (page fetch) | 4 s |
| `requests.post` (LanguageTool) | 8 s |
| `ssl_check` socket | 2 s |
| `domain_age` pool | 7 s |
| `sender_auth` pool | 4 s |
| `_lookup_txt` (dnspython) | 4 s (DKIM probes 3 s) |
| `enrich` per-future | 12 s |
| `enrich` / `page_scan` at endpoint | 20 s / 8 s |

Every slow path has a defensive `except` returning a neutral default, so a
dead WHOIS server or unreachable website can never crash or hang a scan.

---

## 12. Operational & security notes

- **Self-signed/HTTPS tolerance.** The two page/redirect fetchers
  (`redirect_check`, `fetch_page`) call `requests` with `verify=False`, and the
  app suppresses urllib3's InsecureRequestWarning. This is intentional (phish
  kits are often served over self-signed TLS), but means the backend performs
  **no certificate validation** on fetched pages — it relies on `ssl_check`
  only for the *scanned* host's TLS certificate. (The LanguageTool POST uses
  default certificate verification.)
- **Localhost only.** The server binds `127.0.0.1:3000` — reachable only from
  the machine it runs on. There is no authentication layer on any endpoint.
- **Public third-party APIs.** LanguageTool is a public, rate-limited API;
  `python-whois` and the DNSBLs depend on external network reachability. The
  email grammar analysis therefore depends on outbound internet access to
  `api.languagetool.org`.
- **Two hard fails.** If `phishing_model.joblib` or `features.txt` is missing,
  the app crashes at startup. The two *text* models degrade gracefully to `None`
  instead.
- **DNS-dependent scoring.** `extract()` makes live DNS queries, and
  `blacklist_check`/`sender_auth` make DNS queries too. In an offline
  environment every such signal degrades to its neutral default and the scanner
  becomes effectively heuristic-only.
- **Single-writer JSON.** Minigame results are guarded by a process-local lock;
  with multiple backend processes the file could race, but the app is designed
  to run as a single process.
- **Determinism.** All heuristic probes, bump caps, vetoes and blending weights
  are constants — the *only* randomness in the system comes from the external
  services (DNS state, LanguageTool, WHOIS freshness), not from the logic.
