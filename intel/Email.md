# PhisDetect — Email Detection: Complete Reference

> Everything about how an email gets scanned: the six analysis layers (grammar, links,
> spoofing, sender authentication, the TF-IDF text model, and keyword heuristics), how the
> scores are combined into one probability, the API contract, the training corpus and
> pipeline, the frontend rendering, and the verification results.
>
> Code lives in `/home/aditya/AI project/model/`. All function names below match
> `server.py` / `email_text_features.py` / `update_email_data.py` /
> `train_email_text_model.py` exactly so you can jump to them.

---

## 1. The one-minute summary

Scanning an email produces **one probability** `prob ∈ [0, 1]` that the email is phishing,
plus a list of human-readable **indicators**. The probability is computed by `scan_email()`
(`server.py`) from six independent layers:

1. **Per-link scan** — every `http(s)` URL found in the email is run through the full URL
   pipeline (`score_url()`), which itself combines the RF model, URL-text model, heuristics,
   allowlist/blocklist gates, live DNS/WHOIS/SSL enrichment and a page content scan.
2. **Grammar & language manipulation** — generic greetings, missing spaces, ALL-CAPS
   sentences, exclamation pressure, repeated characters, spelling errors (pyspellchecker),
   and a live LanguageTool grammar check.
3. **Spoof detection** — `From:`/`Reply-To:` mismatch, service-word local parts on untrusted
   domains (`security@…`), and **brand-spoofed From domains** (`account-alert@microsoft-
   securityverify.com`).
4. **Sender authentication** — live DNS checks for SPF, DMARC and DKIM on the sender domain;
   an NXDOMAIN sender or missing auth records push the score up — but only when the email is
   already suspicious.
5. **Email-text TF-IDF model** — a LogisticRegression trained on real phishing mboxes,
   SpamAssassin ham, and ~8,000 modern synthetic emails (sign-in reviews, 2FA codes, order
   confirmations, payment scams, lottery, package redelivery…).
6. **Keyword heuristics** — `URGENT_PHRASES` hits and a base spoof bump.

The layers are combined with a **trusted-sender clamp**: if the sender domain is a real brand
or allowlisted, the text model cannot alone push the email to danger unless another explicit
signal already does. The final number is mapped to a **verdict tier** and a **confidence
percentage** (never 100%).

---

## 2. Risk model: tiers, thresholds, confidence

Identical to the URL pipeline — shared `risk_from_prob()` / `confidence_from_prob()` in
`server.py`.

| `prob` | `risk`    | Verdict label | Conclusion shown to user |
|--------|-----------|---------------|--------------------------|
| `< 0.35`  | `safe`    | Safe          | "No significant phishing indicators detected." |
| `[0.35, 0.60)` | `medium` | Suspicious | "Some suspicious signals found. Review carefully…" |
| `[0.60, 0.80)` | `danger` | Threat     | "Strong indicators of phishing. Do not enter any credentials." |
| `≥ 0.80` | `critical` | Critical    | "High-confidence phishing URL. Blocked." |

```python
def confidence_from_prob(prob):
    return min(99, round(max(prob, 1 - prob) * 100))
```

**Confidence is never 100%.** A `critical` email at `prob = 0.99` shows 99%; a `safe` email at
`prob = 0.20` also shows 80% (confidence in the *verdict*, not the probability). The `verdict`
field is `build_verdict(risk)` → `{label, color, conclusion}` from `VERDICT_COLORS` /
`VERDICT_LABELS` / `VERDICT_CONCLUSIONS`.

---

## 3. Pipeline overview

```
POST /api/scan/email   { "content": "<pasted email headers + body>" }
  |
  v
scan_email(content) --------------------------------  (synchronous)
  |- email_urls(content)      -> first 10 URLs, each scored by score_url(url)
  |     |- suspiciousLinks    = count of links with prob >= 0.55
  |     `- max_link_prob      = highest link probability
  |- attachment_count(content)-> suspicious attachments (.exe .scr .bat .vbs .js ...)
  |- spoof_detected(content)  -> "Yes"/"No"  (header mismatch + brand spoof)
  |- grammar_report(content)  -> {level, issues, prob}  (grammar + spelling + LanguageTool)
  |- heuristic_prob(content)  -> 0.20 base + urgent-phrase hits + spoof bump
  |- email_text_prob(content) -> TF-IDF text model probability (clean_email -> predict_proba)
  |- combine: trusted-sender clamp picks how much text-model weight to trust
  |- sender_auth(from_domain)-> SPF/DMARC/DKIM DNS lookups (3-thread pool, ~4s bound)
  |     `- auth_signals()     -> NXDOMAIN / missing-record indicators + bump (capped +0.20)
  |- prob = min(prob + auth_bump, 0.99)
  `- JSON response (risk, confidence, verdict, links[], indicators[], auth status...)
```

The pure-computation layers (grammar, spelling, heuristics, text model) are fast. The two
network layers — **per-link scanning** (reuses the URL pipeline, including live DNS/WHOIS
enrichment and the landing-page fetch) and **sender auth DNS lookups** — dominate the latency.
`sender_auth` is cached per domain for 3600s; LanguageTool results are cached 1800s; URL
enrichment is cached per host per check.

---

## 4. Layer 1 — Grammar & language manipulation

### 4.1 `grammar_issues(content)` — local regex rules

Runs on the raw pasted content (not `clean_email`). Produces a list of specific issue strings:

| Rule | Detection | Example indicator |
|------|-----------|-------------------|
| Generic greeting | `GREETING_PATTERNS` substring match (`dear user`, `dear customer`, `dear member`, `dear friend`, `dear sir`, `dear sir/madam`, `dear account holder`, `dear valued customer`, `hello user`, `hello customer`, `dear beneficiary`) | "Generic greeting ('dear user') — no personalization" |
| Lowercase sentence starts | `[.!?]\s+([a-z])`, needs **≥ 2** hits | "3 sentences start with a lowercase letter" |
| Missing space after punctuation | emails → ` EMAIL ` and URLs → ` URL ` first, then `(?<=[a-z])[,;](?=[a-zA-Z])` and `(?<=[a-zA-Z0-9])\.(?=[a-zA-Z])` (sanitizing emails/URLs avoids `example.com` FPs) | "2 punctuation mark(s) missing a following space" |
| Exclamation pressure | `content.count("!") >= 2` | "4 exclamation marks (emotional pressure)" |
| Consecutive punctuation | `"!!"` or `"??"` in content | "Multiple consecutive punctuation marks" |
| Character repetition | `(.)\1{2,}` | "Excessive character repetition (e.g. 'aaa')" |
| ALL CAPS | any sentence (≥ 5 chars, split by `[.!?]+\s+`) that is fully uppercase | "2 sentence(s) in ALL CAPS" |

### 4.2 `spell_mistakes(content)` — pyspellchecker

- Extracts words `[a-zA-Z]{3,}`; needs ≥ 4 words or returns `[]`.
- `spell.unknown(lowered)` (English word list).
- **Proper-noun fix (2026-08-06):** a word is *not* counted as a misspelling if any original
  token is Title-Case but not fully uppercase (`Aditya`, `Toronto`, `Windows`). Before this
  fix, proper nouns were flagged as spelling errors and drove the grammar probability up to
  0.39, flipping benign sign-in emails to medium — the Netflix FP.
- Returns the first **8** unknown words.

### 4.3 `languagetool_issues(content)` — external grammar API

- `POST https://api.languagetool.org/v2/check` with `text=content[:4000]`, `language=en-US`,
  8s timeout. Any failure returns `[]` (never penalizes).
- Keeps only matches whose category is Grammar / Style / Spelling / Typographical /
  Punctuation / Capitalization / Semantics; renders `"[Category] shortMessage"`, max 10.
- **Cached 1800s** under key `"lt:" + md5(content)` so identical emails aren't re-checked.

### 4.4 `grammar_report(content)` — aggregation

```python
issues   = grammar_issues(content)
misspelled = spell_mistakes(content)         # -> "N spelling error(s) detected"
lt_issues  = languagetool_issues(content)
total    = len(issues) + len(lt_issues)

level = "None"  if total == 0
      = "Minor" if total <= 2
      = "Moderate" if total <= 5
      = "High"  otherwise

prob  = 0.0 if level == "None"
      = min(0.25 + min(total, 6) * 0.07, 0.85)
```

So a single issue = `0.32`, two = `0.39`, three = `0.46`, four = `0.53`, five = `0.60`,
six+ = `0.67` → `0.85` max. The returned `issues` list (≤ 10) feeds the API and the UI.

---

## 5. Layer 2 — Link analysis

### 5.1 `email_urls(content)`

`URL_RE = r"https?://[^\s<>\"')\]]+"` (ignorecase) over the raw content, deduplicated preserving
order. Scan the **first 10** URLs.

### 5.2 Per-link scoring (reuses the whole URL pipeline)

```python
for url in urls[:10]:
    prob, _, rule = score_url(url)      # RF + text + heuristics + gates (see URL.md)
    links.append({ url, host, risk, confidence, verdict, indicators: rule[1] })
```

Every link gets the full `score_url()` treatment — blocklist, allowlist gate, brand
heuristics, URL-text model, enrichment veto — so a phish link inside an otherwise-clean body is
caught. `suspicious_links = count(link_probs >= 0.55)`. `max_link_prob` becomes the *explicit*
signal used in the final combination (§10).

### 5.3 `extract_anchors(content)` + `link_text_mismatch(anchors)`

Anchors are parsed two ways:
- Markdown: `[label](https://...)`
- HTML: `<a href="https://...">label</a>` (labels have tags stripped)

`link_text_mismatch` fires when a **brand name appears in the link text** but the target host is
**not** the brand's real domain (and not a subdomain of it):

> "Link text says 'paypal' but the target host is 'secure-login-verify.tk'"

This catches the classic "click **PayPal** to sign in → goes to an unrelated host" trick without
flagging `paypal.com` links inside a legit `paypal` email. Deduplicated per `(brand, target)`.

### 5.4 `attachment_count(content)`

Regex for `word.ext` tokens ending in `BAD_EXTENSIONS =
(.exe .scr .bat .vbs .js .jar .ps1 .lnk .docm .hta)` → `suspiciousAttachments`. (Best-effort:
counts tokens in text, not MIME parts — pasted content has no attachment bodies.)

---
## 6. Layer 3 — Spoof detection

### 6.1 `spoof_detected(content)` — the three checks

Returns `"Yes"` / `"No"` from three independent rules:

1. **`From:` / `Reply-To:` domain mismatch** — `from:\s*(\S+@\S+)` vs `reply-to:\s*(\S+@\S+)`;
   if the domains differ → `"Yes"`.
2. **Service-word local part on an untrusted domain** — `From: security@…`, `support@…`,
   `admin@…`, `service@…`, `verify@…`. Only fires when the From domain is **not** trusted
   (not allowlisted, not a real brand domain/subdomain). This is why `support@outlook.com` is
   correctly *not* flagged.
3. **Brand-spoofed From domain** — delegated to `_domain_brand_spoof_reason()` (below).

### 6.2 `_domain_brand_spoof_reason(domain)` — the brand machinery

Runs the same brand/typosquat logic the URL layer uses on the **From domain**. `BRANDS` maps
28 brand names → real domains (`amazon.com`, `paypal.com`, `microsoft.com`, `netflix.com`,
`coinbase.com`, `metamask.io`, …). For each brand:

- **Exempt** the real domain and its subdomains: `domain == real or domain.endswith("." + real)`.
  (`microsoft.com`, `login.microsoft.com`, `support.apple.com` are never spoofs.)
- **Exact brand as a label of an unrelated domain** — `microsoft-securityverify.com`: the label
  `microsoft` normalizes to `microsoft` and its *parent* is not the real domain → spoof.
- **Close resemblance** — `_edit_distance(normalize(label), brand) <= 2` (Levenshtein):
  `paypol`, `amazoon`, `netflixx`, `faceb00k`.
- **Embedded brand** — label is longer than the brand, contains the brand, and has a `-`
  prefix/suffix/infix or **any digit**: `microsoft-securityverify.com`, `paypal-verify.com`.
- **Homoglyphs** — `normalize()` maps Cyrillic/Greek confusables (а→a, р→p, ο→o, і→i, ѕ→s),
  full-width Latin (ａ→a), and digit-swaps (1→l, 0→o, 3→e, 4→a, 5→s, 7→t), so
  `mіcrosoft.com` (Cyrillic і) and `paypa1.com` are caught.

The specific reason string becomes the email indicator:

> "From domain 'account-alert@microsoft-securityverify.com' contains brand 'microsoft' but is
> not 'microsoft.com'"

Verified: user's Microsoft phish → spoof `Yes` (reason shown), netflix/paypal phish → `Yes`,
legit `msalerts@microsoft.com` / `sarah@example.com` / `gmail.com` → `No`.

### 6.3 `from_domain(content)`

Extracts just the From address's domain (lowercased) for auth checks — reused by
`auth_signals` and the trusted-sender clamp.

---

## 7. Layer 4 — Sender authentication (SPF / DKIM / DMARC)

Added in Tier 2 Item 4. Uses real DNS (dnspython) to check the *sender domain's* records.

### 7.1 `_lookup_txt(name, timeout=4)`

One TXT lookup → `(records, state)` with state ∈ `{ok, none, error}`:
- result → `(texts, "ok")`
- `NXDOMAIN` → `([], "none")`
- `NoAnswer` → `([], "ok")` (domain resolves, just no TXT)
- anything else (timeout, no nameserver…) → `([], "error")` — never a false flag.

### 7.2 `sender_auth(domain, timeout=4)`

Runs three lookups in a `ThreadPoolExecutor(max_workers=3)` bounded to ~4s total
(`shutdown(wait=False)` so lingering sockets never block the response). Returns
`{spf, dmarc, dkim}` with values `present | absent | domain_missing | unknown`, or `None` when
there is no usable domain or the domain is an IP literal.

| Record | Lookup | Present if |
|--------|--------|-----------|
| **SPF** | TXT on `<domain>` | any record contains `v=spf1` |
| **DMARC** | TXT on `_dmarc.<domain>` | any record contains `v=dmarc1` |
| **DKIM** | TXT on `{selector}._domainkey.<domain>` for selectors `default, google, selector1, selector2, k1` | any record has `v=dkim1` or ` p=` / starts `p=` (a published public key) |

- `state == "none"` on the SPF lookup → `domain_missing` (the whole domain is NXDOMAIN — a
  genuine spoof signal, e.g. `budget.wa.gov`).
- `state == "error"` → `unknown` (never treated as missing).
- Result is **cached 3600s** per domain (`"auth:<domain>"`), so repeat scans of the same sender
  are instant.

### 7.3 `auth_signals(auth, domain, prob)` — the gating rule

```python
if auth.get("spf") == "domain_missing":
    indicator "Sender domain '<d>' does not resolve in DNS"
    bump = max(bump, 0.20)          # unconditional
if prob < 0.5:
    return indicators, bump         # don't flag missing records on clean-looking emails
absent = [k for k in ("spf","dmarc","dkim") if auth.get(k) == "absent"]
if len(absent) >= 2:
    indicator "Sender domain '<d>' publishes no SPF/DMARC/DKIM records"
    bump = max(bump, 0.20)
elif len(absent) == 1:
    indicator "Sender domain '<d>' has no <K> record"
    bump = max(bump, 0.10)
```

Key design decisions:
- **NXDOMAIN sender → +0.20, always** (no DNS at all = strong spoof signal).
- **Missing SPF/DMARC/DKIM only counts when the email is already suspicious** (`prob >= 0.5`
  guard) — small legit sites routinely lack these records, so they must not flag on their own.
- `unknown` is never counted as absent.

Response fields `senderDomain`, `spfStatus`, `dmarcStatus`, `dkimStatus` are rendered on the
frontend.

---

## 8. Layer 5 — Email-text TF-IDF model

### 8.1 `clean_email(raw)` (`email_text_features.py`)

One shared normalizer used **identically** at train and serve time (both call it on the same
kind of input):

1. `strip_html` — block tags (`br p div tr li …`) → space, all tags → space, `html.unescape`.
2. Quoted-reply lines (start with `>` or `|`) → space (`QUOTED_RE`).
3. URLs → ` URL ` (token), emails → ` EMAIL `, number runs → ` NUM `.
4. Lowercase; everything non-`[a-z\s]` → space; collapse whitespace; strip.

The corpus strings and the live payload are both `record_text(subject, body)` =
`"subject: <subject> \n <body>"` — at train time this is built from parsed mbox messages, at
serve time the pasted content is normalized as-is.

### 8.2 Architecture

`email_text_model.joblib` is a scikit **pipeline**:

```python
make_pipeline(
    TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2,
                    max_features=200000, sublinear_tf=True),
    LogisticRegression(C=1.0, max_iter=1000, class_weight="balanced"),
)
```

Word unigrams+bigrams over the cleaned text, sublinear TF, class-balanced LR.

### 8.3 Serving (`email_text_prob(content)`)

```python
def email_text_prob(content):
    if email_text_model is None: return None          # model failed to load
    return float(email_text_model.predict_proba([clean_email(content)])[0][1])
```

Any exception → `None` (never crashes the request; the other layers carry the verdict). The
model is loaded at startup in a `try/except` (`server.py`), so the server still runs if the
joblib is missing.

---

## 9. Layer 6 — Keyword heuristics

```python
def heuristic_prob(content):
    hits = grammar_hits(content)          # URGENT_PHRASES count in lowercase body
    prob = 0.20 + min(hits, 2) * 0.15     # 0.20 / 0.35 / 0.50
    if spoof_detected(content) == "Yes":
        prob += 0.25
    return min(prob, 0.95)
```

`URGENT_PHRASES` (17): `urgent, immediately, act now, verify your account, verify your
identity, suspended, account locked, unusual activity, security alert, password expired,
click here, you have won, claim your prize, limited time, update your payment, confirm your
details, your account will be closed`. This mirrors the same list used to seed the synthetic
training data (`update_email_data.py`).

So a typical phish that says "verify your account immediately" (2 hits → 0.50) and is spoofed
(→ +0.25) starts at `0.75` before any other layer runs.

---
## 10. Score combination in `scan_email()` — the trusted-sender clamp

This is the heart of the email verdict. After all layers compute their probabilities:

```python
text_model_prob = email_text_prob(content)
sender_domain   = from_domain(content)
trusted_sender  = bool(sender_domain) and (
    _allowlisted(sender_domain) or
    any(sender_domain == real or sender_domain.endswith("." + real)
        for real in BRANDS.values()))

explicit = max(max_link_prob, grammar["prob"], heuristic_prob(content))

if text_model_prob is None:
    prob = explicit
elif trusted_sender and explicit < 0.5:
    prob = max(explicit, min(text_model_prob, 0.34))    # clamp trusted senders
elif text_model_prob >= 0.5 or explicit >= 0.5:
    prob = max(explicit, text_model_prob)                # strong signal wins
else:
    prob = max(explicit, min(text_model_prob, 0.34))    # weak text capped
```

Then the auth bump is applied once:

```python
auth_indicators, auth_bump = auth_signals(auth, sender_domain, prob)
prob = min(prob + auth_bump, 0.99)
```

Rules of thumb:

- **Trusted sender + no explicit signal ≥ 0.5** → the text model is capped at **0.34**
  (mirrors the URL allowlist clamp). A legit email from `msalerts@microsoft.com` with
  security vocabulary can no longer be flagged by text alone. (Before the clamp this exact
  case scored danger 67%; now safe.)
- **Any strong signal** (text ≥ 0.5, a suspicious link ≥ 0.5, grammar prob ≥ 0.5, or
  heuristic ≥ 0.5) → the layers combine by `max()`, so real phish still hits critical 99%.
- **Untrusted senders** keep full text-model contribution — a phish from a random domain is
  still caught even if it has perfect grammar and no links.
- `textModelRisk` in the response shows the *raw* model probability; the verdict reflects the
  clamped/combined value, so the two can differ on trusted-sender emails by design.

---

## 11. The API endpoint

`POST /api/scan/email` (`scan_email()`, server.py). Input:
```json
{ "content": "From: account-alert@paypal-verify.com\nTo: user@example.com\nSubject: ...\n\nDear user, ..." }
```

Response:
```jsonc
{
  "risk": "critical",                    // safe | medium | danger | critical
  "confidence": 99,                      // 0-99, never 100
  "verdict": { "label": "Critical", "color": "#8b0000", "conclusion": "..." },
  "suspiciousLinks": "1",                // count of links with prob >= 0.55 (string)
  "suspiciousAttachments": "0",          // count of bad-extension files (string)
  "grammarManipulation": "Moderate",     // None | Minor | Moderate | High
  "spoofingDetected": "Yes",             // Yes | No
  "grammarIssues": ["Generic greeting ('dear user') - no personalization", "..."],
  "textModelRisk": "94%",                // raw model prob as a percentage string, or null
  "senderDomain": "paypal-verify.com",
  "spfStatus": "domain_missing",         // present | absent | domain_missing | unknown
  "dmarcStatus": "absent",
  "dkimStatus": "absent",
  "links": [                             // per-link breakdown (first 10 URLs)
    {
      "url": "http://paypal-verify.com/login",
      "host": "paypal-verify.com",
      "risk": "critical",
      "confidence": 99,
      "verdict": "Critical",
      "indicators": ["Domain 'paypal' closely resembles the brand 'paypal' but is not 'paypal.com'"]
    }
  ],
  "indicators": [
    "From domain 'paypal-verify.com' closely resembles brand 'paypal' but is not 'paypal.com'",
    "Generic greeting ('dear user') - no personalization",
    "Sender domain 'paypal-verify.com' does not resolve in DNS",
    "Sender domain 'paypal-verify.com' publishes no SPF/DMARC/DKIM records"
  ]
}
```

Notes:
- `indicators` = link-text mismatches + spoof reason + grammar issues (first 4) + auth
  indicators. The frontend renders it verbatim through `escapeHtml()`.
- `suspiciousLinks` / `suspiciousAttachments` are **strings** (legacy frontend reads them as
  text) — don't "fix" them to numbers.
- Missing `content` → `400 {"error": "Missing 'content' field"}`.
- Latency is dominated by the per-link URL scans (each may run WHOIS/DNS/page fetch) and the
  sender-auth DNS checks. Both are cached aggressively on repeat scans.

---

## 12. Data & corpus

### 12.1 Sources (`data/`)

| File | Contents | Role |
|------|----------|------|
| `phishing0.mbox` … `phishing3.mbox` | Nazario phishing corpus (monkey.org/~jose/phishing) | real phish, parsed to `subject + body` via `email_text_features.extract_parts`, deduped |
| `easy_ham.tar.bz2` | SpamAssassin 2002 "easy_ham" | benign baseline (up to 2,500 emails, bodies > 200 chars) |
| `enron.tgz` | Enron corpus (optional, not currently present) | fallback benign source if easy_ham is missing |
| `email_text_dataset.jsonl` | **6,187 phish + 6,187 benign** JSONL (`{text, label}`) | the model's training file |

### 12.2 Modern synthetic expansion (`update_email_data.py`)

The root cause of the text model's false positives was **2002-era training data**: old
SpamAssassin ham vs old phish mboxes meant modern legit emails *with security vocabulary*
(sign-in reviews, 2FA codes) looked phishy. The fix was generating modern samples on both
sides — **4,000 phish + 4,000 benign** with a seeded `random.Random(42)` for reproducibility.

**9 modern benign templates** (`_benign_*`), with parameter pools for `name / device / city /
code / brand` (`NAMES`, `DEVICES`, `CITIES`, `MODERN_BRANDS`):

| Template | Subject flavour | Body flavour |
|----------|-----------------|--------------|
| `_benign_signin` | Sign-in review / new sign-in | "new sign-in detected on Windows 11 desktop at 2:14 PM from Toronto. If this was you, no action needed…" |
| `_benign_code` | Your verification code | "your {brand} verification code is 483920, expires in 10 minutes. No one can sign in without it…" |
| `_benign_reset` | Password has been changed | "password successfully changed. If you did not make this change, contact support…" |
| `_benign_order` | Order has shipped / confirmation | "order 12345678 containing a 4K monitor has shipped, delivery in 3–5 business days…" |
| `_benign_receipt` | Your receipt / subscription | "this is your receipt, amount charged: $9.99. Questions? visit the billing page…" |
| `_benign_conference` | Registration open / call for papers | conference invites with travel grants |
| `_benign_team` | Re: {topic} / meeting notes | internal colleague email ("thanks for the notes on the Q3 roadmap…") |
| `_benign_newsletter` | Monthly digest | curated-articles / unsubscribe-preferences newsletter |
| `_benign_alert` | We blocked a sign-in attempt | "credentials entered did not match. No action required right now…" |

**9 modern phish templates** (`_phish_*`), seeded from `PHISH_BRANDS`:

| Template | Con |
|----------|-----|
| `_phish_suspended` | account suspended/restricted → verify identity within 24h or permanent closure |
| `_phish_payment` | payment failed → update billing / card number, expiry, CVV |
| `_phish_unusual` | unusual activity / unauthorized access → enter username + password |
| `_phish_prize` | lottery win → confirm bank details + $150 "processing fee" |
| `_phish_delivery` | FedEx/UPS/DHL/USPS package hold → pay rescheduling fee |
| `_phish_docs` | DocuSign document awaiting signature → sign with email + password |
| `_phish_hr` | HR benefits enrollment → enter SSN + bank account |
| `_phish_crypto` | wallet verification / withdrawal pending → password + recovery phrase |
| `_phish_invoice` | overdue invoice / FINAL NOTICE → pay now with card |

`main()` merges real + modern on each side, balances to the smaller class (`min`), shuffles
with `random.seed(42)`, and writes the JSONL.

### 12.3 Retrained model results (2026-08-06)

- Holdout **99.35%** accuracy, macro F1 **0.99** (20% stratified split).
- Production-style probes: phish **0.94**, clean **0.23 / 0.16** (pre-retrain); after retrain:
  `msalerts` legit **0.107** (was an FP), `sarah` clean **0.083**, user's MS phish **0.900**,
  modern benign sign-in **0.022**, 2FA code **0.019**, modern phish **0.989**.

---

## 13. Training pipeline (end to end)

1. `update_email_data.py` — parse Nazario mboxes + easy_ham (Enron fallback), generate 4,000
   modern benign + 4,000 modern phish, balance → `data/email_text_dataset.jsonl`.
2. `train_email_text_model.py` — `load_data` (each record through `clean_email`), stratified
   80/20 split, fit the TF-IDF+LR pipeline, print holdout accuracy + classification report,
   sanity-probe 4 samples, dump `email_text_model.joblib`.
3. Restart the server (kill by PID via `ss -tlnp | grep ':3000'`, then
   `nohup setsid ./venv/bin/python server.py </dev/null > server.log 2>&1 & disown`).
   Model load is ~8s. **Never `pkill -f "python server.py"`** — it kills the shell too.
4. Run the verification battery (§15).

Golden rules:
- `clean_email` must be byte-identical at train and serve time (both import it from
  `email_text_features.py`). Never edit it without retraining.
- Never remove API fields the frontend reads — only add.
- The email model is orthogonal to the URL models — retraining it never touches `score_url()`.

---

## 14. Frontend rendering

- **Input:** the Email tab (`index.html` `#panel-email`) pastes raw headers+body into
  `#emailInput` → `POST /api/scan/email` (`scanner.js` `scanEmail()`).
- **Detail stats** (`scanner.js` `getDetailConfig('email')`): `suspiciousLinks`,
  `suspiciousAttachments`, `grammarManipulation`, `spoofingDetected` — each colored by
  verdict (safe vs danger class).
- **Indicators** (`renderIndicators('email', …)`): `#emailIndicators` lists `result.indicators`
  verbatim, then a **per-link breakdown** — one row per `result.links[]` with a verdict badge,
  the host, and the link's first indicator. All text passes through `escapeHtml()` (phishing
  content is attacker-controlled).
- **Report button** (`#reportEmailBtn`) appears for non-safe verdicts; today it is a frontend
  mock (`submitReport` → confirm dialog + notification + points). No backend report API yet.
- **Points:** a non-safe verdict awards `+5` client-side (`addPoints`), stored in the profile
  (localStorage). This will become server-authoritative when auth lands.
- The `senderDomain` / `spfStatus` / `dmarcStatus` / `dkimStatus` fields are in the response
  and surfaced in the indicator strings (NXDOMAIN, no-SPF) rather than a dedicated detail row.

---
## 15. Verification battery (run after every email-side change)

1. `POST /api/scan/email` with the paypal-spoof phish sample → `danger`/`critical`, spoof
   `Yes`, and NXDOMAIN + no-SPF indicators.
2. Netflix-style phish (suspension + verify link) → `critical` 99%, grammar Moderate, link
   mismatch + spoof shown.
3. Legit `msalerts@microsoft.com` sign-in review → `safe` (was danger 67% before the
   trusted-sender clamp; text now ~0.11 after the modern retrain).
4. Legit clean email (e.g. `sarah@example.com` lunch plans) → `safe` 80%.
5. Fabricated-domain email (`help@totallymadeupdomain.com`) → at least `medium` (NXDOMAIN
   bump is unconditional).
6. Email containing a phish link but clean body → link scan alone drives it to `danger`.
7. Browser e2e (`/tmp/opencode/e2e.py`, headless Firefox): email phish → Critical 99% with
   brand-spoof + generic-greeting + NXDOMAIN + no-SPF indicators rendered; email clean →
   Safe 80%.

Representative results from the 2026-08-06 session:
paypal-verify.com phish → Critical 99%; netflix phish → Critical 99%; msalerts legit → safe;
sarah clean → safe 80%; all 6 modern benign cases safe (68–80%); all 3 modern phish cases
critical 99%. Direct model probes: sign-in 0.022 / 2FA 0.019 (benign), modern phish 0.989.

---

## 16. Known limitations (be honest about these)

- **Input format sensitivity:** the API takes pasted *text*. Real `.eml` headers, MIME
  multipart, quoted-printable/base64 bodies, and attachments are not fully decoded — users
  must paste a text rendering. `extract_parts` (train-time mbox parsing) is richer than the
  serve-time path.
- **Auth is best-effort DNS:** SPF/DMARC/DKIM lookups can time out or hit DNS-filtering
  networks → `unknown` (never penalized, but signal is lost). DKIM only probes 5 common
  selectors, so a real but non-default selector shows `absent` (and could false-bump — hence
  the `prob >= 0.5` guard).
- **`domain_missing` is a strong veto-free bump** (+0.20) even on clean-looking emails; a
  legit small sender with broken DNS will be pushed to `medium`.
- **LanguageTool is an external network call** (up to 8s, first time per unique email) and
  returns nothing offline. It is skipped gracefully on any failure.
- **pyspellchecker is English-only** and sees the sanitized text; non-English emails get more
  "unknown" words, but the Title-Case exemption limits the damage.
- **Brand spoof detection covers 28 brands** and is string-based — a spoof that renames a
  brand entirely (`mybank` vs `chase`) or uses a real-but-unrelated domain is not caught by
  the brand layer (it may still be caught by the other layers).
- **Text model corpus skew:** synthetic templates dominate the modern half of the training
  data. Real-world phishing continuously evolves; refresh the corpus and retrain periodically.
- **Heuristics are English-centric** and keyword-list driven (`URGENT_PHRASES`,
  `GREETING_PATTERNS`).
- **Link scanning inherits all URL-layer limits** (see `URL.md` §15) plus is capped at the
  first 10 URLs.

---

## 17. Change log — everything added on top of the original email scanner

Original Tier 1 email scanner had only: per-link scan, attachment count, `grammar_issues`
(regex), pyspellchecker, LanguageTool, and header-mechanics `spoof_detected`. This is what
was added since:

| Date | Change | What it does |
|------|--------|--------------|
| Tier 2 #3 | **Email body TF-IDF model** | `email_text_features.py` + `train_email_text_model.py` + `email_text_model.joblib`; `textModelRisk` field; `prob = max(link, grammar, heuristic, text)` |
| Tier 2 #4 | **SPF/DKIM/DMARC** | `sender_auth()` DNS checks, `auth_signals()` gating, `senderDomain`/`spfStatus`/`dmarcStatus`/`dkimStatus` response fields |
| Tier 2 #4 | **Trusted-sender text clamp** | text contribution capped at 0.34 for trusted senders unless an explicit signal ≥ 0.5 |
| Tier 2 #4 | **Brand-spoof From-domain detection** | `_domain_brand_spoof_reason()` reuses URL brand machinery on the From domain; service-word check restricted to untrusted domains |
| Tier 2 #6 | **Modern corpus + retrain** | 9 benign + 9 phish synthetic templates, 4,000 each, balanced 6,187/6,187; holdout 99.35%; fixes the 2002-data FP family |
| Tier 2 #6 | **Proper-noun spelling fix** | Title-Case tokens no longer counted as misspellings (killed the Netflix sign-in FP) |
| — | **Frontend email rendering** | `renderIndicators()` + per-link breakdown in `#emailIndicators`; all output HTML-escaped |

Files that define the email pipeline: `server.py` (all `scan_email` helpers),
`email_text_features.py` (normalizer + mbox parsing), `update_email_data.py` (corpus),
`train_email_text_model.py` (trainer), `email_text_model.joblib` (artifact),
`Code/frontend/index.html` + `Code/frontend/js/scanner.js` (UI).
