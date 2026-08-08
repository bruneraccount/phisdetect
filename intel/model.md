# Models Documentation

**PhisDetect — Machine-Learning Models**

This document describes, in detail, every machine-learning model used by
PhisDetect: what it does, which data it was trained on, which algorithm it uses,
how it was validated, and the overfitting / underfitting considerations around it.

---

## Table of Contents

1. [Overview — the three models](#1-overview)
2. [Model 1 — Main Phishing Model (`phishing_model.joblib`)](#2-model-1--main-phishing-model)
3. [Model 2 — URL Text Model (`url_text_model.joblib`)](#3-model-2--url-text-model)
4. [Model 3 — Email Text Model (`email_text_model.joblib`)](#4-model-3--email-text-model)
5. [The data pipeline scripts](#5-the-data-pipeline-scripts)
6. [How the backend combines the models](#6-how-the-backend-combines-the-models)
7. [Overfitting & underfitting — a deeper look](#7-overfitting--underfitting--a-deeper-look)
8. [How to retrain everything](#8-how-to-retrain-everything)
9. [Model files summary](#9-model-files-summary)

---

## 1. Overview

PhisDetect ships **three separate trained models**, each trained by its own
script, each saved as its own `.joblib` file, and each loaded by the backend at
startup (`backend/server.py`). The scanner never relies on a single model — it
consults different models depending on what it is scanning (a URL or an email)
and blends or gates their scores with rule-based heuristics.

| # | File | Size | Trained by | Input | Algorithm |
|---|------|------|-----------|-------|-----------|
| 1 | `model/trained/phishing_model.joblib` | ~385 MB | `model/src/train.py` | 103 hand-crafted URL features | Random Forest + isotonic calibration |
| 2 | `model/trained/url_text_model.joblib` | ~6.2 MB | `model/src/train_url_text_model.py` | The raw URL string as text | TF-IDF + Logistic Regression (custom char analyzer) |
| 3 | `model/trained/email_text_model.joblib` | ~4.5 MB | `model/src/train_email_text_model.py` | The raw email text (subject + body) | TF-IDF + Logistic Regression |

The two text models are "language" models: they read the *wording* of a URL or
an email and learn what tokens/characters are typical of phishing. The main
model is a "feature" model: it reads hand-engineered *properties* of a URL
(lengths, counts of special characters, DNS answers, etc.).

All three are saved with `joblib.dump(...)` and re-loaded with
`joblib.load(...)`. Model 2 is saved as a **tuple** `(vectorizer, classifier)`;
Models 1 and 3 are saved as single estimator objects.

> **Note on git:** all three `.joblib` files are listed in `.gitignore`. They are
> generated artifacts and are **not** committed to the repository — the largest
> one (385 MB) exceeds GitHub's 100 MB file limit. A fresh clone must retrain
> them (see [How to retrain everything](#8-how-to-retrain-everything)).

---

## 2. Model 1 — Main Phishing Model

**File:** `model/trained/phishing_model.joblib`
**Trainer:** `model/src/train.py`
**Companion output:** `model/trained/features.txt` (the ordered feature names)

### 2.1 Purpose

Decide whether a **URL** is phishing by looking at *structure*: how long it is,
which special characters appear and how often, what the domain looks like, how
the path/query are shaped, and what the domain's DNS records say. It is the
workhorse behind every URL scan and is also applied to every link found inside
an email.

### 2.2 The ML algorithm

```
CalibratedClassifierCV(
    estimator=RandomForestClassifier(n_estimators=100, random_state=42),
    method="isotonic",
    cv=5
)
```

Two components:

1. **Random Forest classifier** — an ensemble of 100 decision trees, each trained
   on a bootstrap sample of the data, with feature randomness per split. The
   forest averages the votes/probabilities of the trees. `random_state=42` makes
   training reproducible.

2. **Isotonic calibration** — the raw forest's probability estimates are not
   necessarily well-calibrated (a forest can say "0.9 phish" when only ~0.7 of
   those cases are actually phish). `CalibratedClassifierCV` with
   `method="isotonic"` learns a monotonic mapping from raw scores to true
   empirical probabilities using cross-validation. `cv=5` means the calibration
   fit is itself done inside 5 folds, so calibration never sees the data it is
   evaluated on.

**Final training:** the model is fit once more on **all** data (lines 74–77 of
`train.py`) before saving, so the shipped artifact uses every example.

**Prediction threshold:** `prob >= 0.5` → phishing.

### 2.3 Training data

| Dataset | Rows | Phish | Benign | Notes |
|---------|------|-------|--------|-------|
| `model/trained/dataset_small.csv` | 58,645 | 30,647 | 27,998 | Base set — 103 canonical + 8 legacy feature columns + label |
| `model/trained/dataset_augmented.csv` | 61,705 | 30,647 | 31,058 | What `train.py` actually reads — base + 3,060 generated benign URLs |

`train.py` reads **only** `dataset_augmented.csv`. It checks that every one of
the 103 feature columns is present (`Missing columns in CSV` check) and builds:

```
X = df[FEATURES]        # the 103 features
y = df["phishing"]      # label: 1 = phish, 0 = benign
```

#### Where `dataset_small.csv` comes from

It is a static file in `model/trained/`. **No script in `model/src/` generates
it** — its origin is the project's early development (an external URL dataset
with feature columns). It has 112 columns: the 103 canonical features, the
`phishing` label, and **8 legacy feature columns** that are no longer part of
the canonical feature list:

```
asn_ip, domain_google_index, qty_redirects, time_domain_activation,
time_domain_expiration, time_response, tls_ssl_certificate, url_google_index
```

These are dropped when `dataset_augmented.csv` is built (the augmentation script
re-aligns everything to the 103 canonical features, filling any missing column
with `-1`).

#### Where the extra benign rows come from

`augment_dataset.py` adds **3,060 generated benign URL rows**:

- Samples 600 random domains from `model/lists/tranco_top1m.txt` (first 1,500,
  seeded `random.seed(7)`), plus 18 hardcoded "guaranteed" real domains
  (`youtube.com`, `google.com`, `amazon.com`, `paypal.com`, `wikipedia.org`,
  `github.com`, `reddit.com`, `facebook.com`, `netflix.com`, `microsoft.com`,
  `ebay.com`, `walmart.com`, etc.).
- For each domain, generates 5 realistic URLs using **20 path templates**
  (`/watch?v=…`, `/search?q=…`, `/products?id=…`, `/account/login?redirect=…`,
  `/api/v2/items?limit=…&offset=…`, `/docs/…/index.html`, `/checkout/…/confirm`,
  `/`, `/about`, etc.) and **9 subdomain prefixes**
  (`""`, `www.`, `m.`, `shop.`, `blog.`, `accounts.`, `docs.`, `support.`,
  `help.`).
- Extracts features with `extract(url, with_dns=False)` (no live DNS), then
  **overwrites the DNS features with safe defaults** (`DNS_DEFAULTS`):
  `qty_ip_resolved=1, ttl_hostname=300, qty_nameservers=2, qty_mx_servers=1,
  domain_spf=1`.
- Labels every generated row `phishing=0`.

(618 domains × 5 URLs = 3,090 candidates; 3,060 survive feature extraction
without error.)

The purpose of augmentation is **benign realism**: real safe URLs look like
`/watch?v=…&list=…` or `/products?id=…`, and these shapes are otherwise
under-represented in the base set — the exact shapes that cause false positives.

### 2.4 The 103 features

All features are hand-crafted by `model/src/extract_features.py`. They fall into
several groups:

**A. URL-wide counts (19 features)** — counts of 17 special characters
(`. - _ / ? = @ & ! space ~ , + * # $ %`) in the whole URL (`qty_dot_url`,
`qty_hyphen_url`, …, `qty_percent_url`) plus `qty_tld_url` (how many
top-level-domain tokens appear in the URL) and `length_url`.

**B. Domain features (21 features)** — the same 17 character counts applied to
the hostname only, plus `qty_vowels_domain` (vowel count), `domain_length`,
`domain_in_ip` (1 if the host is a raw IP address), and
`server_client_domain` (1 if the host contains "server" or "client").

**C. Directory features (18 features)** — the 17 character counts +
`directory_length` computed on the path portion.

**D. File features (18 features)** — the 17 character counts + `file_length`
computed on the last path segment (the "file name").

**E. Params features (20 features)** — the 17 character counts + `params_length`,
`tld_present_params` (is there a TLD-like token in the query string?), and
`qty_params` (how many query parameters). When there is no path/query, these
groups are set to `-1` (a "not applicable" sentinel the forest can learn to
ignore).

**F. Content flags (2 features)** — `email_in_url` (1 if an `user@host` pattern
appears in the URL) and `url_shortened` (1 if the host is in
`model/lookup/shorteners.txt`, e.g. `bit.ly`).

**G. DNS features (5 features)** — `qty_ip_resolved` (how many A records),
`ttl_hostname` (record TTL), `qty_nameservers`, `qty_mx_servers`, `domain_spf`
(1 if an SPF record `v=spf1` exists). These are computed **live** at scan time
via `dns.resolver` (`_walk_up` walks up from the full hostname to find NS/MX/TXT).
Missing/unresolvable values become `-1`; for raw-IP hosts the DNS group
short-circuits to `1,-1,0,0,-1`.

Lookup lists used: `model/lookup/tlds.txt` (1,390 entries) and
`model/lookup/shorteners.txt` (443 entries).

### 2.5 Validation protocol

`train.py` runs a strict validation before producing the final artifact:

1. **5-fold stratified cross-validation**
   (`StratifiedKFold(n_splits=5, shuffle=True, random_state=42)`). Each fold fits
   a *raw* Random Forest (100 trees) on the training folds and scores the
   held-out fold. Out-of-fold probabilities are collected into one `oof_prob`
   array.

2. **Per-fold and aggregate metrics:**
   - Accuracy
   - Confusion-matrix totals: true positives, false positives, false negatives,
     true negatives
   - **False-positive rate** (benign flagged as phish) = `fp / (fp + tn)`
   - **False-negative rate** (phish missed) = `fn / (fn + tp)`

3. **Out-of-fold Brier score** on the raw forest — the mean squared error between
   predicted probability and actual label. Lower is better.

4. **Calibration check on a 20% held-out split**
   (`train_test_split(test_size=0.2, random_state=42, stratify=y)`): trains a raw
   forest and an isotonic-calibrated forest, and compares their Brier scores and
   accuracy side by side. It also prints probability-bin tables (`0.0–0.2`,
   `0.2–0.4`, …) comparing mean predicted probability vs. actual phish rate — a
   reliability-table check of calibration.

5. **Final fit** — a calibrated model on 100% of the data, saved as
   `phishing_model.joblib`.

6. **Feature importance** — prints the top 15 features by
   `model.calibrated_classifiers_[0].estimator.feature_importances_`.

### 2.6 Overfitting / underfitting analysis

**Risk of overfitting:**

- A Random Forest rarely overfits as badly as a single tree, but with 100 trees
  on ~61k rows it can still memorize patterns that do not generalize. The biggest
  concrete risk is the **DNS features**: they are live values at inference but
  static `-1`/default values for large parts of the training table, so the forest
  may learn odd splits on them. This is mitigated in `server.py` by the
  trusted-domain gate and by the DNS defaults used during augmentation.
- The 8 legacy columns in `dataset_small.csv` were dropped, removing features that
  could only ever be `-1` in production (e.g. `time_domain_activation`, `asn_ip`)
  — silently closing that overfitting channel.
- 5-fold out-of-fold evaluation means every example is scored by a model that
  never saw it, so the reported metrics are honest generalization estimates, not
  train-set scores.

**Risk of underfitting:**

- Only 103 hand-crafted features means the model cannot express patterns the
  feature engineers did not think of (e.g. visual/punycode tricks need the
  URL-text model).
- A 100-tree forest on ~61k rows with ~103 features is a fairly modest capacity —
  deliberately so, to keep it general and stable.

**How the pipeline compensates:** structural weaknesses of Model 1 are covered by
Model 2 (URL wording) and by hard rule signals (blocklist, brand-spoof
heuristics, trusted-domain gate) in `server.py`. None of the three is expected to
win alone.

---

## 3. Model 2 — URL Text Model

**File:** `model/trained/url_text_model.joblib`
**Trainer:** `model/src/train_url_text_model.py`
**Input at inference:** the raw URL string (the full text, as-is)

### 3.1 Purpose

Complement Model 1 by looking at the **wording** of a URL. Where Model 1 counts
characters in sections, Model 2 reads the actual *tokens* and *character
patterns* — so it can learn things like: the word `login`/`verify`/`secure`
near the end of the URL, `.xyz`/`.top` hosts, long random alphanumeric paths,
`paypal` appearing *inside the hostname*, etc. It is a "spell of the URL"
signal.

### 3.2 The ML algorithm

A **TF-IDF + Logistic Regression** text classifier. Unlike Models 1 and 3, this
is **not** wrapped in a `Pipeline` — the vectorizer and classifier are two
separate objects, saved and loaded as one **tuple** `(vec, clf)`:

```
vec = TfidfVectorizer(analyzer=analyzer, min_df=2, max_features=150000,
                      sublinear_tf=True)
clf = LogisticRegression(C=1.0, solver="liblinear", max_iter=2000,
                         class_weight="balanced")
```

- **`analyzer`** is a **custom tokenizer** from `model/src/url_text_features.py`.
  It splits the pre-processed text into words of length 2–24, and for every word
  of length ≥3 it *also* emits all character n-grams of lengths 3, 4 and 5
  (sliding windows inside the word). So `paypal-login` becomes the words
  `paypal` `login`, which then emit character shingles like `pay`, `pal`, `log`,
  `gin`, `paypa`, `login`, … This is how the model learns sub-word tricks
  (e.g. `amaz0n`, `paypa1`, `signin`) without an explicit normalizer.
- **TF-IDF** vectorizes those tokens. `min_df=2` drops any token that appears in
  only a single training document (a real anti-overfit measure). `max_features`
  caps the vocabulary at 150,000. `sublinear_tf=True` replaces raw term
  frequencies with `1 + log(tf)`, taming URLs that repeat the same token many
  times.
- **Logistic Regression** with `solver="liblinear"` (good for sparse high-dim
  input), L2 regularization `C=1.0`, and `class_weight="balanced"` so the class
  imbalance does not skew the decision boundary. It produces a well-calibrated
  `predict_proba`.

**Prediction threshold:** `prob >= 0.5` → phishing.

### 3.3 Preprocessing

Inference and training use the same `url_text(url)` helper from
`url_text_features.py`:

1. `clean_url()`: strip and lowercase the input, then cut at the first
   whitespace / comma / semicolon / quote / angle bracket (`[\s,;'"<>]`) so
   trailing markdown or HTML punctuation never reaches the model.
2. Remove the scheme (`https://` → rest of string).
3. Cut the string at the first `#` (fragment) and first `?` (query) — only
   host + path remain.
4. Replace every run of non-alphanumeric characters with a single space, then
   let the analyzer produce the words + character n-grams described above.

So the text model sees only **host + path**, not the query string or fragment.

### 3.4 Training data

The URL-text model does **not** use any CSV dataset. `train_url_text_model.py`
**downloads live data at training time** and balances the classes itself:

| Source | Count | Labels |
|--------|-------|--------|
| OpenPhish feed (`openphish.com/feed.txt`) | up to 150,000 | phish (1) |
| Phishing.Database ACTIVE list (`github.com/mitchellkrogza/Phishing.Database`) | same pool | phish (1) |
| Tranco top-1M domains (`model/lists/tranco_top1m.txt`, first 5,000 + random extras) × 8 URL variants each | = len(phish) | benign (0) |

- **Phishing URLs** are downloaded from two live feeds, deduplicated, and each
  run through `url_text()`. If more than 150,000 survive, 150,000 are randomly
  sampled (`random.seed(42)`).
- **Benign URLs** are synthesized from the Tranco top-1M list: the first 5,000
  domains are taken as "guaranteed", then random others are sampled to reach the
  same count `n` as the phish set. Each domain is expanded into 8 variants
  (`d`, `www.d`, `d/`, `d/login`, `d/index.html`, `d/about`,
  `d/account/settings`, `d/products?id=5`), all prefixed with `https://`. The
  first `n` variants become the benign class.
- Both classes are the **same size** (`n`), giving a perfectly balanced set.
  `random.seed(42)` is used for the benign sampling and the phish cap.

This means the dataset is rebuilt from the web every time the script runs, so
two runs of the trainer do **not** produce identical datasets unless run at the
same time — reproducibility of the *numbers* depends on the feeds being stable,
not on a frozen CSV.

### 3.5 Validation protocol

A plain 80/20 split (`train_test_split(test_size=0.2, random_state=42)` — note:
**no stratify**) with:

- Accuracy
- Confusion matrix (`benign correct / benign flagged / phish missed / phish
  caught`)

All numbers are printed on the held-out 20%. After saving, the script also runs
a **manual sanity check** through a hardcoded list of 14 URLs (e.g.
`http://paypal.com.secure-login-verify.xyz/account/confirm.php?id=98213`,
`https://www.google.com`) and prints the phish-probability of each, so you can
eyeball that the model behaves sensibly.

### 3.6 Overfitting / underfitting analysis

**Overfitting risks:**

- The custom analyzer emits a huge number of character n-grams (150,000-feature
  cap). Without safeguards that would be a memorization machine. It is mitigated
  by:
  - `min_df=2` — tokens seen in only **one** training document are dropped.
  - `sublinear_tf=True` — dampens the weight of any single token.
  - L2 regularization (`C=1.0`) on the logistic regression, shrinking weights
    toward zero.
  - `class_weight="balanced"` prevents the majority class from dominating.
- Held-out test metrics (Section 3.5) are honest generalization estimates.

**Underfitting risks:**

- A linear model cannot capture interactions between distant tokens the way a
  nonlinear model could. But for phishing *wording* the linear + n-gram combo is
  a proven, strong baseline (this is what most commercial URL "AI" classifiers
  do).
- `url_text()` throws away the query string, so query-based tricks invisible.

**Where it matters:** Model 2 is the model most likely to catch *novel*
phishing URLs that share nothing structurally with known phish (so Model 1 fails)
but whose *text* resembles known phishing language.

---

## 4. Model 3 — Email Text Model

**File:** `model/trained/email_text_model.joblib`
**Trainer:** `model/src/train_email_text_model.py`
**Input at inference:** the email's subject + body, concatenated as one text blob

### 4.1 Purpose

Decide whether an **email** is phishing by reading its *language*: urgent
phrasing ("Your account has been suspended"), credential pressure ("verify your
password now"), fake bank/portal names, poor spelling, or scammy greeting
templates. It is the only model that sees email text, and it is what makes
"email" scans meaningful beyond just the links inside the message.

### 4.2 The ML algorithm

A **TF-IDF + Logistic Regression** pipeline (`make_pipeline`, saved as one
object):

```
Pipeline([
    ("tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=2,
                              max_features=200000, sublinear_tf=True)),
    ("clf",   LogisticRegression(C=1.0, max_iter=1000,
                                 class_weight="balanced")),
])
```

- **TF-IDF with `ngram_range=(1,2)`** — single words and word pairs are
  features, so two-word signals like `verify identity` or `account suspended`
  are captured. `min_df=2` drops single-document tokens. `max_features=200000`
  caps the vocabulary. `sublinear_tf=True` dampens word-frequency domination
  (email bodies repeat common words a lot).
- **Logistic Regression** with L2 (`C=1.0`) and `class_weight="balanced"` (the
  raw dataset is imbalanced). `max_iter=1000` gives it room to converge.

**Prediction threshold:** `prob >= 0.5` → phishing.

### 4.3 Preprocessing

The dataset is pre-processed **twice**:

1. **At dataset build time** (`update_email_data.py`): each raw email goes
   through `extract_parts()` (parse mime → subject + body) and then
   `record_text(subject, body)` which produces the text blob
   `subject: <subject> \n <body>`.
2. **At training / inference time** (`train_email_text_model.py` and
   `server.py`): the blob is passed through `clean_email()` from
   `email_text_features.py`, which:
   - strips HTML tags and unescapes entities,
   - replaces quoted/reply lines (lines starting with `>` or `|`),
   - replaces every URL with the literal token `URL`,
   - replaces every email address with the token `EMAIL`,
   - replaces every number with the token `NUM`,
   - lowercases everything and keeps only `[a-z]` letters and spaces.

This normalization is why the model learns *phrasing patterns* rather than
specific links or numbers — the concrete paypal.com URLs and $ amounts are
erased into generic placeholders.

### 4.4 Training data

| File | Format | Rows | Phish | Benign |
|------|--------|------|-------|--------|
| `model/data/email_text_dataset.jsonl` | JSONL, `{"text": … , "label": 0/1}` | ~12,374 | ~6,187 | ~6,187 |

This is a **dedicated email dataset**, generated by `model/src/update_email_data.py`
from several raw corpora in `model/data/`:

- **Phishing emails** from four public phishing mbox files
  (`phishing0.mbox` … `phishing3.mbox`, downloaded from
  `monkey.org/~jose/phishing/`) — deduplicated on the first 400 chars of text.
- **Benign emails** from the SpamAssassin `easy_ham.tar.bz2` corpus
  (downloaded from spamassassin.apache.org) and optionally an Enron mailbox
  archive.
- **Synthetic fallbacks** — if a real corpus is missing, template-based
  `_synthetic_phish(400)` / `_synthetic_benign(500)` rows are used (these use the
  global `random` module without a fixed seed, so they are not byte-for-byte
  reproducible between runs).
- **Modern synthetic additions** — always appended: 4,000 "modern phish"
  emails (account-suspended, payment-failed, prize, delivery, DocuSign, HR,
  crypto, invoice templates from `_modern_phish`) and 4,000 "modern benign"
  emails (sign-in reviews, verification codes, receipts, newsletters, team
  meeting notes from `_modern_benign`). Both generators use `random.Random(42)`
  so the synthetic rows are reproducible.

`main()` then balances to `n = min(len(phish), len(benign))`: it randomly
samples `n` from each class (`random.seed(42)`) and writes exactly `n` phish +
`n` benign rows to the JSONL. The result is a perfectly balanced dataset
(~6,187 each, as seen on disk).

`train_email_text_model.py` reads this JSONL directly (it warns you to run
`update_email_data.py` first if the file is missing) and builds `X`/`y` from the
`text` and `label` fields.

### 4.5 Validation protocol

An 80/20 split (`train_test_split(test_size=0.2, random_state=42, stratify=y)`)
with:

- Holdout accuracy (`pipe.score`)
- A full `classification_report` (precision / recall / F1 for benign and phish)
- The vocabulary size of the fitted vectorizer
- A manual sanity check printing phish probabilities for four hardcoded sample
  emails (two phish-flavoured, two benign-flavoured).

### 4.6 Overfitting / underfitting analysis

**Overfitting risks:**

- Email text is extremely noisy (greetings, signatures, HTML remnants). The
  safeguards are `min_df=2`, `sublinear_tf=True`, L2 regularization (`C=1.0`),
  and a 200k vocabulary cap. `class_weight="balanced"` prevents the benign
  class from being ignored.
- Held-out metrics are honest generalization estimates.

**Underfitting risks:**

- Emails are harder than URLs: humans write them in many languages, lengths, and
  styles. A bigram logistic model will miss phish that share no vocabulary with
  its training set, or that are written in a language that is under-represented.
  That gap is expected and is why email scans *also* run the URL models on every
  link inside the email (see [Section 6](#6-how-the-backend-combines-the-models)).

---

## 5. The data pipeline scripts

All live in `model/src/`. Flow:

```
update_lists.py          → downloads Tranco + OpenPhish lists
update_email_data.py     → builds data/email_text_dataset.jsonl (Model 3 data)
augment_dataset.py       → builds trained/dataset_augmented.csv (Model 1 data)
train.py                 → Model 1 (main model)
train_url_text_model.py  → Model 2 (downloads its own live data)
train_email_text_model.py → Model 3
```

Feature / text modules imported by the trainers and the backend:

```
extract_features.py      → the 103 canonical features + extract()
url_text_features.py     → clean_url / url_text / analyzer (Model 2 tokenizer)
email_text_features.py   → extract_parts / record_text / clean_email (Model 3)
```

### 5.1 `extract_features.py`

Defines the canonical **103 features**, the `extract(url, with_dns=True)` entry
point, and all the helpers:

- `FEATURES` — ordered list of the 103 canonical feature names.
- `parse_url` — splits a URL into `url_all` (host+path+query+fragment), `host`,
  `path`, `query` via `urllib.parse`. Adds `http://` if no scheme is present.
- The 17-character-per-section counting helpers (`_counts`) that produce the
  count groups described in Section 2.4.
- `_dns_features` / `_walk_up` — live DNS lookups (A, then NS/MX/TXT walking up
  the hostname) with fallbacks to `-1`; raw-IP hosts short-circuit to
  `1,-1,0,0,-1`.
- `email_in_url`, `url_shortened`, `domain_in_ip` — computed **inline** in
  `extract()` (an email regex against the whole URL; the host checked against
  `model/lookup/shorteners.txt`; `valid_ip(host)`). `valid_ip` is a module
  function; the other two are not separate functions.
- `count_tld` / `check_tld` — scan the text against `model/lookup/tlds.txt`.

### 5.2 `update_lists.py`

Downloads and refreshes the two list files in `model/lists/`:

- `tranco_top1m.txt` + `tranco_top100k.txt` — from `tranco-list.eu/top-1m.csv.zip`
  (the host column of the CSV, lowercased; 1M and 100k rows).
- `openphish_hosts.txt` — hosts parsed from `openphish.com/feed.txt`.

The Tranco list feeds the **trusted-domain gate** and benign-URL synthesis; the
OpenPhish hosts feed the **blocklist** (`BLOCK`).

### 5.3 `update_email_data.py`

Builds `model/data/email_text_dataset.jsonl` (Section 4.4). Reads the phishing
mboxes + easy_ham/enron corpora in `model/data/`, appends 4,000 synthetic
modern-phish and 4,000 modern-benign emails, and balances to `n = min(phish,
benign)` per class with `random.seed(42)`.

### 5.4 `augment_dataset.py`

Reads `dataset_small.csv` + `model/lists/tranco_top1m.txt`, generates 3,060
benign URLs (Section 2.3), re-extracts their features with
`extract(url, with_dns=False)`, overrides DNS columns with `DNS_DEFAULTS`, and
writes `dataset_augmented.csv`. It also normalizes the base file to the 103
canonical features — the 8 legacy columns present in `dataset_small.csv` are
dropped, and any missing canonical column is filled with `-1`.

### 5.5 `train.py`

The full Model-1 pipeline (Section 2). Uses the 103-feature table from
`dataset_augmented.csv`, runs 5-fold CV + Brier + calibration checks + final fit,
writes `phishing_model.joblib` and `features.txt`.

### 5.6 `train_url_text_model.py`

Builds the TF-IDF logistic model on URL text (Section 3), **downloading live
phishing + benign data** at runtime, validates on a 20% split, writes
`url_text_model.joblib` as a tuple `(vec, clf)`.

### 5.7 `train_email_text_model.py`

Builds the TF-IDF logistic model on email text (Section 4) from
`data/email_text_dataset.jsonl`, validates on a stratified 20% split, writes
`email_text_model.joblib` as a `Pipeline`.

---

## 6. How the backend combines the models

`backend/server.py` loads all three models once at startup:

```
model                = joblib.load(... "phishing_model.joblib")     # calibrated forest
feature_cols         = read "features.txt"                           # 103-feature order
url_text_vec, url_text_clf = joblib.load(... "url_text_model.joblib")  # tuple
email_text_model     = joblib.load(... "email_text_model.joblib")      # pipeline
```

It also loads two host lists: `ALLOW` (Tranco top-1M, the **trusted-domain
gate**) and `BLOCK` (OpenPhish hosts, the **blocklist**).

### 6.1 URL scans (`/api/scan/url` → `score_url`)

Signals combined for a URL:

1. **Main model** — `predict_url()` calls `extract(url)` (live DNS), picks the
   103 features in `features.txt` order, and asks the calibrated forest for
   `p_main`.
2. **Blocklist** — if the host *or* its registrable domain is in `BLOCK`
   (OpenPhish), `p_main` is raised to `max(p_main, 0.95)` and a rule reason is
   attached. **This returns immediately.**
3. **Structural heuristic** — `heuristic_risk(host)` checks brand
   spoofing/resemblance (homoglyph-normalized edit distance ≤ 2), TLD-like
   words in subdomains, cheap-TLD tricks, IDN/punycode labels, suspicious
   keywords (`login`, `verify`, `secure`…), offensive words, and black-market
   words. If any fire, it returns a heuristic probability
   `0.62 + min(n, 3) × 0.05` (i.e. 0.67 / 0.72 / 0.77, capped at 0.80) plus the
   list of reasons; with no reasons it returns `None`.
4. **Trusted-domain gate** — if the host (or any parent label) is in the
   Tranco top-1M `ALLOW` set: the learned models are **suppressed**
   (`p_main = min(p_main, 0.25)`) unless a hard heuristic fired
   (`p_main = max(p_main, heur[0])`). Rationale: real safe URLs
   (`/watch?v=…`, `/products?id=5`) must not be flagged by model quirks; only a
   concrete spoof/blocklist signal may override.
5. **URL-text model** — `url_text_prob(url, host)` applies the text model to the
   cleaned URL, but **skips allowlisted hosts and raw-IP hosts**.
6. **Blending** — if no hard signal fired and the host is untrusted:
   `p_final = 0.6 * p_main + 0.4 * p_text` (the two learned models vote with a
   60/40 weight). If a heuristic fired, `p_final = max(p_main, heur[0],
   p_text)`.

**After scoring, `scan_url` adds enrichment and a page scan:**

- **Enrichment** (parallel, cached): domain age (whois), TLS certificate
  validity, HTTP redirect, and DNS-RBL blacklist checks.
- **Page scan** — unless the host is trusted or `p_final ≥ 0.85`, the page is
  fetched and inspected for credential-harvesting signals (password/SSN/CVV
  form fields, credential words, form submits to a different site, redirects to
  a different site, meta-refresh/JS redirects, brand name in the title but wrong
  host, tiny form-only "phish-kit" pages). Each signal adds a bump (up to
  +0.40 total).
- **Enrichment veto** — a domain registered 2+ years ago **and** with a valid
  TLS cert, flagged only by the learned models (no heuristic/blocklist rule),
  is very unlikely to be phishing: `p_final` is capped at 0.34 (valid TLS) or
  0.55 (no TLS).

**Risk buckets** (used everywhere): `< 0.35` safe · `< 0.60` medium ·
`< 0.80` danger · `≥ 0.80` critical. Confidence = `min(99, round(max(p, 1-p)
* 100))`.

So a URL is critical if it is on the OpenPhish blocklist, dangerous/critical if
the structural heuristic or blended models agree strongly, safe if it is a
trusted top-1M domain with no spoof signal, and the page-scan bump can push a
borderline model score into danger.

### 6.2 Email scans (`/api/scan/email` → `scan_email`)

Signals combined for an email (given the pasted `content`):

1. **Per-link analysis** — every URL found in the content (max 10) is run
   through the full `score_url` pipeline. This yields `max_link_prob` and a
   count of `suspicious_links` (links scoring ≥ 0.55).
2. **Link-text mismatch** — an anchor whose *text* says a brand but whose
   target host is not that brand's real domain → indicator.
3. **Spoofing detection** — From/Reply-To domain mismatch, impersonating
   addresses (`security@…` from a non-trusted domain), brand-spoof reason on
   the From domain.
4. **Grammar / language report** — generic greeting, lowercase sentence starts,
   missing spaces after punctuation, excessive exclamation marks, ALL-CAPS
   sentences, character repetition, a spell-checker pass, and a LanguageTool
   API call. Produces a `grammar["prob"]` (0 up to 0.85).
5. **Heuristic probability** — `heuristic_prob(content)`:
   `0.20 + min(hits, 2) * 0.15` from urgent phrases, +0.25 if spoofing detected
   (capped 0.95).
6. **Email-text model** — `email_text_prob(content)` applies Model 3 to
   `clean_email(content)` → `p_email`.

**Combination rule (email):** let `explicit = max(max_link_prob,
grammar_prob, heuristic_prob)`.

- If the email-text model is missing (`None`): `p = explicit`.
- If the sender domain is **trusted** (top-1M or a real brand domain) *and*
  `explicit < 0.5`: `p = max(explicit, min(p_email, 0.34))` — a trusted sender
  caps how much a lone text-model score can hurt.
- If `p_email ≥ 0.5` **or** `explicit ≥ 0.5`: `p = max(explicit, p_email)` —
  an email is phish if *either* the wording model **or** any explicit signal
  (links / grammar / heuristics) is confident.
- Otherwise: `p = max(explicit, min(p_email, 0.34))` — with weak evidence the
  text model is again capped.

**Sender-auth check** — SPF / DMARC / DKIM DNS records are looked up; a missing
non-resolving domain bumps +0.20, and for already-suspicious emails missing
auth records add indicators (+0.10/+0.20). `p` is capped at 0.99, then the same
risk buckets and confidence formula apply.

So an email is flagged if its wording is clearly phish, if any embedded link is
flagged, or if strong grammar/spoof/auth signals accumulate — but a trusted
sender and weak evidence can cap the contribution of the text model.

### 6.3 Score exposure

The URL response returns `risk`, `confidence`, `verdict`, enrichment fields,
`pageSignals` and `indicators`. The email response returns `risk`,
`confidence`, `textModelRisk` (the raw `p_email` as a percentage), `spfStatus`,
`dmarcStatus`, `dkimStatus`, `suspiciousLinks`, `grammarManipulation`,
`spoofingDetected`, `links[]` (per-link model risks) and `indicators`.

---

## 7. Overfitting & underfitting — a deeper look

### 7.1 What "overfit/underfit" means here

- **Overfit** = the model memorizes the training set, so it scores great on
  training data but badly on new data (high variance).
- **Underfit** = the model is too weak to capture the pattern, so it scores
  badly on both training and new data (high bias).

For a *detector*, overfitting is especially dangerous: a phishing classifier
that overfits will miss genuinely new phishing campaigns (the "novel phish"
that matters most). Underfitting is less dangerous but means wasted signal.

### 7.2 Where each model sits on the bias-variance spectrum

| Model | Capacity | Main overfit risk | Main underfit risk |
|-------|----------|-------------------|--------------------|
| Main forest | 100 trees × 103 features | Memorizing DNS-feature quirks (mostly `-1`s); rare legacy columns (dropped) | Missing patterns the 103 features cannot express |
| URL-text logistic | 150k tokens (words + char 3/4/5-grams), `min_df=2` | Character-ngram sparsity → rare shingle memorization; live data changes between runs | Linear model can't join distant tokens; query string discarded |
| Email-text logistic | 200k word/bi-grams, `min_df=2` | Email noise/signatures learned as signal; synthetic rows teach "template look" | Multi-language, hugely varied emails outrun a bigram linear model |

### 7.3 Mitigations already in place

- **Ensembling** — three models + rules; a memorized artifact of one model is
  gated by the others (trusted-domain gate, 60/40 blending, text-model capping
  for trusted senders).
- **Cross-validation honesty** — all reported numbers are out-of-fold or
  held-out, never train-set.
- **Regularization** — L2 (`C=1.0`) on both logistic models; `min_df=2` on both
  text vectorizers kills single-document tokens; `sublinear_tf=True` dampens
  token-frequency domination; forest capacity is modest.
- **Feature hygiene** — the 8 legacy columns that could never be populated in
  production were dropped, removing a silent overfit channel.
- **Class balancing** — the email dataset is pre-balanced, the URL-text trainer
  balances at runtime, and both logistic models also use
  `class_weight="balanced"`.
- **DNS defaults** — DNS features in the augmented benign rows use safe
  defaults rather than leaving real outliers in the table.

### 7.4 What would make it worse (do not do)

- Lowering `min_df` below 2, or widening `ngram_range` beyond (1,2) for emails,
  without re-validating on a *temporal* split (e.g. train on old campaigns, test
  on new ones).
- Removing L2 (`C` large) on the logistic models.
- Training the URL-text model on the *augmented* URL CSV (template look) — it
  is built to train on live feeds instead.
- Reporting accuracy computed on the training set as if it were real.

### 7.5 What would make it better (future work)

- A **temporal/geographic hold-out** during training, so the CV mirrors how the
  models will actually be used (phishing evolves).
- Raising `min_df` further (e.g. `min_df=3`) on the text models to kill very rare
  shingles.
- A separate feature group for **domain-entropy / homoglyph** signals in Model 1
  (today homoglyph handling lives in the backend heuristics, not the forest).
- More real benign emails: `email_text_dataset.jsonl` currently leans heavily on
  4,000 *synthetic* modern-benign rows, which are far less varied than real
  inbox traffic.
- Freezing the training data for reproducible runs (today the URL-text model
  depends on live feeds).

---

## 8. How to retrain everything

All three `.joblib` files are git-ignored; a fresh clone must regenerate them.
Because `train.py` fits and holds a ~385 MB model object in memory (plus the
61,705-row DataFrame it trains on), training needs a machine with a few GB of
free RAM.

```bash
cd "AI project/model"

# 0) Optional: refresh the domain lists (Tranco top-1M, OpenPhish hosts)
python src/update_lists.py

# 1) Rebuild the email-text dataset  → data/email_text_dataset.jsonl
#    (downloads corpora on first run; synthetic fallbacks if offline)
python src/update_email_data.py

# 2) (Re)build the augmented URL dataset  → trained/dataset_augmented.csv
python src/augment_dataset.py

# 3) Train + validate the main model → trained/phishing_model.joblib
python src/train.py

# 4) Train the URL-text model → trained/url_text_model.joblib
#    (downloads live phishing + benign data at training time)
python src/train_url_text_model.py

# 5) Train the email-text model → trained/email_text_model.joblib
python src/train_email_text_model.py
```

The backend loads all models once at startup (`server.py`, top of file). After
retraining, **restart the backend** so it picks up the new `.joblib` files —
there is no hot reload.

---

## 9. Model files summary

| File | Model | Size | Trained by | Loaded by |
|------|-------|------|------------|-----------|
| `model/trained/phishing_model.joblib` | Main (103 features) | ~385 MB | `train.py` | `server.py` |
| `model/trained/url_text_model.joblib` | URL text (TF-IDF, tuple) | ~6.2 MB | `train_url_text_model.py` | `server.py` |
| `model/trained/email_text_model.joblib` | Email text (TF-IDF pipeline) | ~4.5 MB | `train_email_text_model.py` | `server.py` |
| `model/trained/features.txt` | Feature-name order for the main model | tiny | `train.py` | `server.py` |

### Data files that feed the models

| File | Used by | Contents |
|------|---------|----------|
| `model/trained/dataset_small.csv` | `augment_dataset.py` | 58,645 URLs with 111 features + label |
| `model/trained/dataset_augmented.csv` | `train.py` | 61,705 rows (base + 3,060 synthetic benign) |
| `model/data/email_text_dataset.jsonl` | `train_email_text_model.py` | ~12,374 balanced phish/benign emails |
| `model/lists/tranco_top1m.txt` | `update_lists.py`/backend | trusted-domain gate + benign URL synthesis |
| `model/lists/openphish_hosts.txt` | `update_lists.py`/backend | live phishing blocklist (`BLOCK`) |
| `model/lookup/tlds.txt` | `extract_features.py` | 1,390 TLD strings |
| `model/lookup/shorteners.txt` | `extract_features.py` | 443 URL shortener hosts |
| `model/data/phishing0-3.mbox` + `easy_ham.tar.bz2` | `update_email_data.py` | raw email corpora |

All three models, their trainers, the augmentation / list / email-data scripts,
the feature extractor, and the datasets are covered above. Between the three
models and the rule-based heuristics, PhisDetect balances structural, lexical,
and semantic evidence for both URLs and emails.
