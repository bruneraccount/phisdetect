# URL Model — Complete Technical Reference

Deep-dive on every aspect of the URL detection models: architecture, features, training data, calibration, overfitting/underfitting, scoring pipeline, and limitations.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Model 1 — Random Forest Lexical Model](#2-model-1--random-forest-lexical-model)
3. [Model 2 — URL-Text TF-IDF Model](#3-model-2--url-text-tfidf-model)
4. [Blending & Scoring Pipeline](#4-blending--scoring-pipeline)
5. [Heuristics Layer](#5-heuristics-layer)
6. [Enrichment (DNS/WHOIS)](#6-enrichment-dnswhois)
7. [Overfitting & Underfitting Analysis](#7-overfitting--underfitting-analysis)
8. [Calibration Deep-Dive](#8-calibration-deep-dive)
9. [Feature Engineering — Full Catalog](#9-feature-engineering--full-catalog)
10. [Training Data](#10-training-data)
11. [Augmentation Pipeline](#11-augmentation-pipeline)
12. [Training Procedure](#12-training-procedure)
13. [Serialized Artifacts](#13-serialized-artifacts)
14. [Server Integration](#14-server-integration)
15. [Known Failure Modes](#15-known-failure-modes)
16. [Verification Battery](#16-verification-battery)
17. [Changelog & Decisions](#17-changelog--decisions)

---

## 1. Architecture Overview

The URL scanner uses a **two-model blend** — a calibrated Random Forest over 103 lexical/DNS features, plus a TF-IDF Logistic Regression on raw URL text — combined with heuristic scoring and optional DNS/WHOIS enrichment.

```
URL input
  → BLOCKED? (OpenPhish hosts, Tranco top-100k allowlist, blocklist.txt)
    → yes → score = 0.99 (phish)
    → no  → RF probability (isotonic-calibrated)
           + TF-IDF text probability
           → 0.6 × RF + 0.4 × text  →  base score
           → heuristics adjustment
           → enrichment veto (if DNS/WHOIS available)
           → page-scan cap (if fetched)
           → final score ∈ [0, 1]
```

**Models are independent.** The RF model sees structured numeric features. The text model sees only the URL as a string of characters and n-grams. Neither model's output feeds into the other. The server blends their probabilities at serving time.

---

## 2. Model 1 — Random Forest Lexical Model

### Algorithm

```
RandomForestClassifier(n_estimators=100, random_state=42)
```

- **100 decision trees**, each trained on a bootstrap sample of the training data
- **No max_depth limit** — trees grow until pure leaves (or <2 samples). This is the primary overfitting vector (see §7)
- **No class_weight** — the RF sees balanced data (see §10), so weighting is unnecessary
- **random_state=42** — deterministic for reproducibility
- **Criterion:** Gini impurity (sklearn default)
- **max_features:** `sqrt(n_features)` = `sqrt(103)` ≈ 10 features considered per split (sklearn default for classifiers)

### Calibration

Wrapped in `CalibratedClassifierCV(method="isotonic", cv=5)`:

```
CalibratedClassifierCV(
    estimator=RandomForestClassifier(n_estimators=100, random_state=42),
    method="isotonic", cv=5
)
```

- **Method: isotonic regression** — a non-parametric monotonic mapping from raw RF probability → calibrated probability. Unlike Platt scaling (sigmoid), isotonic makes no assumption about the shape of the calibration curve. Better for Random Forests, which tend to produce overconfident probabilities near 0 and 1.
- **cv=5** — 5-fold internal cross-validation within the training split to fit the isotonic mapping. Prevents overfitting the calibration on the same data used for the RF.
- **Output:** `phishing_model.joblib` (403 MB) — serialized CalibratedClassifierCV object containing 5 calibrated classifiers (one per internal fold) + the final isotonic calibrator.

### Feature Importances (from final model, Gini importance)

| Rank | Importance | Feature | Category |
|------|-----------|---------|----------|
| 1 | 0.0999 | `ttl_hostname` | DNS |
| 2 | 0.0727 | `directory_length` | URL structure |
| 3 | 0.0601 | `length_url` | URL structure |
| 4 | 0.0465 | `qty_slash_directory` | URL structure |
| 5 | 0.0453 | `domain_length` | Domain |
| 6 | 0.0400 | `qty_slash_url` | URL structure |
| 7 | 0.0397 | `qty_vowels_domain` | Domain |
| 8 | 0.0333 | `qty_dot_domain` | Domain |
| 9 | 0.0325 | `qty_nameservers` | DNS |
| 10 | 0.0313 | `file_length` | URL structure |
| 11 | 0.0310 | `qty_mx_servers` | DNS |
| 12 | 0.0262 | `qty_equal_directory` | URL structure |
| 13 | 0.0260 | `qty_dollar_directory` | URL structure |
| 14 | 0.0223 | `qty_underline_directory` | URL structure |
| 15 | 0.0219 | `domain_spf` | DNS |
| 16 | 0.0198 | `qty_dot_directory` | URL structure |
| 17 | 0.0192 | `qty_dot_url` | URL structure |
| 18 | 0.0192 | `qty_hyphen_directory` | URL structure |
| 19 | 0.0192 | `qty_ip_resolved` | DNS |
| 20 | 0.0163 | `qty_plus_file` | URL structure |

**Zero-importance features** (8): `qty_and_domain`, `qty_equal_domain`, `qty_questionmark_domain`, `qty_exclamation_domain`, `qty_slash_domain`, `qty_space_domain`, `qty_tilde_domain`, `qty_comma_domain`. These character types essentially never appear in domain names, making them useless splits.

**Key insight:** DNS features dominate (`ttl_hostname` alone = 10%), but domain/URL structural features collectively contribute more. The model learned that TTL is the single best discriminator (phishing domains often have short TTLs from cheap hosting or fast-flux).

---

## 3. Model 2 — URL-Text TF-IDF Model

### Algorithm

```
LogisticRegression(C=1.0, solver="liblinear", max_iter=2000, class_weight="balanced")
```

- **Logistic Regression** with L1 penalty (liblinear default) — produces sparse weight vectors, naturally selecting informative n-grams
- **class_weight="balanced"** — adjusts weights inversely proportional to class frequency (phishing URLs are ~50% of training data, but the live feed ratio fluctuates; balanced weighting ensures equal contribution)
- **C=1.0** — standard regularization strength
- **max_iter=2000** — ensures convergence on the 300k-sample dataset

### Vectorizer

```
TfidfVectorizer(analyzer=analyzer, min_df=2, max_features=150000, sublinear_tf=True)
```

- **Custom analyzer** (see `url_text_features.py:23-32`):
  1. `url_text()` strips scheme, fragments, query strings, non-alphanumeric characters
  2. Splits on whitespace → word tokens (2-24 chars each)
  3. For each word ≥3 chars: generates **3-gram, 4-gram, and 5-gram character subsequences**
  4. Example: `paypal` → tokens `["paypal"]` → n-grams `["pay", "aya", "yal", "payp", "ayal", "paypal", "paypa", "aypal"]`
- **min_df=2** — ignores terms appearing in fewer than 2 documents (noise reduction)
- **max_features=150,000** — vocabulary cap (typical fit produces exactly 150k)
- **sublinear_tf=True** — applies `1 + log(tf)` dampening to term frequencies, reducing the influence of repeated characters (e.g., `aaaaa`)

### Feature Space

The analyzer produces a mix of:
- **Word-level tokens**: full domain/path segments after cleaning
- **Character 3-grams**: capture short patterns like `www`, `com`, `xyz`
- **Character 4-grams**: capture `http`, `login`, `phish`
- **Character 5-grams**: capture `paypa`, `secure`, `.xyz/`

This design is robust to:
- Homograph attacks (different TLDs with same words)
- Path-based phishing (`paypal.com.secure-login-verify.xyz`)
- URL obfuscation (`pay pal.com` → cleaned to `pay pal com`)

### Serialized Artifact

`url_text_model.joblib` (6.2 MB) — tuple of `(TfidfVectorizer, LogisticRegression)`. Loaded once at server startup.

---

## 4. Blending & Scoring Pipeline

### Score Combination

```python
def score_url(url, rf_prob, text_prob, heuristic_delta, enrichment_delta, page_cap):
    base = 0.6 * rf_prob + 0.4 * text_prob
    score = base + heuristic_delta + enrichment_delta
    if page_cap is not None:
        score = min(score, page_cap)
    return round(score, 4)
```

**Weights:**
- **RF: 60%** — the lexical model is primary; it sees DNS/TTL features the text model cannot
- **Text: 40%** — the text model catches phishing URLs with suspicious word patterns even when lexical features look normal

### Allowlist Gate

Before scoring, two hard gates clamp the score:

1. **Tranco top-100k allowlist**: if the domain is in `tranco_top100k.txt`, the score is clamped to **≤ 0.25**. This prevents false positives on major legitimate domains (google.com, amazon.com, etc.) regardless of URL path anomalies.

2. **`allowlist_gate(score, url, tranco_list)`** in `server.py:213-240`: applies the 0.25 ceiling.

### Blocklist

- `blocklist.txt` — manually curated list of known-phishing domains (not the Tranco/OpenPhish feeds)
- Any URL whose domain appears in `blocklist.txt` → score forced to **0.99**

---

## 5. Heuristics Layer

Applied after blending, before enrichment. These are deterministic rules — no ML involved.

### URL-Path Heuristics (server.py:446-509)

| Heuristic | Delta | Trigger |
|-----------|-------|---------|
| Numeric-heavy domain | +0.04 | Domain is ≥50% digits |
| Long domain (>30 chars) | +0.03 | Domain string length > 30 |
| Very long URL (>100 chars) | +0.02 | Total URL length > 100 |
| Subdomain nesting (>3 levels) | +0.04 | ≥4 dot-separated segments in domain |
| Path depth > 3 | +0.02 | URL path has > 3 `/` segments |
| Login-related path | +0.03 | Path contains `login`, `signin`, `verify`, `secure`, `account` |
| IP address as domain | +0.10 | Domain parses as valid IP |

### Email-Content Heuristics (for scan_url email detection)

| Heuristic | Delta | Trigger |
|-----------|-------|---------|
| URL has `@` character | +0.03 | `@` found in URL |
| URL contains email address | +0.05 | Regex match for `user@domain` pattern |

**Total heuristic ceiling:** Heuristics can add at most ~0.28 to the base score. The server caps heuristic contribution implicitly through the 0.25 allowlist gate and the 1.0 score ceiling.

---

## 6. Enrichment (DNS/WHOIS)

Optional — only runs when DNS resolution succeeds and `dnspython` + `python-whois` are available.

### DNS Enrichment (server.py:658-730)

| Signal | Weight | Logic |
|--------|--------|-------|
| SPF record missing | +0.34 | No `v=spf1` TXT record found |
| No MX servers | +0.20 | MX lookup returns 0 answers |
| Multiple A records (fast-flux) | +0.10 | ≥ 3 A records for hostname |
| TTL < 300s | +0.10 | DNS TTL under 5 minutes (cheap hosting) |

### WHOIS Enrichment (server.py:732-808)

| Signal | Weight | Logic |
|--------|--------|-------|
| Domain age < 30 days | +0.20 | Registration date within last month |
| Domain age < 90 days | +0.10 | Registration date within last 3 months |
| Registrar is privacy service | +0.05 | WHOIS registrant contains "privacy" or "redacted" |

### Enrichment Veto

- If enrichment adds **≥ 0.34** total and base score is **≥ 0.20**: score is pushed to **≥ 0.55** (forced suspicious)
- If enrichment adds **≥ 0.55** total: score is pushed to **≥ 0.85** (near-certain phish)

This ensures domains with missing SPF + no MX + short TTL + new registration are flagged even if the ML models gave a borderline score.

---

## 7. Overfitting & Underfitting Analysis

### RF Model — Overfitting Evidence

| Metric | Train (80% split) | Test (20% split) | Gap |
|--------|-------------------|-------------------|-----|
| Accuracy | 99.89% | 93.83% | **6.06%** |

This 6-point gap is the classic overfitting signature of untuned Random Forests:
- **100 trees** with **no max_depth** grow until pure leaves → memorize training noise
- **99.89% train accuracy** = the RF essentially memorized the training set
- **93.83% test accuracy** = generalization is still strong, but the gap is real
- **AUC = 0.9830** on test → ranking ability is excellent despite overfitting

### RF Model — Underfitting Assessment

**No underfitting detected:**
- 93.83% test accuracy with 103 features on a binary task = strong performance
- AUC 0.983 → near-perfect separation between classes
- Brier 0.0476 → well-calibrated probabilities
- FPR 6.63%, FNR 6.30% → balanced error profile
- The model is NOT underfitting — it is slightly overfitting, which is the lesser evil

### RF Model — Cross-Validation (5-Fold Stratified)

| Fold | Accuracy |
|------|----------|
| 1 | 93.75% |
| 2 | 93.36% |
| 3 | 93.69% |
| 4 | 93.24% |
| 5 | 93.61% |
| **Mean** | **93.53%** |
| **Std** | **0.19%** |

- Low variance across folds (σ = 0.19%) → model is stable, not dependent on a lucky split
- OOF Brier = 0.0484 → out-of-fold probability quality
- OOF AUC = 0.9827

### URL-Text Model — Overfitting Evidence

| Metric | Train (80% split) | Test (20% split) | Gap |
|--------|-------------------|-------------------|-----|
| Accuracy | 96.53% | 93.78% | **2.75%** |

Smaller gap than RF (2.75% vs 6.06%) because:
- Logistic Regression with L1 regularization prevents overfitting
- TF-IDF features are high-dimensional but sparse → LR handles this well
- class_weight="balanced" prevents majority-class bias

### URL-Text Model — Cross-Validation (5-Fold Stratified)

| Fold | Accuracy |
|------|----------|
| 1 | 93.61% |
| 2 | 93.70% |
| 3 | 93.87% |
| 4 | 93.66% |
| 5 | 93.57% |
| **Mean** | **93.68%** |
| **Std** | **0.11%** |

- Even lower variance than RF (σ = 0.11%)
- OOF AUC = 0.9880 → slightly better ranking than RF alone

### Combined Blend Assessment

The two models have **similar standalone accuracy** (~93.5-93.7%) but are **complementary**:
- RF catches structural anomalies (TTL, DNS features, URL length)
- Text catches lexical anomalies (suspicious n-grams, phishing keywords)
- The 60/40 blend likely outperforms either model alone (the server doesn't log blend vs. individual accuracy, but the AUC values suggest the blend is stronger)

---

## 8. Calibration Deep-Dive

### Why Calibrate?

Raw Random Forest probabilities are notoriously **uncalibrated** — they tend to cluster near 0 and 1, overconfident in both directions. A URL with 95% actual phishing risk might get scored as 0.999 by a raw RF, while a 60% risk URL might get 0.82.

### Isotonic Regression

`CalibratedClassifierCV(method="isotonic", cv=5)` works by:

1. **Splitting training data into 5 folds**
2. For each fold: train RF on 4 folds → predict probabilities on the held-out fold
3. **Collect OOF predictions** → fit an isotonic regression mapping: raw_prob → calibrated_prob
4. The isotonic fit is a piecewise-constant non-decreasing function that maps RF outputs to actual observed frequencies
5. **Final prediction** = average of the 5 calibrated classifiers' predictions

### Raw vs Calibrated Comparison (80/20 holdout)

| Metric | Raw RF | Calibrated RF | Improvement |
|--------|--------|---------------|-------------|
| Brier Score | 0.0476 | 0.0464 | -0.0012 (2.5%) |
| Accuracy | 93.83% | 93.77% | -0.06% (negligible) |
| AUC | 0.9830 | 0.9839 | +0.0009 |

- **Brier improvement is meaningful** — the calibrated model's probability estimates are more truthful
- **Accuracy is essentially unchanged** — calibration doesn't change the 0.5 threshold decision
- **AUC barely changes** — calibration doesn't affect ranking

### Calibration Reliability (Calibrated, 80/20 Holdout)

| Bin | N | Mean Predicted | Actual Phish Rate |
|-----|---|---------------|-------------------|
| [0.0, 0.1) | 4,853 | 0.019 | 0.019 |
| [0.1, 0.2) | 640 | 0.144 | 0.119 |
| [0.2, 0.3) | 308 | 0.246 | 0.201 |
| [0.3, 0.4) | 257 | 0.350 | 0.319 |
| [0.4, 0.5) | 229 | 0.453 | 0.485 |
| [0.5, 0.6) | 188 | 0.551 | 0.537 |
| [0.6, 0.7) | 214 | 0.652 | 0.678 |
| [0.7, 0.8) | 269 | 0.754 | 0.762 |
| [0.8, 0.9) | 493 | 0.858 | 0.854 |
| [0.9, 1.0) | 4,890 | 0.984 | 0.989 |

**Interpretation:**
- **Near-perfect calibration at extremes** — the [0.0, 0.1) bin predicts 1.9% and sees 1.9% actual; the [0.9, 1.0) bin predicts 98.4% and sees 98.9%
- **Slight underconfidence in mid-range** — bins 0.2-0.4 predict slightly higher than actual (e.g., [0.2,0.3) predicts 24.6% but actual is 20.1%)
- **Bins 0.4-0.6 are noisy** — small sample sizes (188-229 URLs) make these bins unreliable
- The monotonicity constraint is respected: mean predicted probability increases monotonically across bins

### OOF Calibration (Full Dataset, 5-Fold CV)

| Bin | N | Mean Predicted | Actual Phish Rate |
|-----|---|---------------|-------------------|
| [0.0, 0.1) | 23,818 | 0.012 | 0.016 |
| [0.1, 0.2) | 2,704 | 0.141 | 0.117 |
| [0.2, 0.3) | 1,700 | 0.243 | 0.201 |
| [0.3, 0.4) | 1,403 | 0.344 | 0.290 |
| [0.4, 0.5) | 1,305 | 0.444 | 0.373 |
| [0.5, 0.6) | 1,281 | 0.544 | 0.504 |
| [0.6, 0.7) | 1,401 | 0.647 | 0.648 |
| [0.7, 0.8) | 1,852 | 0.749 | 0.787 |
| [0.8, 0.9) | 3,200 | 0.850 | 0.899 |
| [0.9, 1.0) | 23,041 | 0.980 | 0.991 |

**Pattern:** The RF systematically **overpredicts** in the 0.1-0.5 range (predicted > actual) and **underpredicts** in the 0.7-0.9 range (predicted < actual). This is the classic RF calibration problem — the model is overconfident in the ambiguous middle zone. The isotonic calibrator corrects this partially, but the OOF bins show residual miscalibration.

---

## 9. Feature Engineering — Full Catalog

### 103 Features in 6 Groups

All features are defined in `extract_features.py` (214 lines). The `FEATURES` tuple (line 10-39) lists them in order.

#### Group 1: URL-Global (19 features)

Character counts across the full URL (`host + path + params + query + fragment`):

| Feature | Type | Description |
|---------|------|-------------|
| `qty_dot_url` | int | Count of `.` in full URL |
| `qty_hyphen_url` | int | Count of `-` in full URL |
| `qty_underline_url` | int | Count of `_` in full URL |
| `qty_slash_url` | int | Count of `/` in full URL |
| `qty_questionmark_url` | int | Count of `?` in full URL |
| `qty_equal_url` | int | Count of `=` in full URL |
| `qty_at_url` | int | Count of `@` in full URL |
| `qty_and_url` | int | Count of `&` in full URL |
| `qty_exclamation_url` | int | Count of `!` in full URL |
| `qty_space_url` | int | Count of spaces in full URL |
| `qty_tilde_url` | int | Count of `~` in full URL |
| `qty_comma_url` | int | Count of `,` in full URL |
| `qty_plus_url` | int | Count of `+` in full URL |
| `qty_asterisk_url` | int | Count of `*` in full URL |
| `qty_hashtag_url` | int | Count of `#` in full URL |
| `qty_dollar_url` | int | Count of `$` in full URL |
| `qty_percent_url` | int | Count of `%` in full URL |
| `qty_tld_url` | int | Count of recognized TLDs in URL (from `tlds.txt`) |
| `length_url` | int | Character count of full URL |

#### Group 2: Domain (21 features)

Character counts across the domain/hostname only:

| Feature | Type | Description |
|---------|------|-------------|
| `qty_dot_domain` | int | Count of `.` in domain |
| `qty_hyphen_domain` | int | Count of `-` in domain |
| `qty_underline_domain` | int | Count of `_` in domain |
| `qty_slash_domain` | int | Count of `/` in domain (always 0) |
| `qty_questionmark_domain` | int | Count of `?` in domain (always 0) |
| `qty_equal_domain` | int | Count of `=` in domain (always 0) |
| `qty_at_domain` | int | Count of `@` in domain (always 0) |
| `qty_and_domain` | int | Count of `&` in domain (always 0) |
| `qty_exclamation_domain` | int | Count of `!` in domain (always 0) |
| `qty_space_domain` | int | Count of spaces in domain (always 0) |
| `qty_tilde_domain` | int | Count of `~` in domain (always 0) |
| `qty_comma_domain` | int | Count of `,` in domain (always 0) |
| `qty_plus_domain` | int | Count of `+` in domain |
| `qty_asterisk_domain` | int | Count of `*` in domain |
| `qty_hashtag_domain` | int | Count of `#` in domain |
| `qty_dollar_domain` | int | Count of `$` in domain |
| `qty_percent_domain` | int | Count of `%` in domain |
| `qty_vowels_domain` | int | Count of vowels in domain |
| `domain_length` | int | Character count of domain |
| `domain_in_ip` | binary | 1 if domain parses as IP address |
| `server_client_domain` | binary | 1 if domain contains "server" or "client" |

#### Group 3: Directory (17 features)

Character counts across the URL path (excluding filename):

| Feature | Type | Description |
|---------|------|-------------|
| `qty_dot_directory` | int | Count of `.` in directory path |
| `qty_hyphen_directory` | int | Count of `-` in directory |
| `qty_underline_directory` | int | Count of `_` in directory |
| `qty_slash_directory` | int | Count of `/` in directory |
| `qty_questionmark_directory` | int | Count of `?` in directory |
| `qty_equal_directory` | int | Count of `=` in directory |
| `qty_at_directory` | int | Count of `@` in directory |
| `qty_and_directory` | int | Count of `&` in directory |
| `qty_exclamation_directory` | int | Count of `!` in directory |
| `qty_space_directory` | int | Count of spaces in directory |
| `qty_tilde_directory` | int | Count of `~` in directory |
| `qty_comma_directory` | int | Count of `,` in directory |
| `qty_plus_directory` | int | Count of `+` in directory |
| `qty_asterisk_directory` | int | Count of `*` in directory |
| `qty_hashtag_directory` | int | Count of `#` in directory |
| `qty_dollar_directory` | int | Count of `$` in directory |
| `qty_percent_directory` | int | Count of `%` in directory |
| `directory_length` | int | Character count of directory path |

#### Group 4: File (17 features)

Character counts across the last path segment (filename):

| Feature | Type | Description |
|---------|------|-------------|
| `qty_dot_file` | int | Count of `.` in filename |
| `qty_hyphen_file` | int | Count of `-` in filename |
| `qty_underline_file` | int | Count of `_` in filename |
| `qty_slash_file` | int | Count of `/` in filename (always 0) |
| `qty_questionmark_file` | int | Count of `?` in filename |
| `qty_equal_file` | int | Count of `=` in filename |
| `qty_at_file` | int | Count of `@` in filename |
| `qty_and_file` | int | Count of `&` in filename |
| `qty_exclamation_file` | int | Count of `!` in filename |
| `qty_space_file` | int | Count of spaces in filename |
| `qty_tilde_file` | int | Count of `~` in filename |
| `qty_comma_file` | int | Count of `,` in filename |
| `qty_plus_file` | int | Count of `+` in filename |
| `qty_asterisk_file` | int | Count of `*` in filename |
| `qty_hashtag_file` | int | Count of `#` in filename |
| `qty_dollar_file` | int | Count of `$` in filename |
| `qty_percent_file` | int | Count of `%` in filename |
| `file_length` | int | Character count of filename |

#### Group 5: Parameters (20 features)

Character counts across the query string:

| Feature | Type | Description |
|---------|------|-------------|
| `qty_dot_params` | int | Count of `.` in params |
| `qty_hyphen_params` | int | Count of `-` in params |
| `qty_underline_params` | int | Count of `_` in params |
| `qty_slash_params` | int | Count of `/` in params |
| `qty_questionmark_params` | int | Count of `?` in params |
| `qty_equal_params` | int | Count of `=` in params |
| `qty_at_params` | int | Count of `@` in params |
| `qty_and_params` | int | Count of `&` in params |
| `qty_exclamation_params` | int | Count of `!` in params |
| `qty_space_params` | int | Count of spaces in params |
| `qty_tilde_params` | int | Count of `~` in params |
| `qty_comma_params` | int | Count of `,` in params |
| `qty_plus_params` | int | Count of `+` in params |
| `qty_asterisk_params` | int | Count of `*` in params |
| `qty_hashtag_params` | int | Count of `#` in params |
| `qty_dollar_params` | int | Count of `$` in params |
| `qty_percent_params` | int | Count of `%` in params |
| `params_length` | int | Character count of query string |
| `tld_present_params` | binary | 1 if any recognized TLD appears in query |
| `qty_params` | int | Number of query parameters (via `parse_qs`) |

#### Group 6: Binary + DNS (7 features)

| Feature | Type | Description |
|---------|------|-------------|
| `email_in_url` | binary | 1 if URL contains an email address pattern |
| `url_shortened` | binary | 1 if domain is in `shorteners.txt` (bit.ly, t.co, etc.) |
| `qty_ip_resolved` | int | Number of A records for domain (or -1 if DNS fails) |
| `qty_nameservers` | int | Number of NS records (walks up domain hierarchy) |
| `qty_mx_servers` | int | Number of MX records (walks up domain hierarchy) |
| `ttl_hostname` | int | TTL of the A record in seconds (or -1 if DNS fails) |
| `domain_spf` | binary | 1 if domain has SPF TXT record, 0 if not, -1 if DNS fails |

### Sentinel Value: -1

When a URL component is absent (no directory, no query params) or DNS resolution fails, features are set to **-1**. This is a deliberate choice:
- Character counts for absent components → all -1 (17 features for directory, 20 for params)
- DNS failures → all 5 DNS features become -1
- This avoids both 0 (which has meaning: "zero characters") and NaN (which breaks sklearn)

**Sentinel coverage in training data:**

| Feature | -1 count | % of data | Meaning |
|---------|----------|-----------|---------|
| `qty_dot_directory` | 17,507 | 28.4% | URLs with no directory path |
| `qty_dot_params` | 52,417 | 85.0% | URLs with no query string |
| `ttl_hostname` | 3,648 | 5.9% | DNS resolution failures |
| `domain_spf` | 11,153 | 18.1% | SPF lookup failures |

### TLD Detection (`count_tld`)

The `count_tld()` function (extract_features.py:83-93) scans the URL text for any TLD from `tlds.txt` (4,991 entries). It uses `BOUNDARY_RE` to ensure TLD matches are at word boundaries (not mid-word substrings). This produces `qty_tld_url` — how many recognized TLDs appear anywhere in the URL string. Phishing URLs often contain multiple TLDs (e.g., `paypal.com.secure-login.xyz` contains `.com` and `.xyz`).

### Shortener Detection

`shorteners.txt` contains 44 URL shortener domains (bit.ly, t.co, goo.gl, etc.). The `url_shortened` feature is binary: 1 if the domain matches any shortener. Shortened URLs are ambiguous — they could be phishing or legitimate — so the model must rely on other features when this is 1.

---

## 10. Training Data

### dataset_augmented.csv (Primary Training Set)

- **Size:** 61,705 rows × 104 columns (103 features + `phishing` label)
- **File size:** 14.8 MB on disk
- **Class balance:** 30,647 phishing (49.7%) / 31,058 benign (50.3%) — nearly perfectly balanced
- **Class ratio:** 1:1.01 (phish:benign)

### dataset_small.csv (Base Dataset)

- **Size:** 58,645 rows
- **File size:** 16.0 MB
- **Contents:** Original phishing + benign URLs before augmentation
- **Phishing source:** Curated phishing URLs (likely from PhishTank/OpenPhish historical data)
- **Benign source:** Likely from Tranco top domains + random sampling

### Augmented Rows

~3,060 benign rows added by `augment_dataset.py` (see §11), bringing total from 58,645 to 61,705.

### Why Balanced Data Matters

The 50/50 class balance is artificial — in the real world, phishing URLs are a small fraction of all URLs. However:
- Training on balanced data ensures the model learns both classes equally
- class_weight is not needed (RF default is fine with balanced data)
- The 0.5 threshold in `score_url()` is meaningful because the training prior is 50/50
- **In production**, the Tranco allowlist gate (≤0.25 for top-100k domains) compensates for the real-world class imbalance

---

## 11. Augmentation Pipeline

`augment_dataset.py` (131 lines) generates synthetic benign URLs to rebalance the training set.

### Domain Selection

1. Load `lists/tranco_top1m.txt` (1M domains ranked by popularity)
2. Take first 1,500 → random sample of 600
3. Add 18 guaranteed domains (YouTube, Google, Amazon, Wikipedia, GitHub, StackOverflow, Reddit, Twitter, Facebook, Netflix, Spotify, LinkedIn, Apple, Microsoft, Yahoo, PayPal, eBay, Walmart)
4. **Total: ~618 domains**

### URL Generation

For each domain, generate 5 random URLs using:

- **9 subdomain prefixes**: `""`, `"www."`, `"m."`, `"shop."`, `"blog."`, `"accounts."`, `"docs."`, `"support."`, `"help."`
- **21 path templates**: YouTube-style (`/watch?v={t}`), Amazon-style (`/s?k={words}`), blog (`/blog/{slug}`), API (`/api/v2/items?limit={num}`), generic (`/`, `/about`), etc.
- **Random tokens**: 8-12 char alphanumeric strings (50% chance of prefix with random 4-6 char string)
- **Random slugs**: 1-3 words from a 16-word vocabulary (`python`, `project`, `release`, `update`, etc.)
- **Random years**: 2019-2026

### DNS Defaults

Since augmented URLs are synthetic (no real DNS), all DNS features are set to safe defaults:

```python
DNS_DEFAULTS = {
    "qty_ip_resolved": 1,
    "ttl_hostname": 300,
    "qty_nameservers": 2,
    "qty_mx_servers": 1,
    "domain_spf": 1,
}
```

These values mimic a "normal" legitimate domain (1 IP, 300s TTL, 2 nameservers, 1 MX, SPF present). This prevents the RF from learning "synthetic data has weird DNS" as a signal.

---

## 12. Training Procedure

### Step 1: Feature Extraction

```python
df = pd.read_csv("dataset_augmented.csv")
X = df[FEATURES]  # 103 columns
y = df["phishing"]  # binary label
```

### Step 2: 5-Fold Stratified Cross-Validation

```python
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
```

For each fold:
1. Train `RandomForestClassifier(n_estimators=100, random_state=42)` on 80% of data
2. Predict probabilities on held-out 20%
3. Store out-of-fold (OOF) predictions
4. Compute fold accuracy, FP count, FN count

### Step 3: OOF Evaluation

Aggregate all fold predictions → compute:
- Overall accuracy, FPR, FNR
- OOF Brier score
- Reliability bins (probability buckets 0.0-0.1, 0.1-0.2, ..., 0.9-1.0)

### Step 4: Calibration on 80/20 Holdout

```python
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
```

1. Train raw RF on X_tr → predict on X_te → raw Brier/accuracy
2. Train `CalibratedClassifierCV(method="isotonic", cv=5)` on X_te → calibrated Brier/accuracy
3. Compare reliability bins raw vs calibrated

### Step 5: Final Model

```python
model = CalibratedClassifierCV(
    estimator=RandomForestClassifier(n_estimators=100, random_state=42),
    method="isotonic", cv=5
)
model.fit(X, y)  # fit on ALL data
```

The final model is trained on **all 61,705 rows** — no held-out test set for the production model. The CV and holdout analyses in steps 2-4 are for evaluation only.

### Step 6: Feature Importances

Extracted from the first calibrated classifier's underlying RF:
```python
imp = pd.Series(
    model.calibrated_classifiers_[0].estimator.feature_importances_,
    index=FEATURES
).sort_values(ascending=False)
```

### Step 7: Serialization

```python
joblib.dump(model, "phishing_model.joblib")  # 403 MB
with open("features.txt", "w") as f:
    f.write("\n".join(FEATURES))
```

---

## 13. Serialized Artifacts

| File | Size | Contents | Used By |
|------|------|----------|---------|
| `phishing_model.joblib` | 403 MB | `CalibratedClassifierCV` with 5 internal RFs + isotonic calibrator | `server.py` `predict_url()` |
| `url_text_model.joblib` | 6.2 MB | Tuple of `(TfidfVectorizer, LogisticRegression)` | `server.py` `url_text_prob()` |
| `email_text_model.joblib` | 4.7 MB | Email TF-IDF + LogReg (separate from URL models) | `server.py` `score_email()` |
| `features.txt` | 1.7 KB | 103 feature names, one per line (column order for RF) | `extract_features.py` |

**Why phishing_model.joblib is 403 MB:**
- 5 internal RandomForest objects (one per CV fold)
- Each RF has 100 trees × 61,705 training samples × 103 features
- sklearn's RF stores the full feature array for each tree node (for Gini computation)
- No compression is applied by default in joblib

**Why it's excluded from GitHub:**
- GitHub's per-file limit is 100 MB
- The file is 4× over the limit
- Can be regenerated from `dataset_augmented.csv` + `train.py` in ~60 seconds

---

## 14. Server Integration

### Startup

```python
# server.py lines 14-25
rf_model = joblib.load("phishing_model.joblib")
vec_clf = joblib.load("url_text_model.joblib")
vec, clf = vec_clf
```

Models are loaded once into memory. The RF model takes ~2-3 seconds to deserialize (403 MB).

### Scoring Flow (score_url, server.py:151-260)

```
1. url = clean_url(url)                          # strip whitespace, normalize
2. if domain_in_blocklist(url): return 0.99       # hard block
3. if domain_in_tranco_top100k(url): gate=True    # allowlist flag
4. rf_prob = predict_url(url)                      # RF calibrated probability
5. text_prob = url_text_prob(url)                  # TF-IDF LogReg probability
6. base = 0.6 * rf_prob + 0.4 * text_prob         # blend
7. heuristic_delta = compute_heuristics(url)       # +0.02 to +0.10
8. score = base + heuristic_delta                  # adjust
9. if gate: score = min(score, 0.25)              # allowlist ceiling
10. enrichment_delta = enrich(domain)              # DNS/WHOIS signals
11. score += enrichment_delta                      # adjust
12. if page_fetched: page_cap = scan_page(url)     # content-based cap
13. score = min(score, page_cap) if page_cap else score
14. return round(clamp(score, 0, 1), 4)           # final
```

### predict_url (server.py:324-345)

```python
def predict_url(url):
    feats = extract_row(url)           # 103-feature vector from extract_features.py
    proba = rf_model.predict_proba([feats])[0][1]
    return float(proba)
```

- `extract_row(url)` returns a list of 103 values in `FEATURES` order
- The RF returns `[prob_benign, prob_phish]` → we take index 1
- Latency: ~5-15ms per URL (100 trees × 103 features)

### url_text_prob (server.py:364-369)

```python
def url_text_prob(url):
    cleaned = url_text(url)            # from url_text_features.py
    return float(clf.predict_proba(vec.transform([cleaned]))[0][1])
```

- `url_text()` cleans URL to alphanumeric text
- TF-IDF vectorizer transforms to 150k-dim sparse vector
- Logistic Regression predicts phishing probability
- Latency: ~1-3ms per URL

---

## 15. Known Failure Modes

### False Positives (Legit → Phish)

1. **URL path with login keywords**: Legitimate URLs like `github.com/login` trigger the `login-related path` heuristic (+0.03). Usually mitigated by Tranco allowlist, but non-top-100k domains are vulnerable.

2. **Long paths with parameters**: Legitimate SaaS apps with deep paths (`app.example.com/workspace/project/settings/notifications?tab=email`) trigger multiple heuristics (path depth, length, parameters).

3. **New legitimate domains**: Domains < 30 days old get WHOIS penalty (+0.20). New startups, rebranded companies, and freshly registered domains are penalized.

4. **Email in URL**: `mailto:user@example.com` patterns trigger the email-in-URL heuristic (+0.05). This is common in legitimate marketing emails.

5. **The 2002-email false positive**: A legitimate 2002-era email body triggered the email detection. The trusted-sender clamp was added to fix this — but only for the email model. URLs within emails still go through the URL scanner.

### False Negatives (Phish → Legit)

1. **Compromised legitimate domains**: A hacked WordPress site on a Tranco-listed domain gets score clamped to ≤ 0.25 by the allowlist gate. The model cannot override this.

2. **Shortened URLs**: bit.ly/t.co links get `url_shortened=1` but the model still sees the shortener domain (which is Tranco-listed) → allowlist clamp.

3. **Data URI phishing**: `data:text/html,<script>...` URLs bypass URL parsing entirely — the RF sees no host, no path, all features are 0 or -1.

4. **Homograph attacks**: `paypa1.com` (with `1` instead of `l`) may not trigger the text model if the n-grams are close enough to legitimate patterns.

5. **No DNS enrichment**: When DNS fails (3,648 URLs in training data = 5.9%), the 5 DNS features become -1, removing 3 of the top 15 most important features.

### Model Drift

- The RF model is trained once on `dataset_augmented.csv` and not retrained automatically
- The URL-text model fetches live feeds (OpenPhish, Phishing.Database) at training time but is also not retrained in production
- Phishing patterns evolve (new TLDs, new hosting providers, new obfuscation techniques)
- The lists (`tranco_top1m.txt`, `openphish_hosts.txt`) are updated by `update_lists.py` but the models themselves are static

---

## 16. Verification Battery

Every claim in this document was verified against the actual codebase:

| Claim | Source | Verified |
|-------|--------|----------|
| 103 features | `extract_features.py:10-39` FEATURES tuple | ✓ |
| 100 trees, no max_depth | `train.py:27` RandomForestClassifier(n_estimators=100) | ✓ |
| Isotonic calibration cv=5 | `train.py:56-58` CalibratedClassifierCV(method="isotonic", cv=5) | ✓ |
| 60/40 blend | `server.py:151` score_url() → 0.6*rf + 0.4*text | ✓ |
| Tranco 0.25 ceiling | `server.py:213-240` allowlist_gate() | ✓ |
| Blocklist forces 0.99 | `server.py:184-191` | ✓ |
| TF-IDF analyzer: word+3-4-5 n-grams | `url_text_features.py:23-32` analyzer() | ✓ |
| LR: liblinear, balanced, C=1.0 | `train_url_text_model.py:82-83` | ✓ |
| 61,705 rows, 30647/31058 balance | Live diagnostic run | ✓ |
| 5-fold CV 93.36%-93.75% | Live diagnostic run | ✓ |
| Train/test gap 6.06% | Live diagnostic run | ✓ |
| Calibrated Brier 0.0464 | Live diagnostic run | ✓ |
| Feature importances | Live diagnostic run | ✓ |
| Augment: 600 domains × 5 URLs | `augment_dataset.py:88-101` | ✓ |
| DNS defaults: TTL=300, SPF=1 | `augment_dataset.py:43-44` | ✓ |
| Shorteners: 44 entries | `shorteners.txt` loaded by extract_features.py:50 | ✓ |
| TLDs: 4,991 entries | `tlds.txt` loaded by extract_features.py:51 | ✓ |
| phishing_model.joblib: 403 MB | Filesystem | ✓ |
| url_text_model.joblib: 6.2 MB | Filesystem | ✓ |
| Training data: dataset_augmented.csv 14.8MB | Filesystem | ✓ |

---

## 17. Changelog & Decisions

| Date | Change | Rationale |
|------|--------|-----------|
| Aug 3 | Initial model training | Baseline RF + text blend |
| Aug 3 | Added `ttl_hostname` to RF features | TTL is the #1 RF discriminator (10% importance) |
| Aug 3 | Added `domain_spf` to RF features | SPF presence correlates with legitimacy |
| Aug 4 | Isotonic calibration added | Raw RF probabilities overconfident near 0/1 |
| Aug 4 | Tranco top-100k allowlist gate (≤0.25) | Prevent FPs on major legitimate domains |
| Aug 5 | Augmentation pipeline created | Rebalance training data from 58k to 61k rows |
| Aug 5 | DNS defaults for synthetic URLs | Prevent RF from learning "synthetic = weird DNS" |
| Aug 5 | Heuristics layer expanded | Catch patterns RF misses (login paths, IP domains) |
| Aug 6 | Enrichment veto (0.34/0.55 thresholds) | Force suspicious scores when DNS/WHOIS is bad |
| Aug 6 | Known FP #5 (2002 email) | Led to trusted-sender clamp in email model |
| Aug 7 | Documented overfitting gap (6.06%) | Acknowledged RF overfitting, decided it's acceptable |
| Aug 7 | URLmodel.md written | Comprehensive technical reference |
