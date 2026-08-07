import concurrent.futures
import hashlib
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime

_MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model")
sys.path.insert(0, os.path.join(_MODEL_DIR, "src"))
_TRAINED_DIR = os.path.join(_MODEL_DIR, "trained")

import dns.resolver
import joblib
import pandas as pd
import requests
import urllib3
import whois
from flask import Flask, jsonify, request
from flask_cors import CORS
from spellchecker import SpellChecker

from extract_features import extract, parse_url, valid_ip
from email_text_features import clean_email
from url_text_features import url_text

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

model = joblib.load(os.path.join(_TRAINED_DIR, "phishing_model.joblib"))
feature_cols = [line.strip() for line in open(os.path.join(_TRAINED_DIR, "features.txt")) if line.strip()]

try:
    url_text_vec, url_text_clf = joblib.load(os.path.join(_TRAINED_DIR, "url_text_model.joblib"))
except Exception:
    url_text_vec = url_text_clf = None

try:
    email_text_model = joblib.load(os.path.join(_TRAINED_DIR, "email_text_model.joblib"))
except Exception:
    email_text_model = None

LISTS_DIR = os.path.join(_MODEL_DIR, "lists")


def _load_hosts(name):
    path = os.path.join(LISTS_DIR, name)
    try:
        with open(path) as f:
            return set(line.strip().lower() for line in f if line.strip())
    except OSError:
        return set()


ALLOW = _load_hosts("tranco_top1m.txt")
BLOCK = _load_hosts("openphish_hosts.txt")

CHEAP_TLDS = {
    "xyz", "top", "club", "online", "site", "live", "click", "link", "icu",
    "vip", "fun", "work", "space", "store", "buzz", "cyou", "rest", "token",
    "ga", "gq", "ml", "tk", "cf",
}

HOMOGLYPHS = {
    "а": "a", "б": "b", "в": "b", "г": "r", "д": "g", "е": "e", "ё": "e",
    "ж": "x", "з": "3", "и": "n", "й": "u", "к": "k", "л": "l", "м": "m",
    "н": "h", "о": "o", "п": "n", "р": "p", "с": "c", "т": "t", "у": "y",
    "ф": "o", "х": "x", "ц": "c", "ч": "4", "ш": "w", "щ": "w", "ъ": "b",
    "ы": "b", "ь": "b", "э": "e", "ю": "o", "я": "r",
    "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e", "ζ": "z", "η": "h",
    "θ": "0", "ι": "i", "κ": "k", "λ": "l", "μ": "m", "ν": "v", "ξ": "x",
    "ο": "o", "π": "n", "ρ": "p", "σ": "s", "ς": "s", "τ": "t", "υ": "u",
    "φ": "o", "χ": "x", "ψ": "y", "ω": "w",
    "ѕ": "s", "і": "i", "ј": "j", "ſ": "s", "ı": "i", "ł": "l", "đ": "d",
    "ð": "d", "þ": "p", "ß": "b", "œ": "oe", "æ": "ae",
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e", "ｆ": "f", "ｇ": "g",
    "ｈ": "h", "ｉ": "i", "ｊ": "j", "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n",
    "ｏ": "o", "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t", "ｕ": "u",
    "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y", "ｚ": "z",
    "1": "l", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t",
}

SUSPICIOUS_PHRASES = [
    "account", "signin", "sign-in", "login", "log-in", "logon", "verify",
    "verification", "confirm", "validation", "authenticate", "update", "unlock",
    "reactivate", "recover", "restore", "reset-password", "password", "credential",
    "secure", "secure-login", "bank", "banking", "online-banking", "webmail",
    "billing", "invoice", "payment", "wallet", "crypto", "bitcoin", "giftcard",
    "gift-card", "reward", "prize", "bonus", "giveaway", "winner", "claim",
    "coupon", "sponsor", "promo", "suspended", "suspension", "unusual",
    "security-alert", "temporarily", "limited", "expired", "restricted", "blocked",
    "locked", "terminated", "deactivated", "urgent", "immediate", "action-required",
    "support", "helpdesk", "official", "notification", "customer-service",
    "login-id", "user-id",
    "sale", "forsale", "deals", "auction", "outlet", "clearance", "wholesale",
]

OFFENSIVE_WORDS = {
    "nigger", "niggers", "faggot", "faggots", "cunt", "cunts", "slut", "sluts",
    "whore", "whores", "bitch", "bitches", "fuck", "fucking", "shit", "shitty",
    "rape", "rapist", "nazi", "hitler", "heil", "kkk", "kike", "spic",
    "tranny", "dyke", "retard", "retarded",
}

BLACK_MARKET_WORDS = {
    "drugs", "cocaine", "heroin", "meth", "fentanyl", "viagra", "cialis",
    "xanax", "adderall", "oxy", "oxycontin", "poker", "casino", "gambling",
    "betting", "jackpot", "lottery", "porn", "escort", "payday", "bitcoin",
    "crypto",
}

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
BAD_EXTENSIONS = (".exe", ".scr", ".bat", ".vbs", ".js", ".jar", ".ps1", ".lnk", ".docm", ".hta")

URGENT_PHRASES = [
    "urgent", "immediately", "act now", "verify your account", "verify your identity",
    "suspended", "account locked", "unusual activity", "security alert", "password expired",
    "click here", "you have won", "claim your prize", "limited time", "update your payment",
    "confirm your details", "your account will be closed",
]
LANGUAGE_TOOL_URL = "https://api.languagetool.org/v2/check"
GREETING_PATTERNS = (
    "dear user", "dear customer", "dear member", "dear friend", "dear sir",
    "dear sir/madam", "dear account holder", "dear valued customer",
    "hello user", "hello customer", "dear beneficiary",
)
spell = SpellChecker(language="en")
VERDICT_COLORS = {"safe": "#22c55e", "medium": "#f59e0b", "danger": "#ff3b3b", "critical": "#8b0000"}
VERDICT_LABELS = {"safe": "Safe", "medium": "Suspicious", "danger": "Threat", "critical": "Critical"}
VERDICT_CONCLUSIONS = {
    "safe": "No significant phishing indicators detected.",
    "medium": "Some suspicious signals found. Review carefully before proceeding.",
    "danger": "Strong indicators of phishing. Do not enter any credentials.",
    "critical": "High-confidence phishing URL. Blocked.",
}


def risk_from_prob(prob):
    if prob < 0.35:
        return "safe"
    if prob < 0.60:
        return "medium"
    if prob < 0.80:
        return "danger"
    return "critical"


def confidence_from_prob(prob):
    return min(99, round(max(prob, 1 - prob) * 100))


def predict_url(url):
    feats = extract(url)
    row = pd.DataFrame([feats])[feature_cols]
    prob = float(model.predict_proba(row)[0][1])
    return prob, feats


BRANDS = {
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "microsoft": "microsoft.com",
    "outlook": "outlook.com",
    "netflix": "netflix.com",
    "linkedin": "linkedin.com",
    "twitter": "twitter.com",
    "youtube": "youtube.com",
    "yahoo": "yahoo.com",
    "dropbox": "dropbox.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "citibank": "citibank.com",
    "payoneer": "payoneer.com",
    "stripe": "stripe.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "metamask": "metamask.io",
    "ebay": "ebay.com",
    "walmart": "walmart.com",
    "tiktok": "tiktok.com",
}
SLDS = {
    ".co.uk", ".org.uk", ".ac.uk", ".gov.uk", ".me.uk",
    ".com.au", ".org.au", ".net.au", ".com.nz", ".co.nz",
    ".co.jp", ".co.in", ".org.in", ".net.in", ".com.sg",
    ".com.hk", ".com.cn", ".co.id", ".com.my", ".com.ph",
    ".com.tr", ".co.il", ".co.za", ".com.br", ".com.mx",
    ".com.ar", ".com.co", ".com.eg", ".com.sa", ".com.ng",
    ".com.ua", ".com.tw", ".com.kr", ".co.th", ".com.vn",
    ".com.pk", ".com.bd", ".co.ke", ".com.gh",
}
TLD_WORDS = {"com", "net", "org", "co", "info", "biz", "io"}


def _edit_distance(a, b):
    m, n = len(a), len(b)
    if abs(m - n) > 2:
        return 99
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        for j in range(1, n + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] != b[j - 1]))
        prev = cur
    return prev[n]


def host_parts(host):
    labels = host.lower().split(".")
    if len(labels) < 2:
        return [], "", ""
    if len(labels) >= 3 and "." + ".".join(labels[-2:]) in SLDS:
        return labels[:-3], labels[-3], ".".join(labels[-2:])
    return labels[:-2], labels[-2], labels[-1]


def normalize(s):
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in s.lower())


def _allowlisted(host):
    labels = host.split(".")
    for i in range(len(labels)):
        if ".".join(labels[i:]) in ALLOW:
            return True
    return False


def _allowlist_suffix_len(host):
    labels = host.split(".")
    for i in range(len(labels)):
        if ".".join(labels[i:]) in ALLOW:
            return len(labels) - i
    return 0


def heuristic_risk(host):
    subdomains, registrable, tld = host_parts(host)
    low = host.lower()
    reasons = []

    if _allowlisted(low):
        exempt = _allowlist_suffix_len(low)
        prefix = low.split(".")[:-exempt] if exempt else []
        if not prefix:
            return None
        for brand, _real in BRANDS.items():
            for label in prefix:
                norm = normalize(label)
                if norm == brand:
                    continue
                if _edit_distance(norm, brand) <= 2:
                    reasons.append(f"Domain '{label}' closely resembles the brand '{brand}'")
                elif len(norm) > len(brand) and (
                    norm.startswith(brand + "-")
                    or norm.endswith("-" + brand)
                    or f"-{brand}-" in norm
                    or any(ch.isdigit() for ch in norm)
                ) and brand in norm:
                    reasons.append(f"Brand '{brand}' embedded inside domain '{label}'")
        for label in prefix:
            if label in TLD_WORDS:
                reasons.append(f"TLD-like word '{label}' used as a subdomain label")
            if label.startswith("xn--"):
                reasons.append("IDN/punycode encoded domain label")
        if not reasons:
            return None
        prob = 0.62 + min(len(reasons), 3) * 0.05
        return min(prob, 0.80), reasons

    all_labels = list(subdomains)
    if registrable:
        all_labels.append(registrable)
    reasons = []

    for brand, real in BRANDS.items():
        if low == real or low.endswith("." + real):
            continue
        for label in all_labels:
            norm = normalize(label)
            if norm == brand:
                if label in subdomains:
                    reasons.append(f"Brand '{brand}' appears as a subdomain of an unrelated domain")
            elif _edit_distance(norm, brand) <= 2:
                reasons.append(f"Domain '{label}' closely resembles the brand '{brand}'")
            elif len(norm) > len(brand) and (
                norm.startswith(brand + "-")
                or norm.endswith("-" + brand)
                or f"-{brand}-" in norm
                or any(ch.isdigit() for ch in norm)
            ) and brand in norm:
                reasons.append(f"Brand '{brand}' embedded inside domain '{label}'")
    for label in subdomains:
        if label in TLD_WORDS:
            reasons.append(f"TLD-like word '{label}' used as a subdomain label")
    if registrable in TLD_WORDS and tld in CHEAP_TLDS:
        reasons.append(f"TLD-like word '{registrable}' used before a cheap TLD '{tld}'")

    if any(label.startswith("xn--") for label in all_labels):
        reasons.append("IDN/punycode encoded domain label")

    for phrase in SUSPICIOUS_PHRASES:
        if phrase in low:
            reasons.append(f"Suspicious keyword '{phrase}' in domain name")
    for word in OFFENSIVE_WORDS:
        if word in low:
            reasons.append(f"Offensive term '{word}' in domain name")
    for word in BLACK_MARKET_WORDS:
        if word in low:
            reasons.append(f"Black-market keyword '{word}' in domain name")

    if not reasons:
        return None
    prob = 0.62 + min(len(reasons), 3) * 0.05
    return min(prob, 0.80), reasons


def score_url(url):
    prob, feats = predict_url(url)
    host = parse_url(url)["host"].lower()
    rule = None
    subdomains, registrable, _ = host_parts(host)

    # Hard signal 1: known phishing blocklist.
    if host in BLOCK or (registrable and registrable in BLOCK):
        prob = max(prob, 0.95)
        rule = (prob, ["Domain listed on known phishing blocklist (OpenPhish)"])
        return prob, feats, rule

    # Hard signal 2: structural heuristics (brand spoof, TLD tricks, phrases...).
    heur = heuristic_risk(host)

    # Trusted-domain gate: hosts under a top-1M allowlisted suffix are safe by
    # default. The learned models are suppressed so realistic URL shapes
    # (watch?v=..., ?q=..., /products?id=5) can't trigger false positives.
    # Only a hard heuristic flag (e.g. brand-resemblance prefix) can override.
    if _allowlisted(host):
        if heur:
            prob = max(prob, heur[0])
            rule = heur
        else:
            prob = min(prob, 0.25)
        return prob, feats, rule

    text_prob = url_text_prob(url, host)
    if heur:
        prob = max(prob, heur[0], text_prob or 0.0)
        rule = heur
        return prob, feats, rule

    # Untrusted, no hard rule: blend the two learned models so a single
    # overconfident scorer can't win on its own.
    if text_prob is not None:
        prob = 0.6 * prob + 0.4 * text_prob
    return prob, feats, rule


def url_text_prob(url, host):
    if url_text_vec is None or url_text_clf is None:
        return None
    if _allowlisted(host) or valid_ip(host):
        return None
    try:
        return float(url_text_clf.predict_proba(
            url_text_vec.transform([url_text(url)]))[0][1])
    except Exception:
        return None


def ssl_check(host, timeout=2):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                now = datetime.now()
                return "Valid" if not_before < now < not_after else "Invalid"
    except Exception:
        return "Invalid"


def build_verdict(risk):
    return {
        "label": VERDICT_LABELS[risk],
        "color": VERDICT_COLORS[risk],
        "conclusion": VERDICT_CONCLUSIONS[risk],
    }


CACHE = {}


def cached(key, ttl, fn):
    now = time.time()
    hit = CACHE.get(key)
    if hit and now - hit[0] < ttl:
        return hit[1]
    value = fn()
    CACHE[key] = (now, value)
    return value


def redirect_check(url, timeout=4):
    try:
        resp = requests.get(
            url,
            allow_redirects=False,
            timeout=timeout,
            verify=False,
            stream=True,
            headers={"User-Agent": "Mozilla/5.0 PhisDetect/1.0"},
        )
        resp.close()
        return "Detected" if 300 <= resp.status_code < 400 else "None"
    except Exception:
        return "None"


def blacklist_check(host, timeout=4):
    try:
        for suffix in ("multi.surbl.org", "dbl.spamhaus.org"):
            try:
                answers = dns.resolver.resolve(f"{host}.{suffix}", "A", lifetime=timeout)
                if any(str(a.address).startswith("127.") for a in answers):
                    return "Flagged"
            except dns.resolver.NXDOMAIN:
                continue
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.LifetimeTimeout:
                return "Clear"
        return "Clear"
    except Exception:
        return "Clear"


def _whois_created(host):
    w = whois.whois(host)
    created = w.creation_date
    if isinstance(created, list):
        created = created[0]
    if created is None:
        return None
    if isinstance(created, str):
        created = datetime.fromisoformat(created.replace("Z", "+00:00"))
    if created.tzinfo is not None:
        created = created.replace(tzinfo=None)
    return created


def domain_age(host, timeout=7):
    def run():
        try:
            created = _whois_created(host)
        except Exception:
            return "Unknown"
        if created is None:
            return "Unknown"
        age = datetime.now() - created
        if age.total_seconds() <= 0:
            return "Unknown"
        days = age.days
        if days < 1:
            return f"{max(int(age.total_seconds() // 3600), 1)} hours"
        if days < 90:
            return f"{days} days"
        if days < 730:
            return f"{int(days / 30.44)} months"
        return f"{days / 365.25:.1f} years"

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(run)
        try:
            return fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            return "Unknown"


def enrich(url, host, https):
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    try:
        futs = {
            "domainAge": ex.submit(lambda: cached(f"age:{host}", 1800, lambda: domain_age(host))),
            "redirection": ex.submit(lambda: cached(f"redir:{url}", 300, lambda: redirect_check(url))),
            "blacklist": ex.submit(lambda: cached(f"bl:{host}", 600, lambda: blacklist_check(host))),
        }
        if https:
            futs["sslStatus"] = ex.submit(lambda: cached(f"ssl:{host}", 300, lambda: ssl_check(host)))
        defaults = {"domainAge": "Unknown", "sslStatus": "Invalid", "redirection": "None", "blacklist": "Clear"}
        out = dict(defaults)
        for key, fut in futs.items():
            try:
                out[key] = fut.result(timeout=12)
            except Exception:
                out[key] = defaults[key]
    finally:
        ex.shutdown(wait=False)
    return out


def _established_domain(extra):
    age = extra.get("domainAge", "") or ""
    if isinstance(age, str) and "year" in age:
        try:
            return float(age.split()[0]) >= 2
        except ValueError:
            return False
    return False


PAGE_CREDENTIAL_RE = re.compile(
    r'<input[^>]*type\s*=\s*["\']?password["\']?'
    r'|name\s*=\s*["\']?(?:password|passwd|card_number|cardnumber|card-num|cvv|cvc|ssn)["\']?',
    re.IGNORECASE)
PAGE_FORM_ACTION_RE = re.compile(r'<form[^>]*action\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
PAGE_META_REFRESH_RE = re.compile(
    r'<meta[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*url\s*=\s*["\']?([^"\';\s>]+)',
    re.IGNORECASE)
PAGE_JS_REDIRECT_RE = re.compile(
    r'(?:window|document)\.location(?:\.href)?\s*[=:]\s*["\'](https?://[^"\']+)["\']',
    re.IGNORECASE)
PAGE_TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
CRED_WORDS = ("ssn", "social security", "card number", "cvv", "cvc", "credit card details")


def _page_site(target):
    """Registrable site label of a URL/fragment; IPs and failures return the full host.

    Same rule applied to both sides of every comparison, so detection stays correct;
    this only fixes the labels shown to the user."""
    try:
        host = parse_url(target)["host"].lower()
    except Exception:
        return None
    if not host:
        return None
    if ":" in host and not host.startswith("["):
        host = host.split(":")[0]
    if not host:
        return None
    if valid_ip(host):
        return host
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _page_target_trusted(target):
    """True if the target of a redirect/form-action is itself an allowlisted (top-1M) site."""
    try:
        return _allowlisted(parse_url(target)["host"].lower())
    except Exception:
        return False


def fetch_page(url, timeout=4, max_bytes=1_000_000):
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhisDetect/1.0"},
        )
        if resp.status_code >= 400:
            resp.close()
            return None
        chunks = []
        size = 0
        for chunk in resp.iter_content(8192):
            chunks.append(chunk.decode("utf-8", errors="ignore"))
            size += len(chunks[-1])
            if size >= max_bytes:
                break
        resp.close()
        return {"html": "".join(chunks), "final_url": resp.url, "history": [r.url for r in resp.history]}
    except Exception:
        return None


def page_scan(url, host, prob, rule):
    """Fetch the target page and look for credential-harvesting / phish-kit signals.

    Skips allowlisted hosts (already gated) and already-critical results.
    Returns (signals, bump)."""
    if _allowlisted(host) or prob >= 0.85:
        return [], 0.0
    page = fetch_page(url)
    if page is None:
        return [], 0.0
    html = page["html"]
    low_html = html.lower()
    signals = []
    bump = 0.0
    my_site = _page_site(host)

    final_site = _page_site(page["final_url"])
    if (page["history"] and final_site and final_site != my_site
            and not _page_target_trusted(page["final_url"])):
        signals.append(f"Redirects to '{final_site}', a different site from '{my_site}'")
        bump += 0.15

    for m in PAGE_META_REFRESH_RE.finditer(html):
        target_site = _page_site(m.group(1))
        if (target_site and target_site != my_site
                and not _page_target_trusted(m.group(1))):
            signals.append(f"Meta-refresh redirects to '{target_site}'")
            bump += 0.15
            break
    for m in PAGE_JS_REDIRECT_RE.finditer(html):
        target_site = _page_site(m.group(1))
        if (target_site and target_site != my_site
                and not _page_target_trusted(m.group(1))):
            signals.append(f"JavaScript redirects to '{target_site}'")
            bump += 0.15
            break

    has_form = "<form" in low_html or "<input" in low_html
    cred_fields = bool(PAGE_CREDENTIAL_RE.search(html))
    cred_words = any(w in low_html for w in CRED_WORDS)
    if cred_fields:
        signals.append("Page requests credentials (password / card / SSN fields)")
        bump += 0.25
    elif cred_words and has_form:
        signals.append("Page contains a credential-harvesting form")
        bump += 0.15
    elif has_form and len(html) < 2500:
        signals.append("Very short page containing a form (phish-kit pattern)")
        bump += 0.10

    for m in PAGE_FORM_ACTION_RE.finditer(html):
        action_site = _page_site(m.group(1))
        if (action_site and action_site != my_site
                and not _page_target_trusted(m.group(1))):
            signals.append(f"Form submits to '{action_site}', not '{my_site}'")
            bump += 0.20
            break

    tm = PAGE_TITLE_RE.search(html)
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1)).strip().lower()[:80]
        for brand, real in BRANDS.items():
            if brand in title and host != real and not host.endswith("." + real):
                signals.append(f"Page title mentions '{brand}' but host is not '{real}'")
                bump += 0.15
                break

    return signals, min(bump, 0.40)


@app.post("/api/scan/url")
def scan_url():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Missing 'url' field"}), 400
    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    prob, feats, rule = score_url(url)
    host = parse_url(url)["host"].lower()

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    try:
        fut_enrich = ex.submit(enrich, url, host, url.startswith("https://"))
        fut_page = ex.submit(page_scan, url, host, prob, rule)
        try:
            extra = fut_enrich.result(timeout=20)
        except Exception:
            extra = {"domainAge": "Unknown", "sslStatus": "Invalid",
                     "redirection": "None", "blacklist": "Clear"}
        try:
            page_signals, page_bump = fut_page.result(timeout=8)
        except Exception:
            page_signals, page_bump = [], 0.0
    finally:
        ex.shutdown(wait=False)

    prob = min(prob + page_bump, 0.99)

    # Enrichment veto: a domain registered 2+ years ago with a valid TLS cert,
    # flagged only by the learned models (no heuristic/blocklist rule), is very
    # unlikely to be phishing. Downgrade to at most medium.
    if rule is None and _established_domain(extra):
        if extra.get("sslStatus") == "Valid":
            prob = min(prob, 0.34)
        else:
            prob = min(prob, 0.55)

    risk = risk_from_prob(prob)
    confidence = confidence_from_prob(prob)

    return jsonify({
        "risk": risk,
        "confidence": confidence,
        "verdict": build_verdict(risk),
        "domainAge": extra["domainAge"],
        "sslStatus": extra["sslStatus"],
        "redirection": extra["redirection"],
        "blacklist": extra["blacklist"],
        "pageSignals": page_signals,
        "indicators": (rule[1] if rule else []) + page_signals,
    })


def email_urls(content):
    return list(dict.fromkeys(URL_RE.findall(content)))


def grammar_hits(content):
    low = content.lower()
    return sum(1 for phrase in URGENT_PHRASES if phrase in low)


def grammar_level(content):
    hits = grammar_hits(content)
    if hits == 0:
        return "None"
    if hits == 1:
        return "Minor"
    if hits <= 3:
        return "Moderate"
    return "High"


def attachment_count(content):
    files = re.findall(r'["\']?[\w-]+\.\w+["\']?', content)
    return sum(1 for f in files if f.lower().endswith(BAD_EXTENSIONS))


def _domain_brand_spoof_reason(domain):
    """Return a reason if the From domain impersonates a brand, else None.

    Real brand domains and their subdomains (microsoft.com, login.microsoft.com)
    are exempt; anything else containing/embedding/resembling a brand is a spoof."""
    low = (domain or "").strip().lower().rstrip(".")
    if not low or valid_ip(low):
        return None
    labels = low.split(".")
    for brand, real in BRANDS.items():
        if low == real or low.endswith("." + real):
            continue
        for i, label in enumerate(labels):
            norm = normalize(label)
            if norm == brand:
                parent = ".".join(labels[i + 1:])
                if parent and not parent.endswith(real) and parent != real:
                    return f"From domain '{low}' contains brand '{brand}' but is not '{real}'"
            elif _edit_distance(norm, brand) <= 2:
                return f"From domain '{low}' closely resembles brand '{brand}' but is not '{real}'"
            elif len(norm) > len(brand) and (
                norm.startswith(brand + "-")
                or norm.endswith("-" + brand)
                or f"-{brand}-" in norm
                or any(ch.isdigit() for ch in norm)
            ) and brand in norm:
                return f"From domain '{low}' embeds brand '{brand}' but is not '{real}'"
    return None


def spoof_detected(content):
    low = content.lower()
    from_match = re.search(r"from:\s*([\w.+-]+@[\w-]+\.[\w.]+)", low)
    reply_match = re.search(r"reply-to:\s*([\w.+-]+@[\w-]+\.[\w.]+)", low)
    if from_match and reply_match:
        from_domain = from_match.group(1).split("@")[-1]
        reply_domain = reply_match.group(1).split("@")[-1]
        if from_domain != reply_domain:
            return "Yes"
    impersonation = re.search(r"from:\s*(?:[^<\n]*<)?([\w.+-]+@[\w-]+\.[\w.]+)>?", low)
    if impersonation:
        addr_domain = impersonation.group(1).split("@")[-1]
        local = impersonation.group(1).split("@")[0]
        trusted_domain = (_allowlisted(addr_domain) or
                          any(addr_domain == real or addr_domain.endswith("." + real)
                              for real in BRANDS.values()))
        if not trusted_domain and any(word in local
                                      for word in ("security", "support", "admin", "service", "verify")):
            return "Yes"
        if _domain_brand_spoof_reason(addr_domain):
            return "Yes"
    return "No"


def from_domain(content):
    m = re.search(r"from:\s*(?:[^<\n]*<)?([\w.+-]+@[\w-]+\.[\w.]+)>?", content.lower())
    if m:
        return m.group(1).split("@")[-1].strip().lower()
    return None


DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1"]


def _lookup_txt(name, timeout=4):
    """Return (records, state) with state in {'ok', 'none', 'error'}."""
    try:
        ans = dns.resolver.resolve(name, "TXT", lifetime=timeout)
        return [r.to_text() for r in ans], "ok"
    except dns.resolver.NXDOMAIN:
        return [], "none"
    except dns.resolver.NoAnswer:
        return [], "ok"
    except Exception:
        return [], "error"


def sender_auth(domain, timeout=4):
    """Check SPF, DMARC and DKIM for a sender domain.

    Returns {'spf','dmarc','dkim'} with values:
      'present' | 'absent' | 'domain_missing' | 'unknown'
    or None if no usable domain."""
    domain = (domain or "").strip().lower()
    if not domain or valid_ip(domain):
        return None

    def spf_state():
        recs, state = _lookup_txt(domain)
        if state == "error":
            return "unknown"
        if state == "none":
            return "domain_missing"
        return "present" if any("v=spf1" in r for r in recs) else "absent"

    def dmarc_state():
        recs, state = _lookup_txt("_dmarc." + domain)
        if state == "error":
            return "unknown"
        return "present" if any("v=dmarc1" in r.lower() for r in recs) else "absent"

    def dkim_state():
        for sel in DKIM_SELECTORS:
            recs, state = _lookup_txt(f"{sel}._domainkey.{domain}", timeout=3)
            if state == "error":
                continue
            if any("v=dkim1" in r.lower() or " p=" in r.lower() or r.lower().startswith("p=")
                   for r in recs):
                return "present"
        return "absent"

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    try:
        fs = {"spf": ex.submit(spf_state),
              "dmarc": ex.submit(dmarc_state),
              "dkim": ex.submit(dkim_state)}
        concurrent.futures.wait(list(fs.values()), timeout=timeout)
        return {k: (f.result() if f.done() else "unknown") for k, f in fs.items()}
    finally:
        ex.shutdown(wait=False)


def auth_signals(auth, domain, prob):
    """Only flag missing auth records when the email is already suspicious."""
    if not auth:
        return [], 0.0
    indicators = []
    bump = 0.0
    if auth.get("spf") == "domain_missing":
        indicators.append(f"Sender domain '{domain}' does not resolve in DNS")
        bump = max(bump, 0.20)
    if prob < 0.5:
        return indicators, bump
    absent = [k for k in ("spf", "dmarc", "dkim") if auth.get(k) == "absent"]
    if len(absent) >= 2:
        indicators.append(f"Sender domain '{domain}' publishes no SPF/DMARC/DKIM records")
        bump = max(bump, 0.20)
    elif len(absent) == 1:
        indicators.append(f"Sender domain '{domain}' has no {absent[0].upper()} record")
        bump = max(bump, 0.10)
    return indicators, bump


def _sentences(content):
    return [p.strip() for p in re.split(r"[.!?]+\s+", content) if len(p.strip()) >= 3]


def grammar_issues(content):
    issues = []
    low = content.lower()
    for greeting in GREETING_PATTERNS:
        if greeting in low:
            issues.append(f"Generic greeting ('{greeting}') — no personalization")
            break
    lower_starts = len(re.findall(r"[.!?]\s+([a-z])", content))
    if lower_starts >= 2:
        issues.append(f"{lower_starts} sentences start with a lowercase letter")
    sanitized = re.sub(r"[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+", " EMAIL ", content)
    sanitized = URL_RE.sub(" URL ", sanitized)
    missing_space = len(re.findall(
        r"(?<=[a-z])[,;](?=[a-zA-Z])|(?<=[a-zA-Z0-9])\.(?=[a-zA-Z])", sanitized))
    if missing_space:
        issues.append(f"{missing_space} punctuation mark(s) missing a following space")
    exclamations = content.count("!")
    if exclamations >= 2:
        issues.append(f"{exclamations} exclamation marks (emotional pressure)")
    if "!!" in content or "??" in content:
        issues.append("Multiple consecutive punctuation marks")
    repeated = re.findall(r"(.)\1{2,}", content)
    if repeated:
        issues.append(f"Excessive character repetition (e.g. '{repeated[0] * 3}')")
    caps = [s for s in _sentences(content) if len(s) >= 5 and s.isupper()]
    if caps:
        issues.append(f"{len(caps)} sentence(s) in ALL CAPS")
    return issues


def spell_mistakes(content):
    words = re.findall(r"[a-zA-Z]{3,}", content)
    if len(words) < 4:
        return []
    lowered = [w.lower() for w in words]
    try:
        unknown = spell.unknown(lowered)
    except Exception:
        return []
    out = []
    for w in unknown:
        originals = [x for x in words if x.lower() == w]
        if any(x[:1].isupper() and not x.isupper() for x in originals):
            continue
        out.append(w)
    return out[:8]


def languagetool_issues(content):
    def run():
        try:
            resp = requests.post(
                LANGUAGE_TOOL_URL,
                data={"text": content[:4000], "language": "en-US"},
                timeout=8,
            )
            if resp.status_code != 200:
                return []
            out = []
            for m in resp.json().get("matches", []):
                rule = m.get("rule") or {}
                cat = (rule.get("category") or {}).get("name", "")
                if cat in ("Grammar", "Style", "Spelling", "Typographical",
                           "Punctuation", "Capitalization", "Semantics"):
                    msg = m.get("shortMessage") or m.get("message", "")
                    if msg:
                        out.append(f"[{cat}] {msg}")
            return out[:10]
        except Exception:
            return []
    key = "lt:" + hashlib.md5(content.encode("utf-8", "ignore")).hexdigest()
    return cached(key, 1800, run)


def grammar_report(content):
    issues = grammar_issues(content)
    misspelled = spell_mistakes(content)
    if misspelled:
        issues.append(f"{len(misspelled)} spelling error(s) detected")
    lt_issues = languagetool_issues(content)
    total = len(issues) + len(lt_issues)
    if total == 0:
        level = "None"
    elif total <= 2:
        level = "Minor"
    elif total <= 5:
        level = "Moderate"
    else:
        level = "High"
    prob = 0.0 if level == "None" else min(0.25 + min(total, 6) * 0.07, 0.85)
    all_issues = list(issues) + [f"LanguageTool: {i}" for i in lt_issues]
    return {"level": level, "issues": all_issues[:10], "prob": prob}


def extract_anchors(content):
    anchors = []
    for m in re.finditer(r"\[([^\]]+)\]\(((?:https?://)[^)\s]+)\)", content):
        label = re.sub(r"[^A-Za-z ]", " ", m.group(1)).strip()
        anchors.append((label, m.group(2)))
    for m in re.finditer(
        r'<a\s+[^>]*href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>',
        content, re.IGNORECASE | re.DOTALL,
    ):
        label = re.sub(r"<[^>]+>", " ", m.group(2))
        label = re.sub(r"[^A-Za-z ]", " ", label).strip()
        anchors.append((label, m.group(1)))
    return anchors


def link_text_mismatch(anchors):
    indicators = []
    seen = set()
    for label, url in anchors:
        low_label = label.lower()
        if not low_label:
            continue
        target = parse_url(url)["host"].lower()
        _, registrable, _ = host_parts(target)
        for brand, real in BRANDS.items():
            if brand in low_label and real != target and not target.endswith("." + real):
                key = (brand, target)
                if key not in seen:
                    seen.add(key)
                    indicators.append(
                        f"Link text says '{brand}' but the target host is '{target}'")
    return indicators


def heuristic_prob(content):
    hits = grammar_hits(content)
    prob = 0.20 + min(hits, 2) * 0.15
    if spoof_detected(content) == "Yes":
        prob += 0.25
    return min(prob, 0.95)


def email_text_prob(content):
    if email_text_model is None:
        return None
    try:
        return float(email_text_model.predict_proba([clean_email(content)])[0][1])
    except Exception:
        return None


@app.post("/api/scan/email")
def scan_email():
    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "Missing 'content' field"}), 400

    urls = email_urls(content)
    links = []
    link_probs = []
    for url in urls[:10]:
        prob, _, rule = score_url(url)
        link_probs.append(prob)
        link_risk = risk_from_prob(prob)
        links.append({
            "url": url,
            "host": parse_url(url)["host"],
            "risk": link_risk,
            "confidence": confidence_from_prob(prob),
            "verdict": build_verdict(link_risk)["label"],
            "indicators": rule[1] if rule else [],
        })

    suspicious_links = sum(1 for p in link_probs if p >= 0.55)
    max_link_prob = max(link_probs, default=0.0)
    attachments = attachment_count(content)
    spoof = spoof_detected(content)
    grammar = grammar_report(content)

    email_indicators = []
    email_indicators += link_text_mismatch(extract_anchors(content))
    if spoof == "Yes":
        spoof_domain = from_domain(content)
        spoof_reason = _domain_brand_spoof_reason(spoof_domain) if spoof_domain else None
        email_indicators.append(spoof_reason or
                                "From/Reply-To domain mismatch or impersonating address")
    email_indicators += grammar["issues"][:4]

    text_model_prob = email_text_prob(content)
    sender_domain = from_domain(content)
    trusted_sender = bool(sender_domain) and (
        _allowlisted(sender_domain) or
        any(sender_domain == real or sender_domain.endswith("." + real)
            for real in BRANDS.values()))
    explicit = max(max_link_prob, grammar["prob"], heuristic_prob(content))
    if text_model_prob is None:
        prob = explicit
    elif trusted_sender and explicit < 0.5:
        prob = max(explicit, min(text_model_prob, 0.34))
    elif text_model_prob >= 0.5 or explicit >= 0.5:
        prob = max(explicit, text_model_prob)
    else:
        prob = max(explicit, min(text_model_prob, 0.34))

    if sender_domain:
        auth = cached(f"auth:{sender_domain}", 3600, lambda: sender_auth(sender_domain))
    else:
        auth = None
    auth_indicators, auth_bump = auth_signals(auth, sender_domain, prob)
    email_indicators += auth_indicators

    prob = min(prob + auth_bump, 0.99)
    risk = risk_from_prob(prob)
    confidence = confidence_from_prob(prob)

    return jsonify({
        "risk": risk,
        "confidence": confidence,
        "verdict": build_verdict(risk),
        "suspiciousLinks": str(suspicious_links),
        "suspiciousAttachments": str(attachments),
        "grammarManipulation": grammar["level"],
        "spoofingDetected": spoof,
        "grammarIssues": grammar["issues"],
        "textModelRisk": None if text_model_prob is None else f"{text_model_prob * 100:.0f}%",
        "senderDomain": sender_domain,
        "spfStatus": auth.get("spf", "unknown") if auth else "unknown",
        "dmarcStatus": auth.get("dmarc", "unknown") if auth else "unknown",
        "dkimStatus": auth.get("dkim", "unknown") if auth else "unknown",
        "links": links,
        "indicators": email_indicators,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=3000, threaded=True)
