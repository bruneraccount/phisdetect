import ipaddress
import os
import posixpath
import re
from urllib import parse

import dns.resolver

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

CHARACTERS = [".", "-", "_", "/", "?", "=", "@", "&", "!", " ", "~", ",", "+", "*", "#", "$", "%"]

FEATURES = (
    ["qty_dot_url", "qty_hyphen_url", "qty_underline_url", "qty_slash_url",
     "qty_questionmark_url", "qty_equal_url", "qty_at_url", "qty_and_url",
     "qty_exclamation_url", "qty_space_url", "qty_tilde_url", "qty_comma_url",
     "qty_plus_url", "qty_asterisk_url", "qty_hashtag_url", "qty_dollar_url",
     "qty_percent_url", "qty_tld_url", "length_url"]
    + ["qty_dot_domain", "qty_hyphen_domain", "qty_underline_domain", "qty_slash_domain",
       "qty_questionmark_domain", "qty_equal_domain", "qty_at_domain", "qty_and_domain",
       "qty_exclamation_domain", "qty_space_domain", "qty_tilde_domain", "qty_comma_domain",
       "qty_plus_domain", "qty_asterisk_domain", "qty_hashtag_domain", "qty_dollar_domain",
       "qty_percent_domain", "qty_vowels_domain", "domain_length", "domain_in_ip",
       "server_client_domain"]
    + ["qty_dot_directory", "qty_hyphen_directory", "qty_underline_directory", "qty_slash_directory",
       "qty_questionmark_directory", "qty_equal_directory", "qty_at_directory", "qty_and_directory",
       "qty_exclamation_directory", "qty_space_directory", "qty_tilde_directory", "qty_comma_directory",
       "qty_plus_directory", "qty_asterisk_directory", "qty_hashtag_directory", "qty_dollar_directory",
       "qty_percent_directory", "directory_length"]
    + ["qty_dot_file", "qty_hyphen_file", "qty_underline_file", "qty_slash_file",
       "qty_questionmark_file", "qty_equal_file", "qty_at_file", "qty_and_file",
       "qty_exclamation_file", "qty_space_file", "qty_tilde_file", "qty_comma_file",
       "qty_plus_file", "qty_asterisk_file", "qty_hashtag_file", "qty_dollar_file",
       "qty_percent_file", "file_length"]
    + ["qty_dot_params", "qty_hyphen_params", "qty_underline_params", "qty_slash_params",
       "qty_questionmark_params", "qty_equal_params", "qty_at_params", "qty_and_params",
       "qty_exclamation_params", "qty_space_params", "qty_tilde_params", "qty_comma_params",
       "qty_plus_params", "qty_asterisk_params", "qty_hashtag_params", "qty_dollar_params",
       "qty_percent_params", "params_length", "tld_present_params", "qty_params"]
    + ["email_in_url", "url_shortened"]
    + ["qty_ip_resolved", "qty_nameservers", "qty_mx_servers", "ttl_hostname", "domain_spf"]
)

EMAIL_RE = re.compile(r"[\w\.-]+@[\w\.-]+")
BOUNDARY_RE = re.compile(r"[a-zA-Z0-9.]")


def _load_list(filename):
    with open(os.path.join(_ROOT, "lookup", filename)) as f:
        return [line.strip().lower() for line in f if line.strip()]


SHORTENERS = set(_load_list("shorteners.txt"))
TLDS = _load_list("tlds.txt")


def parse_url(url):
    text = url.strip()
    if not parse.urlparse(text).scheme:
        text = "http://" + text
    protocol, host, path, params, query, fragment = parse.urlparse(text)
    return {
        "url_all": host + path + params + query + fragment,
        "host": host,
        "path": path,
        "query": query,
    }


def count(text, char):
    return text.count(char)


def count_vowels(text):
    return sum(text.lower().count(v) for v in "aeiou")


def valid_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def count_tld(text):
    text = text.lower().strip()
    count = 0
    for tld in TLDS:
        i = text.find(tld)
        while i > -1:
            end = i + len(tld)
            if end >= len(text) or not BOUNDARY_RE.match(text[end]):
                count += 1
            i = text.find(tld, i + 1)
    return count


def check_tld(text):
    text = text.lower().strip()
    for tld in TLDS:
        i = text.find(tld)
        while i > -1:
            end = i + len(tld)
            if end >= len(text) or not BOUNDARY_RE.match(text[end]):
                return True
            i = text.find(tld, i + 1)
    return False


def count_params(text):
    return len(parse.parse_qs(text))


def _counts(part):
    return [count(part, c) for c in CHARACTERS]


def _walk_up(host, qtype):
    labels = host.split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        try:
            answers = dns.resolver.resolve(candidate, qtype, lifetime=5)
            return len(answers), candidate
        except Exception:
            continue
    return 0, None


def _dns_features(host):
    if not host or valid_ip(host):
        return 1, -1, 0, 0, -1
    try:
        ip_answer = dns.resolver.resolve(host, "A", lifetime=5)
        ip_count = len(ip_answer)
        ttl = ip_answer.rrset.ttl
    except Exception:
        ip_count, ttl = -1, -1
    ns_count, _ = _walk_up(host, "NS")
    mx_count, _ = _walk_up(host, "MX")
    _, spf_host = _walk_up(host, "TXT")
    if spf_host is None:
        spf = -1
    else:
        try:
            txt_records = dns.resolver.resolve(spf_host, "TXT", lifetime=5)
            spf = 1 if any("v=spf1" in r.to_text() for r in txt_records) else 0
        except Exception:
            spf = -1
    return ip_count, ttl, ns_count, mx_count, spf


def extract(url, with_dns=True):
    p = parse_url(url)
    url_all, host, path, query = p["url_all"], p["host"], p["path"], p["query"]

    values = {}

    url_counts = _counts(url_all)
    for name, val in zip(FEATURES[:17], url_counts):
        values[name] = val
    values["qty_tld_url"] = count_tld(url_all)
    values["length_url"] = len(url_all)

    domain_counts = _counts(host)
    for name, val in zip(FEATURES[19:36], domain_counts):
        values[name] = val
    values["qty_vowels_domain"] = count_vowels(host)
    values["domain_length"] = len(host)
    values["domain_in_ip"] = 1 if valid_ip(host) else 0
    values["server_client_domain"] = 1 if ("server" in host.lower() or "client" in host.lower()) else 0

    if path:
        directory_counts = _counts(path)
        for name, val in zip(FEATURES[40:57], directory_counts):
            values[name] = val
        values["directory_length"] = len(path)
        file_part = posixpath.basename(path)
        file_counts = _counts(file_part)
        for name, val in zip(FEATURES[58:75], file_counts):
            values[name] = val
        values["file_length"] = len(file_part)
    else:
        for name in FEATURES[40:76]:
            values[name] = -1

    if query:
        params_counts = _counts(query)
        for name, val in zip(FEATURES[76:93], params_counts):
            values[name] = val
        values["params_length"] = len(query)
        values["tld_present_params"] = 1 if check_tld(query) else 0
        values["qty_params"] = count_params(query)
    else:
        for name in FEATURES[76:96]:
            values[name] = -1

    values["email_in_url"] = 1 if EMAIL_RE.search(url_all) else 0
    values["url_shortened"] = 1 if host.lower() in SHORTENERS else 0

    if with_dns:
        ip_count, ttl, ns_count, mx_count, spf = _dns_features(host)
    else:
        ip_count, ttl, ns_count, mx_count, spf = -1, -1, 0, 0, -1
    values["qty_ip_resolved"] = ip_count
    values["ttl_hostname"] = ttl
    values["qty_nameservers"] = ns_count
    values["qty_mx_servers"] = mx_count
    values["domain_spf"] = spf

    return values


def extract_row(url):
    values = extract(url)
    return [values[name] for name in FEATURES]
