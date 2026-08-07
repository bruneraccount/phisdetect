import re


def clean_url(u):
    u = (u or "").strip().lower()
    if not u:
        return ""
    if "://" in u:
        u = u.split("://", 1)[1]
    u = re.split(r"[\s,;'\"<>]", u)[0]
    return u


def url_text(u):
    u = clean_url(u)
    if not u:
        return ""
    u = u.split("#", 1)[0].split("?", 1)[0]
    u = re.sub(r"[^a-z0-9]+", " ", u)
    return u


def analyzer(text):
    words = [w for w in text.split() if 2 <= len(w) <= 24]
    out = list(words)
    for w in words:
        if len(w) < 3:
            continue
        for n in (3, 4, 5):
            for i in range(len(w) - n + 1):
                out.append(w[i:i + n])
    return out
