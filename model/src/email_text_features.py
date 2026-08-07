import html
import re

URL_RE = re.compile(r"https?://\S+|www\.\S+")
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9_.-]+")
NUM_RE = re.compile(r"\d+")
TAG_RE = re.compile(r"<[^>]+>")
BLOCK_TAG_RE = re.compile(r"<\s*(?:br|p|div|tr|/p|/div|/tr|li|/li)\s*/?\s*>", re.I)
QUOTED_RE = re.compile(r"^\s*[>|]", re.M)

_PLAIN_CTYPES = {"text/plain", "text"}
_HTML_CTYPES = {"text/html", "text/x-html"}


def strip_html(s):
    s = BLOCK_TAG_RE.sub(" ", s or "")
    s = TAG_RE.sub(" ", s)
    s = html.unescape(s)
    return s


def _decode(payload, charset):
    if payload is None:
        return ""
    if isinstance(payload, bytes):
        for enc in (charset or "", "utf-8", "latin-1"):
            if not enc:
                continue
            try:
                return payload.decode(enc)
            except (LookupError, UnicodeDecodeError):
                continue
        return payload.decode("utf-8", "ignore")
    return str(payload)


def _walk(msg):
    if msg.is_multipart():
        plain = []
        fallback = []
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in _PLAIN_CTYPES:
                plain.append(_decode(part.get_payload(decode=True), part.get_content_charset()))
            elif ctype in _HTML_CTYPES:
                fallback.append(strip_html(_decode(part.get_payload(decode=True), part.get_content_charset())))
        if any(plain):
            return "\n".join(plain)
        if fallback:
            return "\n".join(fallback)
    ctype = msg.get_content_type()
    text = _decode(msg.get_payload(decode=True), msg.get_content_charset())
    return strip_html(text) if ctype in _HTML_CTYPES else text


def extract_parts(raw):
    """Return (subject, body_text) from a raw email string."""
    import email
    try:
        msg = email.message_from_string(raw or "")
        subject = msg.get("Subject", "") or ""
        return subject, _walk(msg)
    except Exception:
        return "", (raw or "")


def clean_email(raw):
    text = raw or ""
    text = strip_html(text)
    text = QUOTED_RE.sub(" ", text)
    text = URL_RE.sub(" URL ", text)
    text = EMAIL_RE.sub(" EMAIL ", text)
    text = NUM_RE.sub(" NUM ", text)
    text = text.lower()
    text = re.sub(r"[^a-z\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def record_text(subject, body):
    return f"subject: {subject} \n {body}".strip()
