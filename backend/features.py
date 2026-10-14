"""Feature engineering and rule-based indicators for URLs and emails."""
import re
from urllib.parse import urlparse
import ipaddress

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
PHISHING_WORDS = ["verify", "account suspended", "password", "otp", "urgent", "immediately", "login", "confirm", "payment failed", "click here", "limited time", "wallet"]
URGENCY_WORDS = ["urgent", "immediately", "act now", "within 24 hours", "final warning", "suspended", "will be closed"]
CREDENTIAL_WORDS = ["password", "otp", "one time password", "credentials", "verify your identity", "security code", "login"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy"}


def extract_urls(text):
    return [u.rstrip('.,);]!?') for u in URL_RE.findall(text or "")]


def url_features(url):
    raw = (url or "").strip()
    candidate = raw if re.match(r"^[a-z]+://", raw, re.I) else "http://" + raw
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    try:
        ip_based = int(ipaddress.ip_address(host) is not None)
    except ValueError:
        ip_based = 0
    return {
        "length": len(raw),
        "host_length": len(host),
        "dot_count": host.count("."),
        "subdomain_count": max(0, host.count(".") - 1),
        "hyphen_count": host.count("-"),
        "digit_count": sum(c.isdigit() for c in raw),
        "special_char_count": sum(not c.isalnum() for c in raw),
        "at_symbol": int("@" in raw),
        "ip_domain": ip_based,
        "https": int(parsed.scheme.lower() == "https"),
        "shortener": int(host in SHORTENERS),
        "suspicious_keyword_count": sum(w in raw.lower() for w in PHISHING_WORDS),
        "query_length": len(parsed.query),
        "has_punycode": int("xn--" in host),
        "path_length": len(parsed.path),
    }


def email_features(sender="", subject="", body="", email_html="", attachments=None):
    attachments = attachments or []
    text = f"{sender} {subject} {body} {email_html}".lower()
    urls = extract_urls(f"{body} {subject} {email_html}")
    domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
    feats = {
        "length": len(text),
        "host_length": len(domain),
        "dot_count": domain.count("."),
        "subdomain_count": max(0, domain.count(".") - 1),
        "hyphen_count": domain.count("-"),
        "digit_count": sum(c.isdigit() for c in text),
        "special_char_count": sum(not c.isalnum() and not c.isspace() for c in text),
        "at_symbol": int("@" in sender),
        "ip_domain": 0,
        "https": int(bool(urls) and all(u.lower().startswith("https://") for u in urls)),
        "shortener": int(any((urlparse(u if "://" in u else "http://"+u).hostname or "").lower() in SHORTENERS for u in urls)),
        "suspicious_keyword_count": sum(w in text for w in PHISHING_WORDS),
        "query_length": sum(len(urlparse(u if "://" in u else "http://"+u).query) for u in urls),
        "has_punycode": int("xn--" in domain),
        "path_length": sum(len(urlparse(u if "://" in u else "http://"+u).path) for u in urls),
        "url_count": len(urls),
        "urgent_count": sum(w in text for w in URGENCY_WORDS),
        "credential_count": sum(w in text for w in CREDENTIAL_WORDS),
        "attachment_count": len(attachments),
        "risky_attachment": int(any(str(a).lower().endswith((".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".msi", ".jar", ".ps1")) for a in attachments)),
        "uppercase_ratio": (sum(c.isupper() for c in f"{subject} {body}" if c.isalpha()) / max(1, sum(c.isalpha() for c in f"{subject} {body}"))),
        "exclamation_count": (f"{subject} {body}".count("!")),
        "sender_valid": int(bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender))),
    }
    return feats


def rule_analysis(kind, text, features, attachments=None):
    """Transparent heuristic score; this complements, not replaces, the ML model."""
    text = (text or "").lower()
    reasons, score = [], 0
    if features.get("ip_domain"):
        score += 25; reasons.append("URL uses an IP address instead of a regular domain.")
    if features.get("at_symbol"):
        score += 18; reasons.append("An @ symbol may obscure the actual URL destination.")
    if features.get("subdomain_count", 0) >= 3:
        score += 10; reasons.append("URL or sender domain has several subdomains.")
    if features.get("length", 0) > (180 if kind == "url" else 1200):
        score += 8; reasons.append("Unusually long input can be a warning sign.")
    if features.get("shortener"):
        score += 12; reasons.append("A URL-shortening service was detected.")
    if features.get("has_punycode"):
        score += 12; reasons.append("Punycode domain detected; inspect for look-alike characters.")
    if features.get("suspicious_keyword_count", 0):
        score += min(30, features["suspicious_keyword_count"] * 6)
        reasons.append("Suspicious account, credential, or urgency keywords detected.")
    if kind == "email":
        if features.get("urgent_count", 0):
            score += min(18, features["urgent_count"] * 5); reasons.append("Urgency or threat language detected.")
        if features.get("credential_count", 0):
            score += min(20, features["credential_count"] * 5); reasons.append("The message refers to credentials or account verification.")
        if features.get("risky_attachment"):
            score += 25; reasons.append("Potentially risky executable/script attachment extension detected.")
        if features.get("sender_valid") == 0:
            score += 8; reasons.append("Sender address is missing or has an unusual format.")
        if features.get("uppercase_ratio", 0) > .4 and features.get("length", 0) > 30:
            score += 5; reasons.append("Excessive capitalization detected.")
        if features.get("exclamation_count", 0) >= 4:
            score += 5; reasons.append("Excessive exclamation marks detected.")
    score = min(100, max(0, score))
    return score, list(dict.fromkeys(reasons))
