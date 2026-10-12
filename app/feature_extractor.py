"""Deterministic URL-only lexical feature extraction. Never opens or resolves URLs."""
from __future__ import annotations
import ipaddress
import math
import re
from urllib.parse import urlsplit, unquote

SUSPICIOUS_TERMS = (
    "login", "verify", "update", "secure", "account", "password",
    "banking", "wallet", "signin", "confirm", "support", "payment",
    "auth", "recover", "credential", "webscr",
)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}
FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "query_length",
    "fragment_length", "count_dots", "count_hyphens", "count_at",
    "count_question", "count_equal", "count_ampersand", "count_percent",
    "count_digits", "digit_ratio", "count_letters", "letter_ratio",
    "count_slashes", "count_double_slash", "count_underscores",
    "count_tilde", "count_semicolon", "count_plus", "count_comma",
    "count_dollar", "count_non_ascii", "count_encoded_marker",
    "subdomain_count", "has_ip_host", "has_port", "https_scheme",
    "has_punycode", "hostname_has_hyphen", "path_has_extension",
    "path_segment_count", "query_parameter_count", "has_at_in_authority",
    "has_suspicious_term", "suspicious_term_count", "is_shortener",
    "hostname_entropy", "path_entropy", "uses_credentials",
]

def _entropy(value: str) -> float:
    if not value:
        return 0.0
    from collections import Counter
    n = len(value)
    return float(-sum((c/n) * math.log2(c/n) for c in Counter(value).values()))

def _normalize_for_parse(url: str) -> str:
    value = url.strip()
    if not value:
        return value
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value
    return value

def extract_url_features(url: str) -> dict[str, float]:
    """Extract a fixed numeric feature vector from a supplied URL string."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")
    raw = url.strip()
    parsed = urlsplit(_normalize_for_parse(raw))
    host = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    decoded = unquote(raw).lower()
    try:
        ipaddress.ip_address(host)
        has_ip = 1
    except ValueError:
        has_ip = 0
    try:
        port = parsed.port
        has_port = int(port is not None)
    except ValueError:
        has_port = 1
    labels = [part for part in host.split(".") if part]
    suspicious_count = sum(decoded.count(term) for term in SUSPICIOUS_TERMS)
    ext_match = re.search(r"\.[a-zA-Z0-9]{1,8}$", path)
    values = {
        "url_length": len(raw),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "count_dots": raw.count("."),
        "count_hyphens": raw.count("-"),
        "count_at": raw.count("@"),
        "count_question": raw.count("?"),
        "count_equal": raw.count("="),
        "count_ampersand": raw.count("&"),
        "count_percent": raw.count("%"),
        "count_digits": sum(ch.isdigit() for ch in raw),
        "digit_ratio": sum(ch.isdigit() for ch in raw) / max(1, len(raw)),
        "count_letters": sum(ch.isalpha() for ch in raw),
        "letter_ratio": sum(ch.isalpha() for ch in raw) / max(1, len(raw)),
        "count_slashes": raw.count("/"),
        "count_double_slash": raw.count("//"),
        "count_underscores": raw.count("_"),
        "count_tilde": raw.count("~"),
        "count_semicolon": raw.count(";"),
        "count_plus": raw.count("+"),
        "count_comma": raw.count(","),
        "count_dollar": raw.count("$"),
        "count_non_ascii": sum(ord(ch) > 127 for ch in raw),
        "count_encoded_marker": len(re.findall(r"%[0-9a-fA-F]{2}", raw)),
        "subdomain_count": max(0, len(labels) - 2),
        "has_ip_host": has_ip,
        "has_port": has_port,
        "https_scheme": int(parsed.scheme.lower() == "https"),
        "has_punycode": int("xn--" in host),
        "hostname_has_hyphen": int("-" in host),
        "path_has_extension": int(bool(ext_match)),
        "path_segment_count": len([p for p in path.split("/") if p]),
        "query_parameter_count": len([p for p in query.split("&") if p]) if query else 0,
        "has_at_in_authority": int("@" in parsed.netloc),
        "has_suspicious_term": int(suspicious_count > 0),
        "suspicious_term_count": suspicious_count,
        "is_shortener": int(host in SHORTENERS),
        "hostname_entropy": _entropy(host),
        "path_entropy": _entropy(path + ("?" + query if query else "")),
        "uses_credentials": int(parsed.username is not None or parsed.password is not None),
    }
    return {name: float(values[name]) for name in FEATURE_NAMES}
