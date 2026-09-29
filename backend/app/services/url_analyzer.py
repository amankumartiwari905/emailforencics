"""
Heuristic URL suspicion scoring for phishing/credential-harvesting
links found in an email body.

Note on the underlying limitation this module has: keyword matching
on the URL text ("login", "verify", etc.) is a weak, high-false-positive
signal by itself -- plenty of entirely legitimate URLs contain these
words (a real bank's actual login page has "login" in it too). This
module reports keyword matches as a low-weight signal alongside
stronger structural checks (IP-literal hosts, punycode/homoglyph
domains, excessive subdomain nesting, credential-in-URL), rather than
treating every keyword hit as equally suspicious -- see suspicion_score
vs. the boolean `suspicious` flag.
"""

import re
import ipaddress
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_SUSPICIOUS_KEYWORDS = (
    "login", "verify", "account", "password", "secure", "update",
    "confirm", "signin", "banking", "suspended", "unlock",
)

# Weight for a bare keyword hit -- deliberately low, since this alone
# is weak evidence (see module docstring).
_KEYWORD_WEIGHT = 8
_MAX_KEYWORD_CONTRIBUTION = 24  # cap so a URL padded with many keywords
                                  # doesn't dominate the score on volume alone

_NON_HTTPS_WEIGHT = 15
_IP_LITERAL_HOST_WEIGHT = 35       # e.g. http://192.0.2.1/login -- a
                                     # legitimate service is essentially
                                     # never referenced by raw IP in email
_EXCESSIVE_SUBDOMAIN_WEIGHT = 20    # e.g. paypal.com.security-check.evil.net
_CREDENTIALS_IN_URL_WEIGHT = 25     # http://user:pass@host/... -- classic
                                     # URL-obfuscation trick
_PUNYCODE_WEIGHT = 20               # xn--... domains, often IDN homograph attacks

_MAX_SUBDOMAIN_LABELS = 3  # more than this many labels before the
                             # registrable domain is treated as unusual

_SUSPICIOUS_THRESHOLD = 20  # suspicion_score at or above this sets suspicious=True


def _is_ip_literal(hostname: str | None) -> bool:
    if not hostname:
        return False
    # Strip brackets for IPv6 literal hosts, e.g. "[2001:db8::1]"
    candidate = hostname.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _has_excessive_subdomains(hostname: str | None) -> bool:
    if not hostname:
        return False
    labels = hostname.split(".")
    return len(labels) > _MAX_SUBDOMAIN_LABELS


def _is_punycode_domain(hostname: str | None) -> bool:
    if not hostname:
        return False
    return any(label.startswith("xn--") for label in hostname.split("."))


def analyze_url(url: str) -> dict:
    """
    Scores a single URL for phishing-relevant suspicion signals.

    Returns a dict with a boolean `suspicious` (threshold-based, for
    simple downstream filtering) and a numeric `suspicion_score`
    (0-100-ish, unclamped intentionally -- see analyze_urls) alongside
    the human-readable `reasons`, so callers that want finer-grained
    risk weighting (e.g. threat_analyzer.py) aren't limited to a
    boolean.
    """
    if not url or not isinstance(url, str):
        return {
            "url": url,
            "domain": None,
            "https": False,
            "suspicious": False,
            "suspicion_score": 0,
            "reasons": ["Empty or invalid URL"],
        }

    try:
        parsed = urlparse(url)
    except ValueError as e:
        logger.warning("Failed to parse URL %r: %s", url, e)
        return {
            "url": url,
            "domain": None,
            "https": False,
            "suspicious": True,  # unparseable URL is itself a signal worth flagging
            "suspicion_score": 30,
            "reasons": [f"URL could not be parsed: {e}"],
        }

    domain = parsed.hostname
    scheme = (parsed.scheme or "").lower()
    url_lower = url.lower()

    score = 0
    reasons: list[str] = []

    # --- Scheme check ---
    if scheme != "https":
        score += _NON_HTTPS_WEIGHT
        reasons.append(f"URL does not use HTTPS (scheme: {scheme or 'none'})")

    # --- IP-literal host ---
    if _is_ip_literal(domain):
        score += _IP_LITERAL_HOST_WEIGHT
        reasons.append(f"URL host is a raw IP address ({domain}), not a domain name")

    # --- Credentials embedded in URL (user:pass@host trick) ---
    if parsed.username or parsed.password:
        score += _CREDENTIALS_IN_URL_WEIGHT
        reasons.append("URL contains embedded credentials before the host")

    # --- Excessive subdomain nesting (lookalike-brand-in-subdomain trick) ---
    if _has_excessive_subdomains(domain):
        score += _EXCESSIVE_SUBDOMAIN_WEIGHT
        reasons.append(f"URL host has an unusually deep subdomain chain: {domain}")

    # --- Punycode / IDN domain ---
    if _is_punycode_domain(domain):
        score += _PUNYCODE_WEIGHT
        reasons.append(f"URL host uses punycode encoding, often indicating a homograph attack: {domain}")

    # --- Suspicious keywords (low weight, capped total contribution) ---
    keyword_hits = [word for word in _SUSPICIOUS_KEYWORDS if word in url_lower]
    if keyword_hits:
        keyword_contribution = min(len(keyword_hits) * _KEYWORD_WEIGHT, _MAX_KEYWORD_CONTRIBUTION)
        score += keyword_contribution
        for word in keyword_hits:
            reasons.append(f"URL contains suspicious keyword: {word}")

    suspicious = score >= _SUSPICIOUS_THRESHOLD

    return {
        "url": url,
        "domain": domain,
        "https": scheme == "https",
        "suspicious": suspicious,
        "suspicion_score": score,
        "reasons": reasons,
    }


def analyze_urls(urls: list[str]) -> list[dict]:
    """Analyzes every URL in the list, deduping identical URLs so a
    phishing email that repeats the same link 5 times doesn't get
    analyzed 5 times over (common in real templates -- multiple
    "click here" buttons all pointing at the same link)."""
    if not urls:
        return []

    seen: set[str] = set()
    results = []

    for url in urls:
        if not url or url in seen:
            continue
        seen.add(url)
        results.append(analyze_url(url))

    return results