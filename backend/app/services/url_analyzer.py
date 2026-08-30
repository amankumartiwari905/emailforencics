from urllib.parse import urlparse


def analyze_url(url: str):

    parsed = urlparse(url)

    domain = parsed.hostname
    scheme = parsed.scheme.lower()

    suspicious = False
    reasons = []

    # HTTPS check
    if scheme != "https":
        suspicious = True
        reasons.append("URL does not use HTTPS")

    # Suspicious URL patterns
    suspicious_words = [
        "login",
        "verify",
        "account",
        "password",
        "secure",
        "update"
    ]

    url_lower = url.lower()

    for word in suspicious_words:
        if word in url_lower:
            suspicious = True
            reasons.append(f"URL contains suspicious keyword: {word}")

    return {
        "url": url,
        "domain": domain,
        "https": scheme == "https",
        "suspicious": suspicious,
        "reasons": reasons
    }


def analyze_urls(urls):

    results = []

    for url in urls:
        results.append(analyze_url(url))

    return results