"""
Detects typosquatting / lookalike domains by comparing sender and
reply-to/return-path domains against a list of commonly impersonated
brands, using edit distance and simple homoglyph substitution checks.
"""

import re

# Common phishing targets. Extend this list as needed.
WATCHED_BRANDS = [
    "paypal.com", "microsoft.com", "google.com", "apple.com",
    "amazon.com", "netflix.com", "facebook.com", "instagram.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "hdfcbank.com",
    "icicibank.com", "sbi.co.in", "irs.gov", "dhl.com", "fedex.com",
]

# Common homoglyph substitutions attackers use (visually similar chars)
HOMOGLYPH_MAP = {
    "0": "o", "1": "l", "1": "i", "3": "e", "5": "s", "@": "a",
    "rn": "m", "vv": "w", "cl": "d",
}


def _levenshtein(a: str, b: str) -> int:
    """Standard edit-distance calculation, no external dependency needed."""
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        current_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def _normalize_homoglyphs(domain: str) -> str:
    normalized = domain
    for fake, real in HOMOGLYPH_MAP.items():
        normalized = normalized.replace(fake, real)
    return normalized


def check_lookalike_domain(domain: str, max_distance: int = 2) -> dict | None:
    """
    Returns a match dict if `domain` looks like a typosquat of a watched
    brand, else None. Exact matches to the real brand domain are ignored
    (that's legitimate, not a lookalike).
    """
    if not domain:
        return None

    domain = domain.lower().strip()
    normalized = _normalize_homoglyphs(domain)

    for brand in WATCHED_BRANDS:
        if domain == brand:
            return None  # exact legitimate match, not suspicious

        distance = _levenshtein(normalized, brand)

        # Scale threshold slightly by domain length so short brands
        # (e.g. "dhl.com") aren't over-matched against unrelated domains
        threshold = min(max_distance, max(1, len(brand) // 6))

        if 0 < distance <= threshold:
            return {
                "domain": domain,
                "impersonated_brand": brand,
                "edit_distance": distance,
                "reason": f"Domain closely resembles '{brand}' (edit distance {distance})",
            }

        # Substring/subdomain trick: paypal-verify.com, paypal.security-check.com
        brand_root = brand.split(".")[0]
        if brand_root in domain and domain != brand:
            return {
                "domain": domain,
                "impersonated_brand": brand,
                "edit_distance": None,
                "reason": f"Domain contains brand name '{brand_root}' but is not the real domain",
            }

    return None


def analyze_domains_for_lookalikes(domains: list[str]) -> list[dict]:
    results = []
    for domain in domains:
        match = check_lookalike_domain(domain)
        if match:
            results.append(match)
    return results