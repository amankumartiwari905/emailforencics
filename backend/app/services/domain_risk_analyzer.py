"""
Domain risk scoring based on registration and DNS infrastructure
signals. A newly registered, DNS-thin domain is a classic phishing
infrastructure pattern -- attackers spin up throwaway domains just
before a campaign, so age and DNS completeness are strong signals
even without any content analysis.
"""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DomainRiskWeights:
    """Scoring weights, extracted from the function body so they can
    be tuned (or A/B tested) without touching the scoring logic."""
    newly_registered: int = 30
    very_young_domain: int = 20
    no_mx_record: int = 10
    no_ns_record: int = 5
    missing_registrar: int = 5
    very_young_threshold_days: int = 30


_DEFAULT_WEIGHTS = DomainRiskWeights()

_RISK_LEVEL_THRESHOLDS = (
    (70, "HIGH"),
    (40, "MEDIUM"),
    (0, "LOW"),
)


def _has_real_records(records: list) -> bool:
    """
    Treats a list containing only empty/whitespace strings as having
    NO records -- some DNS libraries return [""] instead of [] when a
    record type is absent (seen in this project's own domain_intelligence
    output for mx_records), so a naive `if not mx_records` check would
    incorrectly treat that as "has an MX record".
    """
    if not records:
        return False
    return any(isinstance(r, str) and r.strip() for r in records)


def _classify_risk_level(score: int) -> str:
    for threshold, level in _RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "LOW"  # unreachable given the thresholds above, but explicit


def calculate_domain_risk(
    domain_data: dict,
    weights: DomainRiskWeights = _DEFAULT_WEIGHTS,
) -> dict:
    """
    Scores a domain's phishing-infrastructure risk from WHOIS/DNS data.

    Args:
        domain_data: expects optional keys "domain", "newly_registered"
            (bool), "domain_age_days" (int), "mx_records" (list[str]),
            "ns_records" (list[str]), "registrar" (str).
        weights: scoring weights, overridable for tuning/testing.

    Returns:
        {"domain": str | None, "risk_score": int (0-100),
         "risk_level": "LOW" | "MEDIUM" | "HIGH", "reasons": list[str]}

    Malformed or missing fields degrade gracefully (treated as "signal
    not present") rather than raising, since this feeds a forensic
    pipeline that must handle incomplete WHOIS/DNS data routinely.
    """
    if not isinstance(domain_data, dict):
        logger.warning("calculate_domain_risk received non-dict input: %r", type(domain_data))
        domain_data = {}

    score = 0
    reasons: list[str] = []

    # Newly registered domain (explicit flag from upstream WHOIS check)
    if domain_data.get("newly_registered") is True:
        score += weights.newly_registered
        reasons.append("Domain is newly registered")

    # Very young domain, by age in days
    domain_age = domain_data.get("domain_age_days")
    if isinstance(domain_age, int) and not isinstance(domain_age, bool):
        if domain_age < weights.very_young_threshold_days:
            score += weights.very_young_domain
            reasons.append(f"Domain is less than {weights.very_young_threshold_days} days old")
    elif domain_age is not None:
        logger.debug("domain_age_days was not an int: %r", domain_age)

    # No MX record -- treats [""] the same as [] (see _has_real_records)
    mx_records = domain_data.get("mx_records") or []
    if not _has_real_records(mx_records):
        score += weights.no_mx_record
        reasons.append("Domain has no MX record")

    # No NS records
    ns_records = domain_data.get("ns_records") or []
    if not _has_real_records(ns_records):
        score += weights.no_ns_record
        reasons.append("Domain has no NS record")

    # Missing registrar info
    registrar = domain_data.get("registrar")
    if not (isinstance(registrar, str) and registrar.strip()):
        score += weights.missing_registrar
        reasons.append("Registrar information unavailable")

    score = min(score, 100)
    risk_level = _classify_risk_level(score)

    return {
        "domain": domain_data.get("domain"),
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons,
    }