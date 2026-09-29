"""
Fraud / threat score aggregator.

Combines authentication, header, URL, NLP, attachment, domain, lookalike and
IP signals into one score and classification.

Design rules:
  * Every signal belongs to a category; each category has a cap, so no single
    noisy source (or a long list of items) can dominate the score.
  * Correlated signals within a category are merged (worst item wins).
  * Some signals carry a classification floor, so strong evidence is never
    rounded down to SAFE by a low aggregate score.
  * Missing inputs are reported, never silently treated as clean.
  * All input is untrusted: coerced, sanitized and length-limited.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from email.utils import parseaddr
from enum import Enum
from typing import Any, Iterable, Optional

from app.services.auth_analyzer import analyze_authentication

logger = logging.getLogger(__name__)

SCORING_VERSION = "2.0"


# ==========================================
# CLASSIFICATION
# ==========================================

class Classification(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_RANK = {
    Classification.SAFE: 0,
    Classification.SUSPICIOUS: 1,
    Classification.HIGH: 2,
    Classification.CRITICAL: 3,
}

CRITICAL_MIN = 75
HIGH_MIN = 50
SUSPICIOUS_MIN = 25


def _tier_for_score(score: int) -> Classification:
    if score >= CRITICAL_MIN:
        return Classification.CRITICAL
    if score >= HIGH_MIN:
        return Classification.HIGH
    if score >= SUSPICIOUS_MIN:
        return Classification.SUSPICIOUS
    return Classification.SAFE


# ==========================================
# WEIGHTS (tune on labeled data)
# ==========================================

CATEGORY_CAPS = {
    "authentication": 60,
    "headers": 25,
    "urls": 40,
    "nlp": 55,
    "attachments": 40,
    "domain_intel": 30,
    "lookalike": 40,
    "ip": 30,
}

AUTH_WEIGHT = 0.6
NLP_WEIGHT = 0.5
NLP_MAX_BASE = 40
BEC_COMPOUND_BONUS = 15

REPLY_TO_MISMATCH = 15
RETURN_PATH_MISMATCH = 8      # lower: ESPs and mailing lists legitimately differ
URL_POINTS_EACH = 20
LOOKALIKE_POINTS = 30
ATTACHMENT_EXTRA_FACTOR = 0.25  # additional attachments count at 25%
HIGH_RISK_ATTACHMENT = 80

IP_FLAG_POINTS = {"tor": 15, "vpn": 10, "proxy": 10, "hosting": 5}

MAX_REASON_CHARS = 160
MAX_SIGNALS = 50

ENRICHMENT_KEYS = (
    "url_analysis", "nlp_analysis", "attachment_analysis",
    "domain_intelligence", "lookalike_analysis", "ip_intelligence",
)


# ==========================================
# HELPERS
# ==========================================

@dataclass(frozen=True)
class Signal:
    category: str
    points: int
    reason: str
    floor: Optional[Classification] = None

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "points": self.points,
            "reason": self.reason,
            "floor": self.floor.value if self.floor else None,
        }


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060\ufeff]")


def _clean(value: Any, limit: int = MAX_REASON_CHARS) -> str:
    """Sanitize attacker-controlled text before it enters a reason string."""
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    text = _CONTROL_RE.sub("", text).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y", "on"}:
            return True
        if lowered in {"false", "0", "no", "n", "off", ""}:
            return False
    return default


def _num(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        num = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            num = float(text)
        except ValueError:
            return default
    else:
        try:
            num = float(value)
        except (TypeError, ValueError):
            return default
    return num if math.isfinite(num) else default


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _domain_of(address: Any) -> Optional[str]:
    """Extract the domain from 'Name <user@host>' or 'user@host'."""
    if not isinstance(address, str):
        return None
    _, addr = parseaddr(address)
    if "@" not in addr:
        return None
    domain = addr.rsplit("@", 1)[1].strip().lower().rstrip(".")
    return domain or None


try:  # optional: proper public-suffix handling (co.uk, com.au, ...)
    import tldextract

    _extract = tldextract.TLDExtract(suffix_list_urls=())  # offline, bundled list

    def _org_domain(domain: str) -> str:
        parts = _extract(domain)
        return ".".join(p for p in (parts.domain, parts.suffix) if p) or domain

except ImportError:  # naive fallback: last two labels
    def _org_domain(domain: str) -> str:
        labels = domain.split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else domain


def _aligned(a: str, b: str) -> bool:
    return _org_domain(a) == _org_domain(b)


# ==========================================
# SIGNAL COLLECTORS
# ==========================================

def _auth_signals(email_data: dict) -> tuple[list[Signal], dict, bool]:
    authentication = _dict(email_data.get("authentication"))
    if not authentication:
        return [], {}, False

    auth_result = analyze_authentication(authentication)
    risk = _num(auth_result.get("auth_risk_score"))
    points = min(int(risk * AUTH_WEIGHT), CATEGORY_CAPS["authentication"])

    reasons = [_clean(r) for r in _list(auth_result.get("reasons"))]
    signals = [Signal("authentication", points if i == 0 else 0, r)
               for i, r in enumerate(reasons)]
    if not signals and points:
        signals = [Signal("authentication", points, "Authentication checks failed")]
    return signals, auth_result, True


def _header_signals(email_data: dict) -> list[Signal]:
    sender = _domain_of(email_data.get("from"))
    if not sender:
        return []

    signals = []
    reply_to = _domain_of(email_data.get("reply_to"))
    if reply_to and not _aligned(sender, reply_to):
        signals.append(Signal(
            "headers", REPLY_TO_MISMATCH,
            f"Reply-To domain ({_clean(reply_to, 60)}) differs from sender domain",
        ))

    return_path = _domain_of(email_data.get("return_path"))  # null path '<>' -> None
    if return_path and not _aligned(sender, return_path):
        signals.append(Signal(
            "headers", RETURN_PATH_MISMATCH,
            f"Return-Path domain ({_clean(return_path, 60)}) differs from sender domain",
        ))
    return signals


def _url_signals(email_data: dict) -> list[Signal]:
    signals = []
    for result in _list(email_data.get("url_analysis")):
        if isinstance(result, dict) and _bool(result.get("suspicious")):
            signals.append(Signal(
                "urls", URL_POINTS_EACH,
                f"Suspicious URL detected: {_clean(result.get('url'))}",
                floor=Classification.SUSPICIOUS,  # one bad URL is never SAFE
            ))
    return signals


def _nlp_signals(email_data: dict) -> list[Signal]:
    nlp = _dict(email_data.get("nlp_analysis"))
    nlp_score = _num(nlp.get("threat_score"))
    if nlp_score <= 0:
        return []

    signals = []
    points = min(int(nlp_score * NLP_WEIGHT), NLP_MAX_BASE)

    tactics = [_clean(t, 60) for t in _list(nlp.get("tactics")) if t][:8]
    reason = ("Social engineering language detected: " + ", ".join(tactics)
              if tactics else "Social engineering language detected")

    # Respect the NLP module's own tier as a floor, so a lone high-risk
    # credential/financial hit isn't lost to the 0.5 down-weighting.
    floor = (Classification.SUSPICIOUS
             if nlp.get("nlp_signal_tier") in ("suspicious", "phishing") else None)
    signals.append(Signal("nlp", points, reason, floor=floor))

    categories = set(_dict(nlp.get("pattern_layer")).get("matched_categories") or [])
    if {"financial_fraud", "executive_impersonation"} <= categories:
        signals.append(Signal(
            "nlp", BEC_COMPOUND_BONUS,
            "Compound BEC pattern: financial request combined with "
            "executive-impersonation language",
            floor=Classification.HIGH,
        ))
    return signals


def _attachment_signals(email_data: dict) -> list[Signal]:
    scored = []
    for att in _list(email_data.get("attachment_analysis")):
        if not isinstance(att, dict):
            continue
        score = _num(att.get("risk_score"))
        if score > 0:
            scored.append((score, att))
    scored.sort(key=lambda x: x[0], reverse=True)

    signals = []
    for i, (score, att) in enumerate(scored):
        factor = 1.0 if i == 0 else ATTACHMENT_EXTRA_FACTOR
        why = att.get("reasons")
        why_text = "; ".join(_clean(r, 60) for r in why[:3]) if isinstance(why, list) else _clean(why)
        signals.append(Signal(
            "attachments", int(min(score, 40) * factor),
            f"Suspicious attachment '{_clean(att.get('filename'), 60)}'"
            + (f": {why_text}" if why_text else ""),
            floor=Classification.HIGH if score >= HIGH_RISK_ATTACHMENT else None,
        ))
    return signals


def _domain_signals(email_data: dict) -> list[Signal]:
    worst: Optional[tuple[float, str]] = None
    for domain, intel in _dict(email_data.get("domain_intelligence")).items():
        score = _num(_dict(_dict(intel).get("risk")).get("risk_score"))
        if score > 0 and (worst is None or score > worst[0]):
            worst = (score, str(domain))
    if worst is None:
        return []
    score, domain = worst
    return [Signal("domain_intel", int(min(score, 30)),
                   f"Domain risk detected for {_clean(domain, 80)}: {int(score)}/100")]


def _lookalike_signals(email_data: dict) -> list[Signal]:
    signals = []
    for match in _list(email_data.get("lookalike_analysis")):
        reason = _clean(_dict(match).get("reason")) or "Lookalike domain detected"
        signals.append(Signal("lookalike", LOOKALIKE_POINTS, reason,
                              floor=Classification.SUSPICIOUS))
    return signals


def _ip_signals(email_data: dict) -> list[Signal]:
    """Score each IP once, then keep only the worst (signals overlap heavily)."""
    best: Optional[tuple[int, str, list[str]]] = None
    for ip_data in _list(email_data.get("ip_intelligence")):
        if not isinstance(ip_data, dict):
            continue
        points = int(min(_num(ip_data.get("risk_score")), 30))
        notes = []
        if points:
            notes.append(f"risk {points}")
        # vpn/proxy/tor/hosting describe the same address; take the strongest, not the sum
        flags = [(IP_FLAG_POINTS[f], f) for f in IP_FLAG_POINTS if _bool(ip_data.get(f))]
        if flags:
            flag_points, flag = max(flags)
            points += flag_points
            notes.append(flag.upper() if flag == "tor" else flag)
        if points and (best is None or points > best[0]):
            best = (points, _clean(ip_data.get("ip"), 45), notes)
    if best is None:
        return []
    points, ip, notes = best
    return [Signal("ip", points, f"IP risk detected for {ip}: {', '.join(notes)}")]


# ==========================================
# AGGREGATION
# ==========================================

def _aggregate(signals: Iterable[Signal]) -> tuple[int, dict[str, int]]:
    raw: dict[str, int] = {}
    for s in signals:
        raw[s.category] = raw.get(s.category, 0) + s.points
    capped = {c: min(p, CATEGORY_CAPS.get(c, 30)) for c, p in raw.items()}
    return min(sum(capped.values()), 100), capped


def _floors(signals: list[Signal], category_scores: dict[str, int]) -> list[Classification]:
    floors = [s.floor for s in signals if s.floor]

    # Combination floor: lookalike domain plus header mismatch or weak authentication
    has_lookalike = any(s.category == "lookalike" for s in signals)
    header_mismatch = any(s.category == "headers" and "Reply-To" in s.reason for s in signals)
    weak_auth = category_scores.get("authentication", 0) >= 30
    if has_lookalike and (header_mismatch or weak_auth):
        floors.append(Classification.HIGH)
    return floors


def analyze_threat(email_data: Optional[dict]) -> dict:
    email_data = _dict(email_data)

    signals: list[Signal] = []
    missing = [k for k in ENRICHMENT_KEYS if email_data.get(k) is None]

    try:
        auth_signals, auth_result, auth_ran = _auth_signals(email_data)
    except Exception:  # a broken auth module must not take down scoring
        logger.exception("authentication analysis failed")
        auth_signals, auth_result, auth_ran = [], {}, False
    if not auth_ran:
        missing.append("authentication")
    signals += auth_signals

    for collector in (_header_signals, _url_signals, _nlp_signals, _attachment_signals,
                      _domain_signals, _lookalike_signals, _ip_signals):
        try:
            signals += collector(email_data)
        except Exception:
            logger.exception("collector %s failed", collector.__name__)
            missing.append(collector.__name__.strip("_").replace("_signals", ""))

    if str(_dict(email_data.get("nlp_analysis")).get("llm_status", "")).lower() == "error":
        missing.append("nlp_llm")

    signals.sort(key=lambda s: s.points, reverse=True)
    score, category_scores = _aggregate(signals)

    tier = _tier_for_score(score)
    floors = _floors(signals, category_scores)
    final = max([tier, *floors], key=_RANK.__getitem__)

    return {
        "fraud_score": score,
        "classification": final.value,
        "reasons": [s.reason for s in signals[:MAX_SIGNALS]],
        "signals": [s.to_dict() for s in signals[:MAX_SIGNALS]],
        "category_scores": category_scores,
        "score_based_classification": tier.value,
        "floor_applied": final != tier,
        "missing_inputs": sorted(set(missing)),
        "scoring_version": SCORING_VERSION,
        "auth_analysis": auth_result,
        "nlp_analysis": _dict(email_data.get("nlp_analysis")),
    }