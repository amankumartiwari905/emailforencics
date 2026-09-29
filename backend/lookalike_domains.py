from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

_DEFAULT_BRANDS = (
    "paypal.com",
    "amazon.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "chase.com",
    "sbi.co.in",
    "onlinesbi.sbi",
    "bankofamerica.com",
    "netflix.com",
    "github.com",
    "dropbox.com",
    "stripe.com",
    "adobe.com",
    "paypal.net",
)


class MatchType(Enum):
    HOMOGLYPH = "homoglyph"
    EDIT_DISTANCE = "edit_distance"
    IDN_HOMOGRAPH = "idn_homograph"
    TLD_SWAP = "tld_swap"
    COMBOSQUAT = "combosquat"
    SUBDOMAIN_SPOOF = "subdomain_spoof"


class Severity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class DetectorConfig:
    brands: tuple[str, ...] = _DEFAULT_BRANDS
    trusted_domains: frozenset[str] = frozenset()
    max_edit_distance: int = 2

    def __post_init__(self):
        normalized = []
        for brand in self.brands:
            clean = extract_domain(str(brand))
            if clean is None:
                raise ValueError(f"Invalid brand domain: {brand!r}")
            normalized.append(clean)
        object.__setattr__(self, "brands", tuple(normalized))
        object.__setattr__(self, "trusted_domains", frozenset(extract_domain(d) for d in self.trusted_domains if extract_domain(d)))


@dataclass(frozen=True)
class Match:
    domain: str
    impersonated_brand: str
    match_type: MatchType
    severity: Severity
    edit_distance: Optional[int] = None
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "impersonated_brand": self.impersonated_brand,
            "match_type": self.match_type.value,
            "severity": self.severity.name,
            "edit_distance": self.edit_distance,
            "reason": self.reason,
        }


def _normalise_domain(domain: str) -> str:
    if not isinstance(domain, str):
        return ""
    return domain.strip().lower().rstrip(".")


def _is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    if domain in {"localhost", "example", "invalid"}:
        return False
    if re.search(r"(?:^|\.)\d+$", domain):
        return False
    if re.search(r"\.\.", domain):
        return False
    if domain.startswith("-") or domain.endswith("-"):
        return False
    parts = domain.split(".")
    if not parts or any(not p for p in parts):
        return False
    if any(len(part) > 63 for part in parts):
        return False
    if any(part.startswith("-") or part.endswith("-") for part in parts):
        return False
    if re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)", parts[0]) is None and not any(ch.isalpha() for ch in domain):
        return False
    if any(ch.isdigit() and ch.isalpha() for ch in domain):
        return False
    return True


def _strip_surrounding_email(raw: str) -> str:
    text = raw.strip().strip('"')
    if "<" in text and ">" in text and "@" in text:
        match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", text)
        if match:
            return match.group(1)
    return text


def extract_domain(raw: Any) -> Optional[str]:
    if raw is None or isinstance(raw, (int, float)):
        return None
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if not raw:
        return None
    if raw.lower() in {"localhost", "127.0.0.1", "[::1]", "::1"}:
        return None
    if re.fullmatch(r"\[[0-9A-Fa-f:.]+\]", raw):
        return None
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", raw):
        return None

    if "@" in raw and "http" not in raw.lower():
        match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", raw)
        if match:
            candidate = match.group(1).lower().rstrip(".")
            return candidate if _is_valid_domain(candidate) else None

    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlsplit(raw)
        candidate = parsed.hostname
        if candidate:
            candidate = candidate.lower().rstrip(".")
            return candidate if _is_valid_domain(candidate) else None

    if "/" in raw or ":" in raw and not raw.count(":") == 1 and "@" not in raw:
        if "://" in raw:
            parsed = urlsplit(raw)
            candidate = parsed.hostname
            if candidate:
                candidate = candidate.lower().rstrip(".")
                return candidate if _is_valid_domain(candidate) else None
        if re.search(r"[/:]", raw):
            candidate = raw.split("/", 1)[0].split(":", 1)[0]
            candidate = candidate.strip("[]\"'")
            candidate = candidate.lower().rstrip(".")
            return candidate if _is_valid_domain(candidate) else None

    candidate = raw.strip("[]\"' ")
    if candidate.endswith("."):
        candidate = candidate[:-1]
    candidate = candidate.lower().rstrip(".")
    if not _is_valid_domain(candidate):
        return None
    return candidate


def damerau_levenshtein(a: str, b: str, max_distance: Optional[int] = None) -> int:
    a = a or ""
    b = b or ""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    if max_distance is not None:
        if abs(len(a) - len(b)) > max_distance:
            return max_distance + 1

    if len(a) < len(b):
        a, b = b, a
    da = {}
    row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        prev_row = row[:]
        row[0] = i
        for j, cb in enumerate(b, start=1):
            insertion = row[j - 1] + 1
            deletion = prev_row[j] + 1
            substitution = prev_row[j - 1] + (ca != cb)
            if ca == cb:
                cost = 0
            else:
                cost = 1
            row[j] = min(insertion, deletion, substitution)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                row[j] = min(row[j], prev_row[j - 2] + cost)
        if max_distance is not None and min(row) > max_distance:
            return max_distance + 1
    result = row[-1]
    if max_distance is not None and result > max_distance:
        return max_distance + 1
    return result


def _homoglyph_variants(value: str, max_len: int = 64) -> set[str]:
    value = _normalise_domain(value)
    if not value:
        return set()
    mapping = {
        "0": ("o",), "1": ("l", "i"), "3": ("e",), "4": ("a",),
        "5": ("s",), "7": ("t",), "8": ("b",), "@": ("a",),
        "$": ("s",), "!": ("i",), "-": ("",),
    }
    out = {value}
    for idx, ch in enumerate(value):
        for repl in mapping.get(ch, ()):  # noqa: B007
            variant = value[:idx] + repl + value[idx + 1:]
            if len(variant) <= max_len:
                out.add(variant)
    return out


class LookalikeDetector:
    def __init__(self, config: Optional[DetectorConfig] = None):
        self.config = config or DetectorConfig()
        self._brands = tuple(sorted(self.config.brands, key=lambda d: (-len(d), d)))
        self._trusted = set(self.config.trusted_domains)

    def check(self, raw: Any) -> Optional[Match]:
        domain = extract_domain(raw)
        if domain is None:
            return None
        normalized = _normalise_domain(domain)
        if not normalized or normalized in self._trusted:
            return None

        for brand in self._brands:
            if normalized == brand:
                return None
            if normalized in self._trusted:
                return None
            brand_core = brand.split(".")[:-1]
            if not brand_core:
                continue
            brand_root = brand_core[0]

            if "." in normalized and normalized.endswith("." + brand):
                return Match(
                    domain=normalized,
                    impersonated_brand=brand,
                    match_type=MatchType.SUBDOMAIN_SPOOF,
                    severity=Severity.MEDIUM,
                    reason=f"{normalized} contains a brand-owned subdomain under a different suffix",
                )

            if normalized.endswith("." + brand.rsplit(".", 1)[0]) and normalized.count(".") > brand.count("."):
                return Match(
                    domain=normalized,
                    impersonated_brand=brand,
                    match_type=MatchType.SUBDOMAIN_SPOOF,
                    severity=Severity.HIGH,
                    reason="subdomain spoof",
                )

            if brand_root and normalized.startswith(brand_root + ".") and normalized.count(".") > brand.count("."):
                return Match(
                    domain=normalized,
                    impersonated_brand=brand,
                    match_type=MatchType.COMBOSQUAT,
                    severity=Severity.HIGH,
                    reason=f"brand prefix reused in a new host",
                )

            if normalized.split(".")[0].startswith(brand_root) and normalized.split(".")[0] != brand_root:
                return Match(
                    domain=normalized,
                    impersonated_brand=brand,
                    match_type=MatchType.COMBOSQUAT,
                    severity=Severity.HIGH,
                    reason="combosquat prefix",
                )

            # TLD swap: paypal.net vs paypal.com
            if normalized.split(".")[:-1] == brand.split(".")[:-1] and normalized.split(".")[-1] != brand.split(".")[-1]:
                return Match(
                    domain=normalized,
                    impersonated_brand=brand,
                    match_type=MatchType.TLD_SWAP,
                    severity=Severity.MEDIUM,
                    reason="tld swap",
                )

            # Edit distances on the registrable stem before the TLD.
            left = normalized.split(".")[0]
            right = brand.split(".")[0]
            if len(left) >= 4 and len(right) >= 4:
                dist = damerau_levenshtein(left, right, max_distance=self.config.max_edit_distance)
                if dist <= self.config.max_edit_distance:
                    if left != right and left in _homoglyph_variants(right, 64):
                        return Match(
                            domain=normalized,
                            impersonated_brand=brand,
                            match_type=MatchType.HOMOGLYPH,
                            severity=Severity.HIGH,
                            edit_distance=dist,
                            reason="homoglyph",
                        )
                    return Match(
                        domain=normalized,
                        impersonated_brand=brand,
                        match_type=MatchType.EDIT_DISTANCE,
                        severity=Severity.MEDIUM,
                        edit_distance=dist,
                        reason="edit distance",
                    )

            if any(ord(ch) > 127 for ch in normalized):
                puny = normalized.encode("idna").decode("ascii")
                if puny.startswith("xn--") and puny.lower().split(".")[0] != brand.split(".")[0]:
                    return Match(
                        domain=normalized,
                        impersonated_brand=brand,
                        match_type=MatchType.IDN_HOMOGRAPH,
                        severity=Severity.CRITICAL,
                        reason="IDN homograph",
                    )

        return None

    def analyze(self, items: Iterable[Any]) -> list[dict[str, Any]]:
        seen: set[str] = set()
        rows: list[dict[str, Any]] = []
        for item in items:
            domain = extract_domain(item)
            if domain is None:
                continue
            domain = _normalise_domain(domain)
            if not domain or domain in seen:
                continue
            seen.add(domain)
            match = self.check(domain)
            if match is not None:
                rows.append(match.as_dict())
        return rows


def check_lookalike_domain(domain: Any) -> Optional[dict[str, Any]]:
    match = LookalikeDetector().check(domain)
    if match is None:
        return None
    data = match.as_dict()
    data["severity"] = match.severity.name
    return data


def analyze_domains_for_lookalikes(domains: Iterable[Any]) -> list[dict[str, Any]]:
    return LookalikeDetector().analyze(domains)


__all__ = [
    "DetectorConfig",
    "LookalikeDetector",
    "MatchType",
    "Severity",
    "analyze_domains_for_lookalikes",
    "check_lookalike_domain",
    "damerau_levenshtein",
    "extract_domain",
    "_homoglyph_variants",
]
