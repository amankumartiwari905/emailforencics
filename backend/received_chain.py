from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ProviderRule:
    name: str
    domains: tuple[str, ...] = ()
    labels: tuple[str, ...] = ()
    networks: tuple[Any, ...] = ()


@dataclass(frozen=True)
class TrustPolicy:
    providers: tuple[ProviderRule, ...] = ()
    own_networks: tuple[Any, ...] = ()
    trust_own_domain_by_name_only: bool = False


@dataclass(frozen=True)
class HopTrustVerdict:
    trusted: bool
    reason: str


def _normalize_domain(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().lower().rstrip(".")


def _extract_from_hostname(header: Any) -> str:
    if not isinstance(header, str):
        return ""
    text = header.strip()
    if not text:
        return ""
    match = re.search(r"from\s+([^\s(]+)", text, flags=re.IGNORECASE)
    host = match.group(1) if match else ""
    if host.startswith("[") and host.endswith("]"):
        return ""
    host = host.strip("[]")
    host = host.split("[", 1)[0].strip()
    host = host.strip("'\"")
    if host.startswith("("):
        host = host[1:]
    if "/" in host:
        host = host.split("/", 1)[0]
    host = host.split(".")
    if len(host) <= 1:
        return ""
    host = ".".join(host[:-1]) if host[-1].startswith("by") else ".".join(host)
    # prefer bracketed hostname when present
    bracket = re.search(r"\((?:[^()]*?)\s*\[([^\]]+)\]\)", text)
    if bracket:
        host = bracket.group(1)
    return _normalize_domain(host)


def _host_matches_own_domain(host: str, recipient_domain: Optional[str]) -> bool:
    if not host or not recipient_domain:
        return False
    recipient = _normalize_domain(recipient_domain)
    if not recipient:
        return False
    if host == recipient:
        return True
    return host.endswith("." + recipient)


def _ip_matches_network(ip_value: Any, networks: tuple[Any, ...]) -> bool:
    if not networks:
        return False
    try:
        addr = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    for network in networks:
        try:
            if addr in network:
                return True
        except Exception:
            pass
    return False


def _meaningful_org_name(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    return text.lower()


def EvaluateHop(hop: dict[str, Any], recipient_domain: Optional[str], org_lookup: Optional[dict[str, str]] = None, policy: Optional[TrustPolicy] = None) -> HopTrustVerdict:
    """Backward-compatible alias for the normalized hop-evaluation API."""
    return evaluate_hop_trust(hop, recipient_domain, org_lookup, policy)


def evaluate_hop_trust(hop: dict[str, Any], recipient_domain: Optional[str], org_lookup: Optional[dict[str, str]] = None, policy: Optional[TrustPolicy] = None) -> HopTrustVerdict:
    if not isinstance(hop, dict):
        return HopTrustVerdict(False, "missing hop data")
    if "hop_index" not in hop:
        raise ValueError("hop_index is required")
    if not isinstance(hop.get("ips"), list) or not hop["ips"]:
        return HopTrustVerdict(False, "no IPs in hop")

    policy = policy or TrustPolicy()
    header = hop.get("header") or ""
    host = _extract_from_hostname(header)
    ips = list(hop["ips"])
    ip_text = ips[0]
    try:
        addr = ipaddress.ip_address(ip_text)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
    except ValueError:
        return HopTrustVerdict(False, "invalid IP")

    # Provider trust: IP/org or configured provider networks override all.
    if host:
        host_l = host.lower()
        for rule in policy.providers:
            if rule.domains and any(host_l == d or host_l.endswith("." + d) for d in rule.domains):
                if rule.networks and _ip_matches_network(ip_text, rule.networks):
                    return HopTrustVerdict(True, f"trusted via {rule.name} provider network")
                if org_lookup and ip_text in org_lookup:
                    org_name = _meaningful_org_name(org_lookup[ip_text])
                    if org_name and rule.name.lower() in org_name:
                        return HopTrustVerdict(True, f"trusted {rule.name} provider organization match")

        if org_lookup and ip_text in org_lookup:
            org_name = _meaningful_org_name(org_lookup[ip_text])
            if org_name:
                if host_l and "google" in host_l and re.search(r"(?<![a-z])google(?![a-z])", org_name):
                    return HopTrustVerdict(True, "trusted google provider organization match")
                if "microsoft" in host_l and re.search(r"(?<![a-z])microsoft(?![a-z])", org_name):
                    return HopTrustVerdict(True, "trusted microsoft provider organization match")

    if recipient_domain and _host_matches_own_domain(host, recipient_domain):
        if addr.is_global:
            if policy.trust_own_domain_by_name_only:
                return HopTrustVerdict(True, "trusted own-domain by configured name-only policy")
            return HopTrustVerdict(False, "public IP on own domain is not trusted without an explicit policy")
        if _ip_matches_network(ip_text, policy.own_networks):
            return HopTrustVerdict(True, "trusted own network")
        return HopTrustVerdict(True, "trusted private own-domain relay")

    return HopTrustVerdict(False, "untrusted hop")


def detect_trusted_hop_boundary(hops: list[dict[str, Any]], recipient_domain: Optional[str], org_lookup: Optional[dict[str, str]] = None, policy: Optional[TrustPolicy] = None) -> int:
    if not hops:
        return 0
    policy = policy or TrustPolicy()
    ordered = sorted(hops, key=lambda item: int(item.get("hop_index", 0)))
    trusted_count = 0
    for hop in ordered:
        if "hop_index" not in hop:
            raise ValueError("hop_index is required")
        verdict = evaluate_hop_trust(hop, recipient_domain, org_lookup, policy)
        if verdict.trusted:
            trusted_count += 1
        else:
            break
    return trusted_count


def _iter_public_ips(hops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []
    for hop in sorted(hops, key=lambda item: int(item.get("hop_index", 0))):
        ip_values = hop.get("ips") or []
        for value in ip_values:
            try:
                addr = ipaddress.ip_address(value)
                if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                    addr = addr.ipv4_mapped
                if addr.is_global:
                    results.append({"hop_index": hop.get("hop_index"), "ip": str(addr), "confidence": "high"})
            except ValueError:
                continue
    return results


def find_earliest_reliable_ip(hops: list[dict[str, Any]], trusted_hop_limit: Optional[int] = None) -> Optional[dict[str, Any]]:
    if not hops:
        return None

    if trusted_hop_limit is None:
        return {
            "ip": None,
            "hop_index": None,
            "confidence": "unverified",
        }

    sorted_hops = sorted(hops, key=lambda item: int(item.get("hop_index", 0)))
    boundary_ip = None
    for hop in sorted_hops:
        if int(hop.get("hop_index", 0)) >= int(trusted_hop_limit):
            for ip_value in hop.get("ips") or []:
                try:
                    addr = ipaddress.ip_address(ip_value)
                    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                        addr = addr.ipv4_mapped
                    if addr.is_global:
                        boundary_ip = {"ip": str(addr), "hop_index": hop.get("hop_index"), "confidence": "high"}
                        return boundary_ip
                    if not addr.is_private and not addr.is_loopback and not addr.is_link_local and not addr.is_multicast and not addr.is_reserved:
                        boundary_ip = {"ip": str(addr), "hop_index": hop.get("hop_index"), "confidence": "low"}
                except ValueError:
                    continue
    if boundary_ip:
        return boundary_ip
    return None


def build_relay_chain(hops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    chain = []
    for hop in sorted(hops, key=lambda item: int(item.get("hop_index", 0)), reverse=True):
        ip_values = hop.get("ips") or []
        for value in ip_values:
            try:
                addr = ipaddress.ip_address(value)
                if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                    addr = addr.ipv4_mapped
                chain.append({
                    "hop_index": hop.get("hop_index"),
                    "ip": str(addr),
                    "is_public": bool(addr.is_global),
                    "is_private": bool(addr.is_private),
                })
            except ValueError:
                continue
    return chain


def naive_trace(hops: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if not hops:
        return None
    ordered = sorted(hops, key=lambda item: int(item.get("hop_index", 0)))
    first = ordered[0]
    for value in first.get("ips") or []:
        try:
            addr = ipaddress.ip_address(value)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                addr = addr.ipv4_mapped
            return {"ip": str(addr), "hop_index": first.get("hop_index")}
        except ValueError:
            continue
    return None


def build_trace_comparison(hops: list[dict[str, Any]], trusted_hop_limit: int, earliest_ip_info: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not hops:
        return {"outcome": "no_ips", "mismatch_detected": False, "explanation": "no relay hops available", "hop_by_hop_path": []}

    naive = naive_trace(hops)
    if earliest_ip_info is None:
        return {"outcome": "no_reliable_origin", "mismatch_detected": False, "explanation": "no reliable public origin was identified", "hop_by_hop_path": []}

    hop_path = []
    for hop in sorted(hops, key=lambda item: int(item.get("hop_index", 0))):
        status = "trusted" if int(hop.get("hop_index", 0)) < int(trusted_hop_limit) else "untrusted"
        hop_path.append({"hop_index": hop.get("hop_index"), "trust_status": status})

    if naive and earliest_ip_info.get("ip") == naive.get("ip"):
        return {"outcome": "agree", "mismatch_detected": False, "explanation": "the earliest reliable public IP agrees with the naive trace", "hop_by_hop_path": hop_path}

    return {
        "outcome": "mismatch",
        "mismatch_detected": True,
        "explanation": "trusted mail infrastructure boundary is present, but the earliest reliable public IP differs from the naive trace",
        "hop_by_hop_path": hop_path,
    }


__all__ = [
    "ProviderRule",
    "TrustPolicy",
    "HopTrustVerdict",
    "EvaluateHop",
    "_extract_from_hostname",
    "evaluate_hop_trust",
    "detect_trusted_hop_boundary",
    "find_earliest_reliable_ip",
    "build_relay_chain",
    "naive_trace",
    "build_trace_comparison",
]
