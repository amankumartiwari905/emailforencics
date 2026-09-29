"""
Extracts IP addresses from email Received: headers, preserving hop order.

Received headers follow patterns like:
    from mail.example.com (mail.example.com [192.0.2.1])
    from [IPv6:2001:db8::1] (host.example.com [2001:db8::1])
    from example.com (example.com. [10.20.30.40]:25)

We extract only IPs found inside [..] or (..) -- the context MTAs
actually place the connecting IP in -- rather than scanning the whole
header text, which would also match version strings, message IDs, or
anything else dotted-quad-shaped.
"""

import re
import ipaddress
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Matches an IP (v4 or v6, with optional "IPv6:" prefix and optional
# trailing :port) inside [...] or (...). IPv6 addresses can contain
# colons themselves, so the char class covers both address families.
_IP_CONTEXT_RE = re.compile(
    r'\[(?:IPv6:)?([0-9a-fA-F:.]+)\](?::\d+)?'   # [IP] or [IPv6:IP] or [IP]:port
    r'|'
    r'\((?:IPv6:)?([0-9a-fA-F:.]+)\)(?::\d+)?'   # (IP) or (IPv6:IP) or (IP):port
)


def _is_valid_ip(candidate: str) -> bool:
    """Validates candidate as a real IPv4/IPv6 address, rejecting things
    like malformed fragments, version strings, or bare colons that the
    regex's charset might otherwise let through."""
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


@dataclass
class IpHop:
    """One Received-header hop and the IP(s) found within it."""
    hop_index: int
    header: str
    ips: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "hop_index": self.hop_index,
            "header": self.header,
            "ips": self.ips,
        }


def extract_ip_addresses(headers: list[str]) -> list[dict]:
    """
    Extracts IPs from a list of Received headers, preserving hop order
    and per-header grouping.

    Args:
        headers: Received header strings, in the order returned by the
            email parser (typically newest-hop-first).

    Returns:
        A list of dicts, one per header, each with:
            hop_index: position in the input list
            header: the original header text
            ips: deduped list of valid IPs found in that header, in
                 the order they appear

    Malformed or empty headers do not raise -- they simply produce an
    empty ips list for that hop, since a forensic pipeline should
    degrade gracefully rather than fail on one bad header among many.
    """
    if not headers:
        return []

    hops: list[IpHop] = []

    for idx, header in enumerate(headers):
        if not header or not isinstance(header, str):
            logger.debug("Skipping empty/invalid header at index %d", idx)
            hops.append(IpHop(hop_index=idx, header=header or "", ips=[]))
            continue

        found: list[str] = []
        try:
            for match in _IP_CONTEXT_RE.finditer(header):
                candidate = match.group(1) or match.group(2)
                if candidate and _is_valid_ip(candidate) and candidate not in found:
                    found.append(candidate)
        except re.error:
            logger.exception("Regex failure while parsing header at index %d", idx)

        hops.append(IpHop(hop_index=idx, header=header, ips=found))

    return [hop.to_dict() for hop in hops]


def flatten_unique_ips(hops: list[dict]) -> list[str]:
    """
    Returns a flat, order-preserved, deduped list of every IP seen
    across all hops. Useful for bulk operations (geolocation, proxy
    checks) where per-hop structure doesn't matter.

    Args:
        hops: the list of dicts returned by extract_ip_addresses().
    """
    seen: list[str] = []
    seen_set: set[str] = set()

    for hop in hops:
        for ip in hop.get("ips", []):
            if ip not in seen_set:
                seen.append(ip)
                seen_set.add(ip)

    return seen