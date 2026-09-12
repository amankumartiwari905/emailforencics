import ipaddress
import re

# Common trusted mail infrastructure hostname patterns. A hop's "from"
# hostname matching one of these is only trusted if the IP behind it
# also genuinely belongs to that provider (see _PROVIDER_ORG_KEYWORDS)
# -- otherwise an attacker naming their own server "mx.google.com"
# would get trusted just for the name, which defeats the whole point.
_TRUSTED_MTA_PATTERNS = [
    r"google\.com$", r"gmail\.com$", r"googlemail\.com$",
    r"outlook\.com$", r"protection\.outlook\.com$", r"microsoft\.com$",
    r"yahoo\.com$", r"yahoodns\.net$",
    r"amazonses\.com$", r"amazonaws\.com$",
    r"zoho\.com$", r"protonmail\.ch$",
]

_trusted_re = re.compile("|".join(_TRUSTED_MTA_PATTERNS), re.IGNORECASE)

# Maps a matched hostname pattern to keywords expected in the IP's real
# organization/ISP name (sourced from real IP intelligence, e.g.
# ProxyCheck's "organization" field).
_PROVIDER_ORG_KEYWORDS = {
    "google": ["google"],
    "gmail": ["google"],
    "googlemail": ["google"],
    "outlook": ["microsoft"],
    "protection.outlook": ["microsoft"],
    "microsoft": ["microsoft"],
    "yahoo": ["yahoo", "oath"],
    "yahoodns": ["yahoo", "oath"],
    "amazonses": ["amazon"],
    "amazonaws": ["amazon"],
    "zoho": ["zoho"],
    "protonmail": ["proton"],
}

_FROM_HOSTNAME_RE = re.compile(r'^from\s+([^\s(]+)', re.IGNORECASE)


def _extract_from_hostname(header: str) -> str:
    """Extracts only the hostname after 'from' -- the part that claims
    who sent this hop. Deliberately ignores the 'by ...' clause, since
    that can trivially contain trusted-looking text an attacker placed
    there on purpose (e.g. 'by mail-relay.yourcompany.com')."""
    match = _FROM_HOSTNAME_RE.search(header.strip())
    return match.group(1) if match else ""


def _hostname_org_keyword(hostname: str) -> list[str] | None:
    """Returns the expected organization keywords if hostname matches a
    known provider pattern, else None."""
    for pattern, keywords in _PROVIDER_ORG_KEYWORDS.items():
        if re.search(re.escape(pattern) + r"$", hostname, re.IGNORECASE):
            return keywords
    return None


def detect_trusted_hop_boundary(
    ip_hops: list[dict],
    recipient_domain: str | None = None,
    ip_org_lookup: dict[str, str] | None = None,
) -> int:
    """
    Walks hops from the top (hop_index 0 = most recently added, closest
    to the final recipient) downward, and returns the index of the first
    hop that cannot be verified as trusted.

    A hop is trusted only if EITHER:
    - its 'from' hostname ends with the recipient's own domain, OR
    - its 'from' hostname matches a known provider pattern (e.g.
      google.com) AND the IP behind that hop is actually registered
      to that provider (cross-checked against ip_org_lookup) -- a
      hostname claim alone is never enough, since it's attacker-writable
      text with no verification behind it.

    ip_org_lookup: dict mapping IP string -> organization/ISP name.
    If no org data is available for an IP claiming a trusted provider
    hostname, that hop is NOT trusted (fails closed, not open).
    """
    ip_org_lookup = ip_org_lookup or {}

    for hop in ip_hops:
        header = hop.get("header", "")
        from_hostname = _extract_from_hostname(header)
        hop_ips = hop.get("ips", [])

        is_trusted = False

        # Case 1: hostname is the recipient's own domain
        if recipient_domain and from_hostname.lower().endswith(recipient_domain.lower()):
            is_trusted = True

        # Case 2: hostname claims a known provider -- verify against
        # the actual IP organization before trusting it
        if not is_trusted:
            expected_keywords = _hostname_org_keyword(from_hostname)
            if expected_keywords:
                for ip in hop_ips:
                    org = (ip_org_lookup.get(ip) or "").lower()
                    if org and any(kw in org for kw in expected_keywords):
                        is_trusted = True
                        break

        if not is_trusted:
            return hop["hop_index"]

    return len(ip_hops)


def find_earliest_reliable_ip(
    ip_hops: list[dict],
    trusted_hop_limit: int | None = None
) -> dict | None:
    """
    Finds the oldest usable public IP from the Received-header chain.

    Private/reserved IP addresses are ignored because they cannot be
    meaningfully geolocated on the public Internet.

    If trusted_hop_limit is provided, the specified number of newest
    trusted hops are skipped.
    """

    if not ip_hops:
        return None

    start_index = trusted_hop_limit or 0
    candidates = ip_hops[start_index:]

    # Oldest → newest
    for hop in reversed(candidates):

        for ip in hop.get("ips", []):

            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue

            # Ignore private/reserved/loopback/link-local addresses
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
            ):
                continue

            return {
                "hop_index": hop["hop_index"],
                "ip": ip,
                "all_ips_at_hop": hop.get("ips", []),
                "header": hop["header"],
                "confidence": (
                    "high"
                    if trusted_hop_limit is not None
                    else "unverified"
                ),
            }

    return None


def build_relay_chain(ip_hops: list[dict]) -> list[dict]:
    """
    Returns the relay path in chronological order (oldest → newest).

    Keeps all hops, including private IPs, because private relay
    infrastructure can still be useful forensic evidence.
    """

    chain = [hop for hop in reversed(ip_hops) if hop.get("ips")]

    return [
        {
            "hop_index": hop["hop_index"],
            "ip": hop["ips"][0],
            "all_ips": hop["ips"]
        }
        for hop in chain
    ]


def naive_trace(ip_hops: list[dict]) -> dict | None:
    """
    Simulates what a naive tool does: trusts the FIRST IP found in the
    Received-header chain, no reasoning about which hops could be
    forged by the attacker vs. which are the recipient's own trusted
    infrastructure. This is what most basic phishing tools do.
    """
    if not ip_hops:
        return None

    for hop in ip_hops:
        if hop.get("ips"):
            return {
                "hop_index": hop["hop_index"],
                "ip": hop["ips"][0],
                "header": hop["header"],
                "method": "naive (first IP found, no trust reasoning)",
            }
    return None


def build_trace_comparison(
    ip_hops: list[dict],
    trusted_hop_limit: int,
    reasoned_result: dict | None,
) -> dict:
    """
    Compares the naive approach against our trusted-hop-boundary
    reasoning, and walks the full hop-by-hop path from receiver back
    to the earliest identifiable server -- this is the actual
    "sender -> server1 -> server2 -> server3 -> receiver" chain,
    walked backward.
    """
    naive_result = naive_trace(ip_hops)

    # Full hop-by-hop path, receiver-side (index 0) to sender-side (last)
    hop_path = []
    for hop in ip_hops:
        is_trusted = hop["hop_index"] < trusted_hop_limit
        hop_path.append({
            "hop_index": hop["hop_index"],
            "ip": hop["ips"][0] if hop["ips"] else None,
            "header": hop["header"],
            "trust_status": "trusted (recipient infrastructure)" if is_trusted else "untrusted (could be spoofed)",
        })

    mismatch = (
        naive_result is not None
        and reasoned_result is not None
        and naive_result["ip"] != reasoned_result["ip"]
    )

    return {
        "naive_trace": naive_result,
        "reasoned_trace": reasoned_result,
        "hop_by_hop_path": hop_path,
        "trust_boundary_hop_index": trusted_hop_limit,
        "mismatch_detected": mismatch,
        "explanation": (
            f"The naive approach would incorrectly trace this email to {naive_result['ip']}, "
            f"which is actually within the recipient's own trusted mail infrastructure. "
            f"Our system correctly identifies {reasoned_result['ip']} as the true origin by "
            f"walking past the trust boundary at hop {trusted_hop_limit}."
            if mismatch else
            "Both approaches agree on the origin IP for this email -- the relay chain in this "
            "case has a straightforward, unambiguous trust boundary."
        ),
    }