import ipaddress
import re

# Common trusted mail infrastructure hostname patterns. Received headers
# added by these systems are treated as reliable, since major providers
# don't let arbitrary senders forge their own internal relay headers.
_TRUSTED_MTA_PATTERNS = [
    r"google\.com", r"gmail\.com", r"googlemail\.com",
    r"outlook\.com", r"protection\.outlook\.com", r"microsoft\.com",
    r"yahoo\.com", r"yahoodns\.net",
    r"amazonses\.com", r"amazonaws\.com",
    r"zoho\.com", r"protonmail\.ch",
]

_trusted_re = re.compile("|".join(_TRUSTED_MTA_PATTERNS), re.IGNORECASE)


def detect_trusted_hop_boundary(
    ip_hops: list[dict],
    recipient_domain: str | None = None
) -> int:
    """
    Walks hops from the top (hop_index 0 = most recently added, closest
    to the final recipient) downward, and returns the index of the first
    hop that does NOT look like trusted infrastructure.

    Everything from index 0 up to (but not including) the returned index
    is "our side" -- added by mail systems that don't let arbitrary
    senders forge headers. Everything from the returned index onward is
    untrusted territory: the attacker's infrastructure, or spoofable.

    If recipient_domain is given, it's also checked against each hop's
    header text -- catches self-hosted mail servers that wouldn't match
    the generic provider patterns above.
    """
    for hop in ip_hops:
        header = hop.get("header", "")

        is_trusted = bool(_trusted_re.search(header))

        if not is_trusted and recipient_domain:
            is_trusted = recipient_domain.lower() in header.lower()

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