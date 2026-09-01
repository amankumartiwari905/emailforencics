import ipaddress


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