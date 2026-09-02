import re
import ipaddress

_IP_CONTEXT_RE = re.compile(
    r'\[([0-9a-fA-F:.]+)\]|\(([0-9a-fA-F:.]+)\)'
)


def _is_valid_ip(candidate: str) -> bool:
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def extract_ip_addresses(headers):
    hops = []

    for idx, header in enumerate(headers):
        found = []
        for match in _IP_CONTEXT_RE.finditer(header):
            candidate = match.group(1) or match.group(2)
            if candidate and _is_valid_ip(candidate) and candidate not in found:
                found.append(candidate)

        hops.append({
            "hop_index": idx,
            "header": header,
            "ips": found,
        })

    return hops


def flatten_unique_ips(hops):
    seen = []
    for hop in hops:
        for ip in hop["ips"]:
            if ip not in seen:
                seen.append(ip)
    return seen