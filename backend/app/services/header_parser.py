import re

_SPF_RE = re.compile(r'\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b', re.I)
_DKIM_RE = re.compile(r'\bdkim=(pass|fail|none|neutral|temperror|permerror)\b', re.I)
_DMARC_RE = re.compile(r'\bdmarc=(pass|fail|bestguesspass|none)\b', re.I)
_DMARC_POLICY_RE = re.compile(r'\bp=(reject|quarantine|none)\b', re.I)
_HEADER_FROM_RE = re.compile(r'header\.from=([\w.-]+)', re.I)


def parse_authentication_results(msg, trusted_receiving_domain: str | None = None):
    """
    Parses Authentication-Results headers.

    Only the FIRST Authentication-Results header is authoritative by default:
    it's the one your own receiving MTA inserted. Any Authentication-Results
    header further down the chain could have been forged by an earlier
    (attacker-controlled) hop, since nothing stops a malicious server from
    adding a fake 'spf=pass' header before it reaches you.

    If trusted_receiving_domain is given, we instead pick the first header
    whose field (before ';') matches that domain -- more robust when there
    are multiple receivers in a forwarding chain.
    """
    auth_headers = msg.get_all("Authentication-Results", [])

    result = {
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "dmarc_policy": None,
        "header_from_domain": None,
        "source_header_index": None,
        "raw": None,
    }

    if not auth_headers:
        return result

    chosen_index = 0
    if trusted_receiving_domain:
        for i, header in enumerate(auth_headers):
            if trusted_receiving_domain.lower() in header.split(";")[0].lower():
                chosen_index = i
                break

    header = auth_headers[chosen_index]

    spf_match = _SPF_RE.search(header)
    dkim_match = _DKIM_RE.search(header)
    dmarc_match = _DMARC_RE.search(header)
    policy_match = _DMARC_POLICY_RE.search(header)
    from_match = _HEADER_FROM_RE.search(header)

    result.update({
        "spf": spf_match.group(1).lower() if spf_match else None,
        "dkim": dkim_match.group(1).lower() if dkim_match else None,
        "dmarc": dmarc_match.group(1).lower() if dmarc_match else None,
        "dmarc_policy": policy_match.group(1).lower() if policy_match else None,
        "header_from_domain": from_match.group(1) if from_match else None,
        "source_header_index": chosen_index,
        "raw": header,
        "additional_headers_present": len(auth_headers) > 1,
    })

    return result