"""
Parses Authentication-Results headers into structured SPF/DKIM/DMARC
verdicts.

Security note: an Authentication-Results header is only trustworthy if
it was added by the recipient's own receiving MTA -- any hop before
that boundary is attacker-controlled and can freely forge a fake
'spf=pass' header to defeat naive parsers that just grab the first
match. This module picks the header most likely to be authoritative
and explicitly reports when that choice is uncertain, rather than
silently defaulting to something that might be wrong.
"""

import re
import logging
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

_SPF_VALUES = "pass|fail|softfail|neutral|none|temperror|permerror"
_DKIM_VALUES = "pass|fail|none|neutral|temperror|permerror"
_DMARC_VALUES = "pass|fail|bestguesspass|none"
_POLICY_VALUES = "reject|quarantine|none"

_SPF_RE = re.compile(rf'\bspf=({_SPF_VALUES})\b', re.IGNORECASE)
_DKIM_RE = re.compile(rf'\bdkim=({_DKIM_VALUES})\b', re.IGNORECASE)
_DMARC_RE = re.compile(rf'\bdmarc=({_DMARC_VALUES})\b', re.IGNORECASE)
_DMARC_POLICY_RE = re.compile(rf'\bp=({_POLICY_VALUES})\b', re.IGNORECASE)
_HEADER_FROM_RE = re.compile(r'header\.from=([\w.-]+)', re.IGNORECASE)

# The authserv-id (text before the first ';') should END WITH the
# trusted domain, not merely contain it as a substring -- "in" matching
# lets an attacker-controlled header claiming to be
# "notyourcompany.com.evil-relay.net" falsely match a
# trusted_receiving_domain of "yourcompany.com". endswith() (after
# stripping a leading dot-separator) is far harder to spoof this way.
_AUTHSERV_ID_RE = re.compile(r'^\s*([^\s;]+)')


@dataclass
class AuthenticationResult:
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    dmarc_policy: str | None = None
    header_from_domain: str | None = None
    source_header_index: int | None = None
    raw: str | None = None
    additional_headers_present: bool = False
    trust_verified: bool = False  # True only if trusted_receiving_domain
                                   # was given AND actually matched a header
    parse_warnings: list = None

    def __post_init__(self):
        if self.parse_warnings is None:
            self.parse_warnings = []

    def to_dict(self) -> dict:
        return asdict(self)


def _authserv_id(header: str) -> str:
    """Extracts the authserv-id -- the token before the first ';' -- 
    which per RFC 8601 identifies the authenticating server."""
    match = _AUTHSERV_ID_RE.match(header)
    return match.group(1) if match else ""


def _domain_matches_authserv_id(authserv_id: str, trusted_domain: str) -> bool:
    """
    True if authserv_id is exactly trusted_domain, or a subdomain of it
    (e.g. "mx1.yourcompany.com" matches "yourcompany.com"). Deliberately
    NOT a substring check, to resist an attacker crafting an authserv-id
    that merely contains the trusted domain as text.
    """
    authserv_id = authserv_id.lower().strip()
    trusted_domain = trusted_domain.lower().strip().lstrip(".")

    return authserv_id == trusted_domain or authserv_id.endswith("." + trusted_domain)


def _select_authoritative_header(
    auth_headers: list[str],
    trusted_receiving_domain: str | None,
) -> tuple[int, bool]:
    """
    Returns (chosen_index, trust_verified).

    trust_verified is True only when trusted_receiving_domain was
    provided AND a header's authserv-id genuinely matched it -- callers
    should treat trust_verified=False as "we picked the first header as
    a best guess, but couldn't confirm it's the recipient's own MTA."
    """
    if not trusted_receiving_domain:
        return 0, False

    for i, header in enumerate(auth_headers):
        authserv_id = _authserv_id(header)
        if _domain_matches_authserv_id(authserv_id, trusted_receiving_domain):
            return i, True

    # No header's authserv-id matched the trusted domain -- falling back
    # to index 0 is a guess, not a verified choice, and callers should
    # know that via trust_verified=False.
    logger.debug(
        "trusted_receiving_domain=%r did not match any Authentication-Results "
        "authserv-id; falling back to first header as unverified guess",
        trusted_receiving_domain,
    )
    return 0, False


def parse_authentication_results(
    msg,
    trusted_receiving_domain: str | None = None,
) -> dict:
    """
    Parses Authentication-Results headers into SPF/DKIM/DMARC verdicts.

    Only ONE header is treated as authoritative: by default the first
    one (closest to the recipient, generally the receiving MTA's own),
    since any Authentication-Results header further down the relay
    chain could have been forged by an earlier, attacker-controlled
    hop -- nothing stops a malicious server from inserting a fake
    'spf=pass' header before the email reaches the real recipient MTA.

    If trusted_receiving_domain is given, the header whose authserv-id
    actually matches that domain (or a subdomain of it) is preferred
    over positional order -- more robust when there are multiple
    receivers in a forwarding chain. If no header matches, this falls
    back to index 0 as an unverified guess, and the result's
    `trust_verified` field reflects that explicitly.

    Returns a dict (see AuthenticationResult) always containing every
    key, so callers never need defensive .get() chains.
    """
    result = AuthenticationResult()

    try:
        auth_headers = msg.get_all("Authentication-Results", []) or []
    except Exception:
        logger.exception("Failed to read Authentication-Results headers")
        result.parse_warnings.append("header_read_failed")
        return result.to_dict()

    if not auth_headers:
        return result.to_dict()

    chosen_index, trust_verified = _select_authoritative_header(
        auth_headers, trusted_receiving_domain
    )

    header = auth_headers[chosen_index]
    if not isinstance(header, str):
        result.parse_warnings.append("selected_header_not_string")
        return result.to_dict()

    spf_match = _SPF_RE.search(header)
    dkim_match = _DKIM_RE.search(header)
    dmarc_match = _DMARC_RE.search(header)
    policy_match = _DMARC_POLICY_RE.search(header)
    from_match = _HEADER_FROM_RE.search(header)

    result.spf = spf_match.group(1).lower() if spf_match else None
    result.dkim = dkim_match.group(1).lower() if dkim_match else None
    result.dmarc = dmarc_match.group(1).lower() if dmarc_match else None
    result.dmarc_policy = policy_match.group(1).lower() if policy_match else None
    result.header_from_domain = from_match.group(1) if from_match else None
    result.source_header_index = chosen_index
    result.raw = header
    result.additional_headers_present = len(auth_headers) > 1
    result.trust_verified = trust_verified

    if trusted_receiving_domain and not trust_verified:
        result.parse_warnings.append(
            "trusted_receiving_domain_not_matched_any_header"
        )

    return result.to_dict()