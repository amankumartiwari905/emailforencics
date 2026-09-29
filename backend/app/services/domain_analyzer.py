"""
Extracts and compares domains from email address header fields
(From/Reply-To/Return-Path) to detect sender-identity mismatches --
one of the most common and cheapest-to-check phishing signals (a
legitimate sender rarely has their reply-to or bounce address on a
different domain than their From address).
"""

import logging
from email.utils import parseaddr
from email.headerregistry import Address

logger = logging.getLogger(__name__)


def extract_domain(email_field: str | None) -> str | None:
    """
    Extracts the domain from a raw email header value, correctly
    handling RFC 5322 "Display Name <address@domain>" format --
    NOT just naive splitting on '@'.

    This matters concretely: a raw From header like
        "John Smith - CEO" <ceo@yourcompany-corp.com>
    naively split on '@' and taking everything after it produces
    "yourcompany-corp.com>" -- the trailing angle bracket leaks into
    the domain, corrupting every downstream comparison, WHOIS lookup,
    and lookalike-domain check that consumes it. email.utils.parseaddr
    is the standard library's RFC-5322-aware parser and handles this
    correctly, including quoted display names, comments, and
    multiple '@' edge cases that naive splitting gets wrong.

    Returns None for empty/malformed input, and for International
    Domain Names (IDN) returns the ASCII/punycode form (e.g.
    'xn--...') so it matches consistently against DNS/WHOIS lookups,
    which operate on punycode, not the raw Unicode.
    """
    if not email_field or not isinstance(email_field, str):
        return None

    display_name, address = parseaddr(email_field)

    if not address or "@" not in address:
        return None

    domain = address.rsplit("@", 1)[-1].strip().lower()

    if not domain:
        return None

    # Strip a single trailing dot (FQDN notation, e.g. "example.com.")
    # so it compares equal to the non-dotted form everywhere else.
    domain = domain.rstrip(".")

    if not domain:
        return None

    # Normalize IDN/Unicode domains to punycode (ASCII) so comparisons
    # and downstream DNS/WHOIS lookups are consistent -- a domain
    # written with Unicode homoglyphs and its punycode equivalent
    # should be treated as the exact same domain here, not as a
    # mismatch or two different keys in domain_intelligence.
    try:
        domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        # Not encodable as IDNA (e.g. already-invalid domain syntax,
        # or contains characters idna can't handle) -- keep the
        # lowercased raw form rather than failing the whole extraction.
        logger.debug("IDNA encoding failed for domain %r; using raw form", domain)

    return domain


def analyze_domains(email_data: dict) -> dict:
    """
    Compares the From, Reply-To, and Return-Path domains of an email
    to flag sender-identity mismatches -- a classic phishing/BEC
    indicator (attacker controls the From display name but routes
    replies/bounces to their own infrastructure).

    A mismatch is only flagged when BOTH domains being compared are
    present and successfully extracted -- a missing Reply-To (very
    common in legitimate mail) is not itself suspicious and should
    never be reported as a "mismatch".
    """
    if not isinstance(email_data, dict):
        logger.warning("analyze_domains received non-dict input: %r", type(email_data))
        email_data = {}

    sender = email_data.get("from")
    reply_to = email_data.get("reply_to")
    return_path = email_data.get("return_path")

    sender_domain = extract_domain(sender)
    reply_to_domain = extract_domain(reply_to)
    return_path_domain = extract_domain(return_path)

    reply_to_mismatch = bool(
        sender_domain and reply_to_domain and sender_domain != reply_to_domain
    )
    return_path_mismatch = bool(
        sender_domain and return_path_domain and sender_domain != return_path_domain
    )

    return {
        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "reply_to_mismatch": reply_to_mismatch,
        "return_path_mismatch": return_path_mismatch,
    }