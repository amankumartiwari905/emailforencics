"""
Domain intelligence: DNS record resolution + WHOIS registration lookup.

Production concerns addressed vs. a naive implementation:
- Both dns.resolver and python-whois can hang indefinitely on an
  unresponsive server with no timeout set -- a single slow/malicious
  domain could otherwise stall the entire /analyze request. Every
  network call here has an explicit timeout.
- Sequential per-domain, per-record-type lookups are slow (an email
  with 3 domains x 5 lookups each = up to 15 sequential blocking
  calls). analyze_email_domains now runs domains concurrently via a
  thread pool, since dns.resolver/whois are both sync/blocking
  libraries with no native asyncio support.
- Bare `except Exception: pass` swallows real operational signal
  (timeout vs. NXDOMAIN vs. malformed response all look identical
  downstream) -- now logged with the specific failure reason.
"""

import logging
import socket
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.exception
import whois

logger = logging.getLogger(__name__)

_DNS_TIMEOUT_SECONDS = 5.0
_DNS_LIFETIME_SECONDS = 8.0  # total time budget across retries
_WHOIS_TIMEOUT_SECONDS = 8.0
_DOMAIN_ANALYSIS_MAX_WORKERS = 5
_NEWLY_REGISTERED_THRESHOLD_DAYS = 30

_RECORD_TYPES = ("A", "AAAA", "MX", "NS")


def _empty_domain_result(domain: str, status: str) -> dict:
    return {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "domain_age_days": None,
        "newly_registered": False,
        "status": status,
        "errors": [],
    }


def _is_valid_domain_format(domain: str) -> bool:
    """Basic structural sanity check -- not a full RFC 1035 validator,
    but enough to reject obviously malformed input before spending
    network round-trips on it."""
    if not domain or not isinstance(domain, str):
        return False
    domain = domain.strip()
    if "." not in domain or len(domain) > 253:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    return all(len(label) <= 63 for label in domain.split("."))


def _make_resolver() -> dns.resolver.Resolver:
    """Creates a resolver with explicit timeouts. A fresh instance per
    call avoids any shared-mutable-state issues if this module is ever
    used across threads (which it now is, via the thread pool below)."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = _DNS_TIMEOUT_SECONDS
    resolver.lifetime = _DNS_LIFETIME_SECONDS
    return resolver


def _resolve_records(resolver: dns.resolver.Resolver, domain: str, record_type: str) -> tuple[list[str], str | None]:
    """
    Returns (records, error). error is None on success (including the
    legitimate "no such record" case, which is not an error).
    """
    try:
        answers = resolver.resolve(domain, record_type)
    except dns.resolver.NXDOMAIN:
        return [], None  # domain doesn't exist -- not this function's job to flag
    except dns.resolver.NoAnswer:
        return [], None  # domain exists, just has no records of this type
    except dns.exception.Timeout:
        logger.warning("DNS %s lookup timed out for %s", record_type, domain)
        return [], f"{record_type.lower()}_timeout"
    except Exception as e:
        logger.warning("DNS %s lookup failed for %s: %s", record_type, domain, e)
        return [], f"{record_type.lower()}_error"

    if record_type == "MX":
        # RFC 7505 null MX ("." exchange, meaning "this domain accepts
        # no mail") should not be reported as an empty string after
        # rstrip -- filter it out explicitly rather than leaving a
        # misleading [""] in the result (the exact class of bug fixed
        # in calculate_domain_risk's mx_records handling).
        records = [str(a.exchange).rstrip(".") for a in answers]
        return [r for r in records if r], None

    return [str(a).rstrip(".") for a in answers], None


def _whois_lookup(domain: str) -> tuple[dict, str | None]:
    """
    Runs a WHOIS lookup with a hard timeout via socket.setdefaulttimeout,
    since python-whois doesn't expose a native timeout parameter.

    Note: setdefaulttimeout is process-global, not per-call -- this is
    a real limitation of the underlying library, not something this
    function can fully isolate. It's restored in a finally block to
    minimize the window where it affects unrelated socket calls
    elsewhere in the process.
    """
    info = {"registrar": None, "creation_date": None, "expiration_date": None}
    previous_timeout = socket.getdefaulttimeout()

    try:
        socket.setdefaulttimeout(_WHOIS_TIMEOUT_SECONDS)
        domain_info = whois.whois(domain)
    except Exception as e:
        logger.warning("WHOIS lookup failed for %s: %s", domain, e)
        return info, "whois_error"
    finally:
        socket.setdefaulttimeout(previous_timeout)

    registrar = getattr(domain_info, "registrar", None)
    creation_date = getattr(domain_info, "creation_date", None)
    expiration_date = getattr(domain_info, "expiration_date", None)

    # WHOIS providers inconsistently return a single date or a list of
    # dates (some registries report multiple historical records) --
    # take the earliest for creation, since that's the true registration
    # date; either the first or a min() over the list would work, min()
    # is more defensive against providers that don't return them sorted.
    if isinstance(creation_date, list) and creation_date:
        creation_date = min((d for d in creation_date if d is not None), default=None)
    if isinstance(expiration_date, list) and expiration_date:
        expiration_date = max((d for d in expiration_date if d is not None), default=None)

    info["registrar"] = registrar if isinstance(registrar, str) and registrar.strip() else None

    if creation_date:
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        info["creation_date"] = creation_date

    if expiration_date:
        if expiration_date.tzinfo is None:
            expiration_date = expiration_date.replace(tzinfo=timezone.utc)
        info["expiration_date"] = expiration_date

    return info, None


def analyze_domain(domain: str) -> dict:
    """
    Resolves DNS records (A/AAAA/MX/NS) and WHOIS registration data for
    a single domain.

    Returns a dict with status "invalid_domain" for structurally bad
    input, or "success" otherwise (individual sub-lookups can still
    fail independently -- see the "errors" list for which ones did).
    """
    if not _is_valid_domain_format(domain):
        return _empty_domain_result(domain, "invalid_domain")

    domain = domain.strip().lower()
    result = _empty_domain_result(domain, "success")
    resolver = _make_resolver()

    for record_type in _RECORD_TYPES:
        records, error = _resolve_records(resolver, domain, record_type)
        result[f"{record_type.lower()}_records"] = records
        if error:
            result["errors"].append(error)

    whois_info, whois_error = _whois_lookup(domain)
    if whois_error:
        result["errors"].append(whois_error)

    result["registrar"] = whois_info["registrar"]

    creation_date = whois_info["creation_date"]
    expiration_date = whois_info["expiration_date"]

    if creation_date:
        result["creation_date"] = creation_date.isoformat()
        now = datetime.now(timezone.utc)
        result["domain_age_days"] = (now - creation_date).days

    if expiration_date:
        result["expiration_date"] = expiration_date.isoformat()

    result["newly_registered"] = (
        result["domain_age_days"] is not None
        and result["domain_age_days"] <= _NEWLY_REGISTERED_THRESHOLD_DAYS
    )

    return result


def analyze_email_domains(domain_analysis: dict) -> dict:
    """
    Analyzes every distinct sender/reply-to/return-path domain from an
    email's domain_analysis dict, concurrently.

    dns.resolver and python-whois are both synchronous/blocking
    libraries with no native asyncio support, so concurrency here uses
    a thread pool rather than asyncio.gather (which the rest of this
    codebase uses for genuinely async I/O like httpx calls). Each
    domain's DNS+WHOIS lookups (up to ~5 network round-trips) run in
    its own thread, so N domains take roughly as long as the slowest
    one instead of the sum of all of them.
    """
    domains: set[str] = set()

    for key in ("sender_domain", "reply_to_domain", "return_path_domain"):
        value = domain_analysis.get(key)
        if value and isinstance(value, str):
            domains.add(value.strip().lower())

    if not domains:
        return {}

    results: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=min(_DOMAIN_ANALYSIS_MAX_WORKERS, len(domains))) as pool:
        future_to_domain = {pool.submit(analyze_domain, d): d for d in domains}

        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                results[domain] = future.result()
            except Exception:
                logger.exception("Unexpected failure analyzing domain %s", domain)
                results[domain] = _empty_domain_result(domain, "error")

    return results