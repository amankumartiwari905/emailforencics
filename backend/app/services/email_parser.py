"""
Parses a raw email into a structured forensic record: headers, body,
links, attachments (with hashes), IP relay chain, and authentication
results. Every extraction stage is isolated so a malformed or
adversarially crafted email degrades individual fields instead of
crashing the whole analysis -- a forensic tool that can't handle a
slightly broken phishing email is useless.
"""

from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.errors import MessageError
import re
import html
import logging
import hashlib
from typing import Callable, TypeVar

from app.services.ip_extractor import extract_ip_addresses, flatten_unique_ips
from app.services.ip_validator import validate_ip
from app.services.header_parser import parse_authentication_results

logger = logging.getLogger(__name__)

T = TypeVar("T")

_LINK_RE = re.compile(r'https?://[^\s<>"\']+')
_TAG_RE = re.compile(r'<[^>]+>')

# Caps how much of an attachment we hash/report on. A crafted .eml with
# a huge fake attachment shouldn't be able to make the analysis worker
# spend unbounded time/memory hashing it -- we hash only up to this
# limit and flag the result as truncated, rather than hashing the full
# payload (which would defeat the point of having a cap at all).
_MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024  # 25MB

# Hard ceiling on total decoded attachment bytes read across the whole
# email, independent of the per-attachment cap -- protects against an
# email with hundreds of medium-sized attachments collectively exceeding
# available memory even though no single one trips the per-file cap.
_MAX_TOTAL_ATTACHMENT_BYTES = 200 * 1024 * 1024  # 200MB


def _safe(stage_name: str, fn: Callable[[], T], default: T) -> T:
    """Runs a parsing stage in isolation, logging and falling back to
    `default` on any exception rather than propagating it."""
    try:
        return fn()
    except Exception:
        logger.exception("Email parsing stage failed: %s", stage_name)
        return default


def _extract_body(msg: EmailMessage) -> tuple[str, str]:
    """
    Returns (body_text, source_type). Prefers text/plain; falls back to
    HTML-stripped text if only text/html is present, instead of
    silently returning an empty body.
    """
    plain, html_body = "", ""

    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.is_multipart():
                    continue  # container parts have no own content
                ctype = part.get_content_type()
                if ctype == "text/plain" and not plain:
                    plain = part.get_content()
                elif ctype == "text/html" and not html_body:
                    html_body = part.get_content()
        else:
            ctype = msg.get_content_type()
            if ctype == "text/plain":
                plain = msg.get_content()
            elif ctype == "text/html":
                html_body = msg.get_content()
    except (LookupError, MessageError, UnicodeDecodeError) as e:
        # get_content() can raise on bad charset declarations or
        # malformed MIME -- a crafted email shouldn't be able to
        # abort body extraction entirely because of this.
        logger.warning("Body content decode failed: %s", e)

    if plain:
        return plain, "text/plain"
    if html_body:
        stripped = html.unescape(_TAG_RE.sub(" ", html_body))
        return stripped, "text/html (stripped)"
    return "", "none"


def _decode_payload_bounded(part, remaining_budget: int) -> tuple[bytes, bool]:
    """
    Decodes an attachment's payload, but only reads up to
    min(_MAX_ATTACHMENT_BYTES, remaining_budget) bytes worth of hashing
    work. Returns (payload_used_for_hash, was_truncated).

    Note: get_payload(decode=True) still materializes the full decoded
    payload in memory (the email module doesn't support streaming
    decode), so this bounds what we DO with it (hashing, size
    reporting) rather than bounding the decode itself -- a fully
    streaming parser would be a larger change to the underlying
    email-parsing approach.
    """
    payload = part.get_payload(decode=True) or b""
    full_size = len(payload)

    cap = min(_MAX_ATTACHMENT_BYTES, max(remaining_budget, 0))
    truncated = full_size > cap

    return (payload[:cap] if truncated else payload), truncated, full_size


def _extract_attachments(msg: EmailMessage) -> list[dict]:
    found = []
    total_budget_remaining = _MAX_TOTAL_ATTACHMENT_BYTES

    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue

        try:
            payload_for_hash, truncated, full_size = _decode_payload_bounded(
                part, total_budget_remaining
            )
        except Exception:
            logger.exception("Failed to decode attachment payload; skipping")
            found.append({
                "filename": _safe("attachment_filename", part.get_filename, None),
                "content_type": _safe("attachment_content_type", part.get_content_type, None),
                "size": None,
                "truncated": None,
                "sha256": None,
                "md5": None,
                "error": "payload_decode_failed",
            })
            continue

        total_budget_remaining -= len(payload_for_hash)

        # Hashes are computed over the (possibly truncated) payload and
        # explicitly reported as partial when truncation occurred --
        # a partial-file hash should never be treated as a definitive
        # match against a known-malicious-hash list downstream.
        sha256_hash = hashlib.sha256(payload_for_hash).hexdigest() if payload_for_hash else None
        md5_hash = hashlib.md5(payload_for_hash).hexdigest() if payload_for_hash else None

        found.append({
            "filename": _safe("attachment_filename", part.get_filename, None),
            "content_type": _safe("attachment_content_type", part.get_content_type, None),
            "size": full_size,
            "truncated": truncated,
            "sha256": sha256_hash,
            "md5": md5_hash,
            "error": None,
        })

        if total_budget_remaining <= 0:
            logger.warning(
                "Total attachment budget exhausted; remaining attachments "
                "in this email will not be hashed"
            )
            break

    return found


def parse_email(email_data: bytes) -> dict:
    """
    Parses raw email bytes into a structured forensic record.

    Every field defaults to a safe empty value and is populated via
    _safe(), so a malformed or adversarially crafted email produces a
    partial-but-usable result with `parse_errors` populated, rather
    than raising and aborting the whole /analyze request.
    """
    result: dict = {
        "from": None, "to": None, "subject": None, "date": None,
        "reply_to": None, "return_path": None,
        "body": "", "body_source": "none",
        "links": [], "attachments": [],
        "ip_hops": [], "unique_ips": [], "validated_ips": [],
        "received_headers": [], "authentication": {},
        "parse_errors": [],
    }

    if not isinstance(email_data, (bytes, bytearray)):
        result["parse_errors"].append(
            f"invalid_input_type: expected bytes, got {type(email_data).__name__}"
        )
        return result

    if not email_data:
        result["parse_errors"].append("empty_email_data")
        return result

    try:
        msg = BytesParser(policy=policy.default).parsebytes(email_data)
    except Exception as e:
        logger.exception("Failed to parse raw email bytes")
        result["parse_errors"].append(f"unparseable_email: {e}")
        return result

    result["from"] = _safe("from_header", lambda: msg.get("From"), None)
    result["to"] = _safe("to_header", lambda: msg.get("To"), None)
    result["subject"] = _safe("subject_header", lambda: msg.get("Subject"), None)
    result["date"] = _safe("date_header", lambda: msg.get("Date"), None)
    result["reply_to"] = _safe("reply_to_header", lambda: msg.get("Reply-To"), None)
    result["return_path"] = _safe("return_path_header", lambda: msg.get("Return-Path"), None)

    body, body_source = _safe("body_extraction", lambda: _extract_body(msg), ("", "error"))
    result["body"] = body
    result["body_source"] = body_source
    result["links"] = _safe("link_extraction", lambda: _LINK_RE.findall(body), [])

    result["authentication"] = _safe(
        "authentication_parsing",
        lambda: parse_authentication_results(msg),
        {"spf": None, "dkim": None, "dmarc": None},
    )

    received_headers = _safe("received_headers", lambda: msg.get_all("Received", []) or [], [])
    result["received_headers"] = received_headers

    ip_hops = _safe("ip_extraction", lambda: extract_ip_addresses(received_headers), [])
    result["ip_hops"] = ip_hops

    unique_ips = _safe("ip_dedup", lambda: flatten_unique_ips(ip_hops), [])
    result["unique_ips"] = unique_ips

    # Validate once per unique IP -- no duplicate work, and no network
    # calls here. Geolocation is a separate, async, cacheable step
    # triggered by the caller, not embedded in parsing.
    result["validated_ips"] = _safe(
        "ip_validation",
        lambda: [validate_ip(ip) for ip in unique_ips],
        [],
    )

    result["attachments"] = _safe("attachment_extraction", lambda: _extract_attachments(msg), [])

    return result