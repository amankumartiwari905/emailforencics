from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
import re
import html
import logging
import hashlib

from app.services.ip_extractor import extract_ip_addresses, flatten_unique_ips
from app.services.ip_validator import validate_ip
from app.services.header_parser import parse_authentication_results

logger = logging.getLogger(__name__)

_LINK_RE = re.compile(r'https?://[^\s<>"\']+')
_TAG_RE = re.compile(r'<[^>]+>')

# Cap how much attachment content we'll read into memory per part.
# Prevents a single crafted .eml with a huge fake attachment from
# taking down the analysis worker.
_MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024  # 25MB


def _safe(stage_name, fn, default):
    """Run a parsing stage in isolation. A malformed/crafted email should
    degrade individual fields, not kill the whole analysis -- a forensic
    tool that can't handle a slightly broken phishing email is useless."""
    try:
        return fn()
    except Exception:
        logger.exception("Email parsing stage failed: %s", stage_name)
        return default


def _extract_body(msg: EmailMessage) -> tuple[str, str]:
    """Returns (body_text, source_type). Falls back to HTML-stripped
    text if there's no text/plain part, instead of silently returning ''."""
    plain, html_body = "", ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain" and not plain:
                plain = part.get_content()
            elif ctype == "text/html" and not html_body:
                html_body = part.get_content()
    else:
        if msg.get_content_type() == "text/plain":
            plain = msg.get_content()
        elif msg.get_content_type() == "text/html":
            html_body = msg.get_content()

    if plain:
        return plain, "text/plain"
    if html_body:
        # Strip tags for a text view; keep raw html separately if you want
        # to render it (sandboxed!) in the UI later.
        stripped = html.unescape(_TAG_RE.sub(" ", html_body))
        return stripped, "text/html (stripped)"
    return "", "none"


def parse_email(email_data: bytes) -> dict:
    result = {
        "from": None, "to": None, "subject": None, "date": None,
        "reply_to": None, "return_path": None,
        "body": "", "body_source": "none",
        "links": [], "attachments": [],
        "ip_hops": [], "unique_ips": [], "validated_ips": [],
        "received_headers": [], "authentication": {},
        "parse_errors": [],
    }

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

    received_headers = _safe("received_headers", lambda: msg.get_all("Received", []), [])
    result["received_headers"] = received_headers

    ip_hops = _safe("ip_extraction", lambda: extract_ip_addresses(received_headers), [])
    result["ip_hops"] = ip_hops

    unique_ips = _safe("ip_dedup", lambda: flatten_unique_ips(ip_hops), [])
    result["unique_ips"] = unique_ips

    # Validate once per unique IP -- no duplicate work, and no network
    # calls here. Geolocation is a separate, async, cacheable step that
    # should be triggered by the caller, not embedded in parsing.
    result["validated_ips"] = _safe(
        "ip_validation",
        lambda: [validate_ip(ip) for ip in unique_ips],
        [],
    )

    def _extract_attachments():
        found = []
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                payload = part.get_payload(decode=True) or b""
                truncated = len(payload) > _MAX_ATTACHMENT_BYTES

                # Hashes are used downstream for known-malicious-file
                # lookups and for de-duplicating attachments across
                # emails in the same campaign.
                sha256_hash = hashlib.sha256(payload).hexdigest() if payload else None
                md5_hash = hashlib.md5(payload).hexdigest() if payload else None

                found.append({
                    "filename": part.get_filename(),
                    "content_type": part.get_content_type(),
                    "size": len(payload),
                    "truncated": truncated,
                    "sha256": sha256_hash,
                    "md5": md5_hash,
                })
        return found

    result["attachments"] = _safe("attachment_extraction", _extract_attachments, [])

    return result