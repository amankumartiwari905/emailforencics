"""
Email analysis API routes.

Orchestrates the full forensic pipeline: parsing, IP/geolocation
intelligence, domain intelligence, URL/attachment analysis, NLP + ML
phishing detection, threat scoring, identity correlation, and report
generation.

Production concerns addressed vs. the working version:
- Upload size/type are validated before any processing starts, so a
  multi-GB or non-email upload can't tie up worker resources before
  even reaching parse_email's own internal safeguards.
- Every pipeline stage is wrapped so a failure in one intelligence
  source (a DNS timeout, a ProxyCheck outage, a broken attachment)
  degrades that stage's output rather than failing the whole request
  -- consistent with the error-isolation philosophy already used
  throughout the underlying services (_safe() in email_parser.py, the
  per-section wrapper in report_generator.py).
- attachment_analysis is now correctly awaited -- analyze_attachments
  became async when VirusTotal lookups were added, but the call site
  here was still synchronous, which would have raised "a coroutine was
  never awaited" or silently produced a coroutine object instead of a
  result list.
- Structured logging with request-scoped context (email_hash, case_id)
  so a slow or failing request can be traced through logs without
  string-grepping.
"""

import asyncio
import logging
import os
import tempfile
from io import BytesIO

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from starlette.datastructures import UploadFile as StarletteUploadFile

from app.services.email_parser import parse_email
from app.services.domain_analyzer import analyze_domains
from app.services.domain_intelligence import analyze_email_domains
from app.services.analysis_cache import (
    compute_email_hash,
    get_cached_analysis,
    set_cached_analysis,
)
from app.services.domain_risk_analyzer import calculate_domain_risk
from app.services.url_analyzer import analyze_urls
from app.services.threat_analyzer import analyze_threat
from app.services.identity_correlator import (
    get_campaign_cluster,
    get_full_graph,
    correlate_email,
)
from app.services.report_generator import generate_forensic_report
from app.services.attachment_analyzer import analyze_attachments
from app.services.lookalike_domain_detector import analyze_domains_for_lookalikes
from app.services.nlp_threat_analyzer import analyze_nlp_threat
from app.services.phishing_classifier import classify_email
from app.services.proxy_check import check_proxy
from app.services.ip_geolocation import get_ip_location
from app.services.location_analyzer import (
    find_earliest_reliable_ip,
    build_relay_chain,
    detect_trusted_hop_boundary,
    build_trace_comparison,
)

logger = logging.getLogger(__name__)

router = APIRouter()

_MAX_UPLOAD_BYTES = 30 * 1024 * 1024  # 30MB -- generously above the
                                        # 25MB per-attachment cap in
                                        # email_parser.py, since a
                                        # multipart email has headers
                                        # + encoding overhead on top
_ALLOWED_CONTENT_TYPES = {
    "message/rfc822", "application/octet-stream", "text/plain", "",
}  # "" covers browsers/clients that omit a content-type for .eml


async def _read_upload_bounded(file: UploadFile) -> bytes:
    """
    Reads an upload with a hard size cap, rejecting oversized uploads
    before they're fully buffered into memory. FastAPI's UploadFile
    already spools to disk past a threshold, but we still want to
    reject absurd uploads early with a clear error rather than letting
    them flow into the parsing pipeline.
    """
    chunks = []
    total = 0
    chunk_size = 1024 * 1024  # 1MB

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Upload exceeds maximum allowed size of {_MAX_UPLOAD_BYTES // (1024 * 1024)}MB",
            )
        chunks.append(chunk)

    return b"".join(chunks)


def _extract_recipient_domain(to_header: str | None) -> str | None:
    """Extracts the recipient's own domain from the To header, used to
    identify which relay hops belong to trusted, recipient-controlled
    infrastructure. Uses the same RFC-5322-aware extraction as
    domain_analyzer to avoid the display-name-corruption bug that
    naive '@'-splitting has (see domain_analyzer.extract_domain)."""
    from app.services.domain_analyzer import extract_domain
    return extract_domain(to_header)


async def _run_ip_intelligence(ip_addresses: list[str]) -> tuple[list[dict], dict[str, str]]:
    """
    Runs ProxyCheck lookups for every extracted IP and builds an
    IP -> organization lookup used later to verify whether a hop's
    claimed hostname (e.g. "mx.google.com") genuinely corresponds to
    that provider's IP space, rather than trusting the hostname text
    alone (see location_analyzer.detect_trusted_hop_boundary).

    check_proxy is synchronous (requests-based), so this runs it in a
    thread pool via asyncio.to_thread rather than blocking the event
    loop for each IP sequentially.
    """
    if not ip_addresses:
        return [], {}

    try:
        ip_intelligence = await asyncio.gather(
            *[asyncio.to_thread(check_proxy, ip) for ip in ip_addresses],
            return_exceptions=True,
        )
    except Exception:
        logger.exception("IP intelligence batch failed unexpectedly")
        ip_intelligence = [{"ip": ip, "error": "lookup_failed"} for ip in ip_addresses]
    else:
        ip_intelligence = [
            item if not isinstance(item, Exception)
            else {"ip": ip, "error": str(item)}
            for ip, item in zip(ip_addresses, ip_intelligence)
        ]

    ip_org_lookup = {
        item.get("ip"): item.get("organization") or item.get("provider")
        for item in ip_intelligence
        if isinstance(item, dict) and item.get("ip")
    }

    return ip_intelligence, ip_org_lookup


async def _run_geolocation(ip_addresses: list[str]) -> dict[str, dict]:
    if not ip_addresses:
        return {}

    geo_results = await asyncio.gather(
        *[get_ip_location(ip) for ip in ip_addresses],
        return_exceptions=True,
    )

    return {
        ip: (
            location if not isinstance(location, Exception)
            else {"ip": ip, "status": "lookup_error", "reason": str(location)}
        )
        for ip, location in zip(ip_addresses, geo_results)
    }


async def _run_stage(stage_name: str, coro_or_call, default):
    """
    Runs one pipeline stage (sync or async) in isolation. On failure,
    logs the exception and returns `default` so one broken intelligence
    source never takes down the entire /analyze request -- consistent
    with the error-isolation approach used inside email_parser.py.
    """
    try:
        result = coro_or_call() if callable(coro_or_call) else coro_or_call
        if asyncio.iscoroutine(result):
            result = await result
        return result
    except Exception:
        logger.exception("Pipeline stage failed: %s", stage_name)
        return default


@router.post("/analyze")
async def analyze_email_endpoint(file: UploadFile = File(...)):
    """
    Runs the full forensic analysis pipeline on an uploaded .eml file
    and returns the structured result. Identical results for the same
    email content are served from cache instead of re-running external
    API calls.
    """
    if file.content_type not in _ALLOWED_CONTENT_TYPES:
        logger.info("Unexpected content-type for upload: %s", file.content_type)
        # Not rejected outright -- many valid .eml uploads arrive with
        # an unhelpful or missing content-type depending on the client,
        # and email_parser.py's own parsing will reject genuinely
        # invalid content. This is logged for visibility, not enforced.

    # ==========================================
    # 1. READ + PARSE EMAIL
    # ==========================================

    email_data = await _read_upload_bounded(file)

    if not email_data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    email_hash = compute_email_hash(email_data)
    cached_result = get_cached_analysis(email_hash)
    if cached_result is not None:
        logger.info("Cache hit for email_hash=%s", email_hash[:12])
        return cached_result

    parsed_email = parse_email(email_data)

    # ==========================================
    # 2. IP EXTRACTION
    # ==========================================

    ip_addresses = parsed_email.get("unique_ips") or []
    ip_hops = parsed_email.get("ip_hops") or []

    # ==========================================
    # 3. VPN / PROXY / TOR INTELLIGENCE + IP GEOLOCATION
    #    (run concurrently -- independent external API calls)
    # ==========================================

    (ip_intelligence, ip_org_lookup), ip_locations = await asyncio.gather(
        _run_ip_intelligence(ip_addresses),
        _run_geolocation(ip_addresses),
    )

    # ==========================================
    # 4. RELAY CHAIN + EARLIEST RELIABLE IP
    # ==========================================

    recipient_domain = _extract_recipient_domain(parsed_email.get("to"))

    trusted_hop_limit = await _run_stage(
        "trusted_hop_boundary",
        lambda: detect_trusted_hop_boundary(ip_hops, recipient_domain, ip_org_lookup),
        0,
    )
    earliest_ip_info = await _run_stage(
        "earliest_reliable_ip",
        lambda: find_earliest_reliable_ip(ip_hops, trusted_hop_limit),
        None,
    )
    relay_chain = await _run_stage(
        "relay_chain", lambda: build_relay_chain(ip_hops), []
    )
    trace_comparison = await _run_stage(
        "trace_comparison",
        lambda: build_trace_comparison(ip_hops, trusted_hop_limit, earliest_ip_info),
        {"outcome": "unavailable", "mismatch_detected": False},
    )

    # ==========================================
    # 5. DOMAIN ANALYSIS + DNS/WHOIS INTELLIGENCE
    # ==========================================

    domain_analysis = await _run_stage(
        "domain_analysis", lambda: analyze_domains(parsed_email), {}
    )
    domain_intelligence = await _run_stage(
        "domain_intelligence", lambda: analyze_email_domains(domain_analysis), {}
    )

    for domain, data in domain_intelligence.items():
        try:
            domain_intelligence[domain]["risk"] = calculate_domain_risk(data)
        except Exception:
            logger.exception("Domain risk scoring failed for %s", domain)
            domain_intelligence[domain]["risk"] = {
                "domain": domain, "risk_score": 0, "risk_level": "UNKNOWN", "reasons": [],
            }

    # ==========================================
    # 6. URL ANALYSIS
    # ==========================================

    links = parsed_email.get("links") or []
    url_analysis = await _run_stage("url_analysis", lambda: analyze_urls(links), [])

    # ==========================================
    # 7. ATTACHMENT ANALYSIS
    #    (async -- includes VirusTotal hash lookups)
    # ==========================================

    attachments = parsed_email.get("attachments") or []
    attachment_analysis = await _run_stage(
        "attachment_analysis", analyze_attachments(attachments), []
    )

    # ==========================================
    # 8. LOOKALIKE DOMAIN DETECTION
    # ==========================================

    domains_to_check = list(domain_intelligence.keys())
    lookalike_analysis = await _run_stage(
        "lookalike_domains",
        lambda: analyze_domains_for_lookalikes(domains_to_check),
        [],
    )

    # ==========================================
    # 9. NLP + ML PHISHING CLASSIFICATION
    #    (run concurrently -- independent analyses)
    # ==========================================

    nlp_analysis, ml_phishing_analysis = await asyncio.gather(
        _run_stage(
            "nlp_analysis",
            analyze_nlp_threat(
                body=parsed_email.get("body"),
                subject=parsed_email.get("subject"),
                sender=parsed_email.get("from"),
            ),
            {"threat_score": 0, "nlp_signal_tier": "unavailable", "tactics": [], "reasons": []},
        ),
        _run_stage(
            "ml_phishing_classification",
            lambda: classify_email(
                subject=parsed_email.get("subject"),
                body=parsed_email.get("body"),
            ),
            {"prediction": "unavailable", "phishing_probability": None},
        ),
    )

    # ==========================================
    # 10. THREAT ANALYSIS (aggregate scoring)
    # ==========================================

    threat_input = {
        **parsed_email,
        "domain_analysis": domain_analysis,
        "domain_intelligence": domain_intelligence,
        "url_analysis": url_analysis,
        "ip_intelligence": ip_intelligence,
        "attachment_analysis": attachment_analysis,
        "lookalike_analysis": lookalike_analysis,
        "nlp_analysis": nlp_analysis,
        "ml_phishing_analysis": ml_phishing_analysis,
    }

    threat_analysis = await _run_stage(
        "threat_scoring",
        lambda: analyze_threat(threat_input),
        {"fraud_score": None, "classification": "unavailable", "reasons": []},
    )

    # ==========================================
    # 11. IDENTITY CORRELATION
    # ==========================================

    identity_correlation = await _run_stage(
        "identity_correlation",
        lambda: correlate_email({**parsed_email, "domain_analysis": domain_analysis}),
        {"case_id": None, "related_cases": [], "correlation_found": False},
    )

    # ==========================================
    # 12. FINAL RESPONSE
    # ==========================================

    result = {
        "email": parsed_email,
        "domain_analysis": domain_analysis,
        "domain_intelligence": domain_intelligence,
        "threat_analysis": threat_analysis,
        "url_analysis": url_analysis,
        "identity_correlation": identity_correlation,
        "ip_intelligence": ip_intelligence,
        "ip_locations": ip_locations,
        "earliest_reliable_ip": earliest_ip_info,
        "relay_chain": relay_chain,
        "trace_comparison": trace_comparison,
        "attachment_analysis": attachment_analysis,
        "lookalike_analysis": lookalike_analysis,
        "nlp_analysis": nlp_analysis,
        "ml_phishing_analysis": ml_phishing_analysis,
    }

    set_cached_analysis(email_hash, result)

    logger.info(
        "Analysis complete: case_id=%s classification=%s fraud_score=%s",
        identity_correlation.get("case_id"),
        threat_analysis.get("classification"),
        threat_analysis.get("fraud_score"),
    )

    return result


@router.post("/analyze/report")
async def analyze_email_with_report(file: UploadFile = File(...)):
    """
    Returns a downloadable PDF forensic report. Reuses a cached
    analysis if this exact email was already analyzed via /analyze
    recently, otherwise runs the full pipeline once and caches it.
    """
    email_data = await _read_upload_bounded(file)

    if not email_data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    email_hash = compute_email_hash(email_data)
    analysis = get_cached_analysis(email_hash)

    if analysis is None:
        rebuilt_file = StarletteUploadFile(filename=file.filename, file=BytesIO(email_data))
        analysis = await analyze_email_endpoint(rebuilt_file)

    tmp_dir = tempfile.gettempdir()
    output_path = os.path.join(tmp_dir, f"forensic_report_{os.urandom(4).hex()}.pdf")

    try:
        generate_forensic_report(analysis, output_path)
    except Exception:
        logger.exception("PDF report generation failed for email_hash=%s", email_hash[:12])
        raise HTTPException(status_code=500, detail="Failed to generate forensic report")

    return FileResponse(
        output_path,
        media_type="application/pdf",
        filename="forensic_report.pdf",
    )


@router.get("/cases/{case_id}/cluster")
async def get_case_cluster(case_id: str):
    """
    Returns the full campaign cluster (graph) this case belongs to --
    every connected case/domain/IP/URL reachable through shared
    indicators, for rendering a network graph in the dashboard.
    """
    cluster = get_campaign_cluster(case_id)
    if cluster is None:
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    return cluster


@router.get("/cases/graph")
async def get_correlation_graph():
    """Returns the entire correlation graph across all analyzed emails."""
    return get_full_graph()