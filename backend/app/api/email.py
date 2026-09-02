from fastapi import APIRouter, UploadFile, File
import asyncio
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
import os
from app.services.identity_correlator import get_campaign_cluster, get_full_graph
import tempfile
from fastapi.responses import FileResponse
from app.services.report_generator import generate_forensic_report
from app.services.attachment_analyzer import analyze_attachments
from app.services.lookalike_domain_detector import analyze_domains_for_lookalikes
from app.services.nlp_threat_analyzer import analyze_nlp_threat
from app.services.identity_correlator import correlate_email
from app.services.phishing_classifier import classify_email
from app.services.proxy_check import check_proxy
from app.services.ip_geolocation import get_ip_location
from app.services.location_analyzer import (
    find_earliest_reliable_ip,
    build_relay_chain,
    detect_trusted_hop_boundary,
)

router = APIRouter()


@router.post("/analyze")
async def analyze_email_endpoint(file: UploadFile = File(...)):

    # ==========================================
    # 1. READ + PARSE EMAIL
    # ==========================================

    email_data = await file.read()

    email_hash = compute_email_hash(email_data)
    cached_result = get_cached_analysis(email_hash)
    if cached_result is not None:
        return cached_result

    parsed_email = parse_email(email_data)


    # ==========================================
    # 2. IP EXTRACTION
    # ==========================================

    ip_addresses = parsed_email.get("unique_ips") or []
    ip_hops = parsed_email.get("ip_hops") or []


    # ==========================================
    # 3. VPN / PROXY / TOR INTELLIGENCE
    # ==========================================

    ip_intelligence = []

    for ip in ip_addresses:
        ip_intelligence.append(check_proxy(ip))


    # ==========================================
    # 4. IP GEOLOCATION
    # ==========================================

    geo_results = await asyncio.gather(
        *[get_ip_location(ip) for ip in ip_addresses],
        return_exceptions=True,
    )

    ip_locations = {
        ip: (
            location
            if not isinstance(location, Exception)
            else {
                "ip": ip,
                "status": "lookup_error",
                "reason": str(location),
            }
        )
        for ip, location in zip(ip_addresses, geo_results)
    }


    # ==========================================
    # 5. RELAY CHAIN + EARLIEST RELIABLE IP
    # ==========================================

    recipient_domain = None
    to_header = parsed_email.get("to")

    if to_header and "@" in to_header:
        recipient_domain = to_header.split("@")[-1].strip(">").strip()

    trusted_hop_limit = detect_trusted_hop_boundary(
        ip_hops,
        recipient_domain
    )

    earliest_ip_info = find_earliest_reliable_ip(
        ip_hops,
        trusted_hop_limit
    )

    relay_chain = build_relay_chain(ip_hops)


    # ==========================================
    # 6. DOMAIN ANALYSIS
    # ==========================================

    domain_analysis = analyze_domains(parsed_email)

    domain_intelligence = analyze_email_domains(
        domain_analysis
    )


    # ==========================================
    # 7. DOMAIN RISK ANALYSIS
    # ==========================================

    for domain, data in domain_intelligence.items():

        domain_intelligence[domain]["risk"] = (
            calculate_domain_risk(data)
        )


    # ==========================================
    # 8. URL ANALYSIS
    # ==========================================

    links = parsed_email.get("links") or []

    url_analysis = analyze_urls(links)


    # ==========================================
    # 8b. ATTACHMENT ANALYSIS
    # ==========================================

    attachments = parsed_email.get("attachments") or []

    attachment_analysis = analyze_attachments(
        attachments
    )


    # ==========================================
    # 8c. LOOKALIKE DOMAIN DETECTION
    # ==========================================

    domains_to_check = list(
        domain_intelligence.keys()
    )

    lookalike_analysis = analyze_domains_for_lookalikes(
        domains_to_check
    )


    # ==========================================
    # 8d. NLP / SOCIAL ENGINEERING ANALYSIS
    #
    # Detects urgency language, BEC patterns
    # (fake invoice, payment redirect, executive
    # impersonation), and credential harvesting cues.
    # ==========================================

    nlp_analysis = await analyze_nlp_threat(
        body=parsed_email.get("body"),
        subject=parsed_email.get("subject"),
        sender=parsed_email.get("from"),
    )


    # ==========================================
    # 8e. ML PHISHING CLASSIFICATION
    #
    # Uses TF-IDF + Logistic Regression to classify
    # the email as phishing or legitimate.
    # ==========================================

    ml_phishing_analysis = classify_email(
        subject=parsed_email.get("subject"),
        body=parsed_email.get("body"),
    )


    # ==========================================
    # 9. THREAT ANALYSIS
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

    threat_analysis = analyze_threat(
        threat_input
    )


    # ==========================================
    # 10. IDENTITY CORRELATION
    # ==========================================

    identity_correlation = correlate_email({
        **parsed_email,
        "domain_analysis": domain_analysis,
    })


    # ==========================================
    # 11. FINAL RESPONSE
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

        "attachment_analysis": attachment_analysis,

        "lookalike_analysis": lookalike_analysis,

        "nlp_analysis": nlp_analysis,

        "ml_phishing_analysis": ml_phishing_analysis,
    }

    set_cached_analysis(
        email_hash,
        result
    )

    return result


@router.post("/analyze/report")
async def analyze_email_with_report(
    file: UploadFile = File(...)
):
    """
    Returns a downloadable PDF forensic report.
    Reuses a cached analysis if this exact email was
    already analyzed via /analyze recently,
    otherwise runs the full pipeline once and caches it.
    """

    email_data = await file.read()

    email_hash = compute_email_hash(
        email_data
    )

    analysis = get_cached_analysis(
        email_hash
    )

    if analysis is None:
        from starlette.datastructures import UploadFile as StarletteUploadFile
        from io import BytesIO

        rebuilt_file = StarletteUploadFile(
            filename=file.filename,
            file=BytesIO(email_data)
        )

        analysis = await analyze_email_endpoint(
            rebuilt_file
        )

    tmp_dir = tempfile.gettempdir()

    output_path = os.path.join(
        tmp_dir,
        f"forensic_report_{os.urandom(4).hex()}.pdf"
    )

    generate_forensic_report(
        analysis,
        output_path
    )

    return FileResponse(
        output_path,
        media_type="application/pdf",
        filename="forensic_report.pdf"
    )