from fastapi import APIRouter, UploadFile, File
import asyncio

from app.services.email_parser import parse_email
from app.services.domain_analyzer import analyze_domains
from app.services.domain_intelligence import analyze_email_domains
from app.services.domain_risk_analyzer import calculate_domain_risk
from app.services.url_analyzer import analyze_urls
from app.services.threat_analyzer import analyze_threat
from app.services.identity_correlator import correlate_email
from app.services.proxy_check import check_proxy
from app.services.ip_geolocation import get_ip_location
from app.services.location_analyzer import (
    find_earliest_reliable_ip,
    build_relay_chain,
)

router = APIRouter()


@router.post("/analyze")
async def analyze_email_endpoint(file: UploadFile = File(...)):

    # ==========================================
    # 1. READ + PARSE EMAIL
    # ==========================================

    email_data = await file.read()

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
    # 5. RELAY CHAIN + EARLIEST PUBLIC IP
    # ==========================================

    earliest_ip_info = find_earliest_reliable_ip(ip_hops)

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
    # 9. THREAT ANALYSIS
    #
    # IMPORTANT:
    # Threat analyzer gets ALL intelligence.
    # ==========================================

    threat_input = {
        **parsed_email,

        "domain_analysis": domain_analysis,

        "domain_intelligence": domain_intelligence,

        "url_analysis": url_analysis,

        "ip_intelligence": ip_intelligence,
    }

    threat_analysis = analyze_threat(threat_input)


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

    return {
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
    }