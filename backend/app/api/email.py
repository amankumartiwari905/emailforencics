from ipaddress import ip_address

from fastapi import APIRouter, UploadFile, File
from app.services.domain_risk_analyzer import calculate_domain_risk
from app.services.email_parser import parse_email
from app.services.threat_analyzer import analyze_threat
from app.services.domain_analyzer import analyze_domains
from app.services.proxy_check import check_proxy
from app.services.domain_intelligence import analyze_email_domains
from app.services.url_analyzer import analyze_urls
from app.services.identity_correlator import correlate_email

router = APIRouter()


@router.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):

    # Read uploaded email
    email_data = await file.read()

    # Parse email
    parsed_email = parse_email(email_data)
    
    ip_addresses = parsed_email.get("ip_addresses") or []

    # IP intelligence
    ip_intelligence = []
    for ip in ip_addresses:
        ip_intelligence.append(check_proxy(ip))

    # Basic domain analysis
    domain_analysis = analyze_domains(parsed_email)

    # Real DNS / MX / NS intelligence
    domain_intelligence = analyze_email_domains(domain_analysis)

    # Calculate risk scores for each domain
    for domain, data in domain_intelligence.items():
        domain_intelligence[domain]["risk"] = calculate_domain_risk(data)

    # Threat analysis
    threat_analysis = analyze_threat(parsed_email)

    # URL analysis
    links = parsed_email.get("links") or []
    url_analysis = analyze_urls(links)

    # Identity / previous-case correlation
    identity_correlation = correlate_email({
        **parsed_email,
        "domain_analysis": domain_analysis
    })

    return {
        "email": parsed_email,
        "domain_analysis": domain_analysis,
        "domain_intelligence": domain_intelligence,
        "threat_analysis": threat_analysis,
        "url_analysis": url_analysis,
        "identity_correlation": identity_correlation,
        "ip_intelligence": ip_intelligence,
    }