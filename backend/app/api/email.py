from fastapi import APIRouter, UploadFile, File
from app.services.identity_correlator import correlate_email
from app.services.email_parser import parse_email
from app.services.threat_analyzer import analyze_threat
from app.services.domain_analyzer import analyze_domains
from app.services.url_analyzer import analyze_urls
from app.services.domain_intelligence import analyze_domain
router = APIRouter()


@router.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):

    email_data = await file.read()

    parsed_email = parse_email(email_data)

    domain_analysis = analyze_domains(parsed_email)

    threat_analysis = analyze_threat(parsed_email)
    
    sender_domain = domain_analysis.get("sender_domain")

    domain_intelligence = None

    if sender_domain:
        domain_intelligence = analyze_domain(sender_domain)

    # Reuse the parsed message and analyze every extracted URL.  Emails with
    # no links should still produce a valid response.
    links = parsed_email.get("links") or []
    url_analysis = analyze_urls(links)

    identity_correlation = correlate_email({
        **parsed_email,
        "domain_analysis": domain_analysis
    })

    return {
        "email": parsed_email,
        "domain_analysis": domain_analysis,
        "threat_analysis": threat_analysis,
        "url_analysis": url_analysis,
        "domain_intelligence": domain_intelligence,
        "identity_correlation": identity_correlation
    }