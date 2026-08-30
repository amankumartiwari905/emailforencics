import dns.resolver
import whois
from datetime import datetime, timezone


def analyze_domain(domain: str):

    # Domain validation
    if not domain or "." not in domain:
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
            "status": "invalid_domain"
        }

    result = {
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
        "status": "success"
        
    }

    # A records
    try:
        answers = dns.resolver.resolve(domain, "A")
        result["a_records"] = [
            str(answer) for answer in answers
        ]
    except Exception:
        pass

    # AAAA records
    try:
        answers = dns.resolver.resolve(domain, "AAAA")
        result["aaaa_records"] = [
            str(answer) for answer in answers
        ]
    except Exception:
        pass

    # MX records
    try:
        answers = dns.resolver.resolve(domain, "MX")
        result["mx_records"] = [
            str(answer.exchange).rstrip(".")
            for answer in answers
        ]
    except Exception:
        pass

    # NS records
    try:
        answers = dns.resolver.resolve(domain, "NS")
        result["ns_records"] = [
            str(answer).rstrip(".")
            for answer in answers
        ]
    except Exception:
        pass

    # WHOIS lookup
    try:
        domain_info = whois.whois(domain)

        result["registrar"] = domain_info.registrar

        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        # WHOIS can return a list of dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if creation_date:
            result["creation_date"] = creation_date.isoformat()

            now = datetime.now(timezone.utc)

            # Make creation date timezone-aware if needed
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(
                    tzinfo=timezone.utc
                )

            result["domain_age_days"] = (
                now - creation_date
            ).days

        if expiration_date:
            result["expiration_date"] = expiration_date.isoformat()

    except Exception:
        pass

    result["newly_registered"] = (
        result["domain_age_days"] <= 30
        if result["domain_age_days"] is not None
        else False
    )

    return result