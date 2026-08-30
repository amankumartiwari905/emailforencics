import dns.resolver


def analyze_domain(domain: str):

    result = {
        "domain": domain,
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
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

    return result