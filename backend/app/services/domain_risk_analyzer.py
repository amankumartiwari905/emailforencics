def calculate_domain_risk(domain_data: dict):

    score = 0
    reasons = []

    # Newly registered domain
    if domain_data.get("newly_registered") is True:
        score += 30
        reasons.append("Domain is newly registered")

    # Very young domain
    domain_age = domain_data.get("domain_age_days")

    if isinstance(domain_age, int) and domain_age < 30:
        score += 20
        reasons.append("Domain is less than 30 days old")

    # No MX record
    mx_records = domain_data.get("mx_records") or []

    if not mx_records:
        score += 10
        reasons.append("Domain has no MX record")

    # No NS records
    ns_records = domain_data.get("ns_records") or []

    if not ns_records:
        score += 5
        reasons.append("Domain has no NS record")

    # Missing registrar
    if not domain_data.get("registrar"):
        score += 5
        reasons.append("Registrar information unavailable")

    # Cap score at 100
    score = min(score, 100)

    if score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "domain": domain_data.get("domain"),
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }