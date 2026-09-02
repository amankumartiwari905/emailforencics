from app.services.auth_analyzer import analyze_authentication


def analyze_threat(email_data):
    score = 0
    reasons = []

    # -------------------------
    # Authentication (SPF/DKIM/DMARC) — delegated to auth_analyzer
    # so this score is calculated in exactly one place.
    # -------------------------
    authentication = email_data.get("authentication", {})
    auth_result = analyze_authentication(authentication)

    # auth_analyzer's own score maxes at 100; scale it down to fit
    # proportionally into the overall fraud score instead of adding
    # its raw 0-100 value directly (that would dominate everything else).
    auth_contribution = min(int(auth_result["auth_risk_score"] * 0.6), 60)
    score += auth_contribution
    reasons.extend(auth_result["reasons"])

    # -------------------------
    # Sender / Reply-To
    # -------------------------
    sender = email_data.get("from")
    reply_to = email_data.get("reply_to")

    if sender and reply_to:
        sender_domain = sender.split("@")[-1].lower()
        reply_domain = reply_to.split("@")[-1].lower()

        if sender_domain != reply_domain:
            score += 15
            reasons.append("Sender and Reply-To domains do not match")

    # -------------------------
    # Return-Path mismatch
    # -------------------------
    return_path = email_data.get("return_path")

    if sender and return_path:
        sender_domain = sender.split("@")[-1].lower()
        return_domain = return_path.split("@")[-1].lower()

        if sender_domain != return_domain:
            score += 15
            reasons.append("Sender and Return-Path domains do not match")

    # -------------------------
    # URLs
    # -------------------------
    links = email_data.get("links") or []

    if links:
        score += 5
        reasons.append("Email contains external links")

    url_analysis = email_data.get("url_analysis") or []
    suspicious_urls = [r for r in url_analysis if r.get("suspicious") is True]

    if suspicious_urls:
        score += min(len(suspicious_urls) * 20, 40)
        for result in suspicious_urls:
            reasons.append(f"Suspicious URL detected: {result.get('url')}")

    # -------------------------
    # NLP / social engineering analysis
    # -------------------------
    nlp_analysis = email_data.get("nlp_analysis") or {}
    nlp_score = nlp_analysis.get("nlp_risk_score", 0)
    if nlp_score > 0:
        # Scale contribution similarly to auth -- this is one signal
        # among several, not the whole score.
        nlp_contribution = min(int(nlp_score * 0.5), 40)
        score += nlp_contribution

        categories = nlp_analysis.get("pattern_analysis", {}).get("matched_categories", [])
        if categories:
            reasons.append(f"Social engineering language detected: {', '.join(categories)}")

        llm = nlp_analysis.get("llm_analysis")
        if llm and llm.get("tactics_identified"):
            reasons.append(f"AI analysis flagged tactics: {', '.join(llm['tactics_identified'])}")
    # -------------------------
    # Attachments
    # -------------------------
    attachment_analysis = email_data.get("attachment_analysis") or []
    for att in attachment_analysis:
        att_score = att.get("risk_score", 0)
        if att_score > 0:
            score += min(att_score, 40)
            reasons.append(f"Suspicious attachment '{att.get('filename')}': {att.get('reasons')}")
    # -------------------------
    # Domain intelligence risk
    # -------------------------
    domain_intelligence = email_data.get("domain_intelligence") or {}
    for domain, intelligence in domain_intelligence.items():
        risk = intelligence.get("risk") or {}
        domain_score = risk.get("risk_score", 0)
        if isinstance(domain_score, (int, float)) and domain_score > 0:
            score += min(int(domain_score), 30)
            reasons.append(f"Domain risk detected for {domain}: {domain_score}/100")
     # -------------------------      
     # Lookalike domain detection
     # -------------------------
    lookalike_analysis = email_data.get("lookalike_analysis") or []
    for match in lookalike_analysis:
        score += 30
        reasons.append(match.get("reason"))

    # -------------------------
    # IP intelligence
    # -------------------------
    ip_intelligence = email_data.get("ip_intelligence") or []
    for ip_data in ip_intelligence:
        risk_score = ip_data.get("risk_score")
        if isinstance(risk_score, (int, float)) and risk_score > 0:
            score += min(int(risk_score), 30)
            reasons.append(f"IP risk detected for {ip_data.get('ip')}: {risk_score}")

        if ip_data.get("vpn") is True:
            score += 10
            reasons.append(f"VPN detected for IP {ip_data.get('ip')}")
        if ip_data.get("proxy") is True:
            score += 10
            reasons.append(f"Proxy detected for IP {ip_data.get('ip')}")
        if ip_data.get("tor") is True:
            score += 15
            reasons.append(f"TOR detected for IP {ip_data.get('ip')}")
        if ip_data.get("hosting") is True:
            score += 5
            reasons.append(f"Hosting infrastructure detected for IP {ip_data.get('ip')}")

    # -------------------------
    # Cap + classify
    # -------------------------
    score = min(score, 100)

    if score >= 75:
        classification = "CRITICAL"
    elif score >= 50:
        classification = "HIGH"
    elif score >= 25:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"

    return {
        "fraud_score": score,
        "classification": classification,
        "reasons": reasons,
        "auth_analysis": auth_result,  # full breakdown kept for the UI
        "nlp_analysis": nlp_analysis,
    }