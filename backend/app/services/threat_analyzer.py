def analyze_threat(email_data):
    score = 0
    reasons = []

    authentication = email_data.get("authentication", {})

    # -------------------------
    # SPF
    # -------------------------
    spf = authentication.get("spf")

    if spf == "fail":
        score += 20
        reasons.append("SPF authentication failed")

    # -------------------------
    # DKIM
    # -------------------------
    dkim = authentication.get("dkim")

    if dkim == "fail":
        score += 15
        reasons.append("DKIM authentication failed")

    # -------------------------
    # DMARC
    # -------------------------
    dmarc = authentication.get("dmarc")

    if dmarc == "fail":
        score += 20
        reasons.append("DMARC authentication failed")

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
            reasons.append(
                "Sender and Reply-To domains do not match"
            )

    # -------------------------
    # Return-Path mismatch
    # -------------------------
    return_path = email_data.get("return_path")

    if sender and return_path:
        sender_domain = sender.split("@")[-1].lower()
        return_domain = return_path.split("@")[-1].lower()

        if sender_domain != return_domain:
            score += 15
            reasons.append(
                "Sender and Return-Path domains do not match"
            )

    # -------------------------
    # URLs
    # -------------------------
    links = email_data.get("links") or []

    if links:
        score += 5
        reasons.append("Email contains external links")

    # Suspicious URL results
    url_analysis = email_data.get("url_analysis") or []

    suspicious_urls = [
        result
        for result in url_analysis
        if result.get("suspicious") is True
    ]

    if suspicious_urls:
        score += min(len(suspicious_urls) * 20, 40)

        for result in suspicious_urls:
            url = result.get("url")

            reasons.append(
                f"Suspicious URL detected: {url}"
            )

    # -------------------------
    # Attachments
    # -------------------------
    attachments = email_data.get("attachments") or []

    if attachments:
        score += 10
        reasons.append("Email contains attachments")

    # -------------------------
    # Domain analysis
    # -------------------------
    domain_analysis = email_data.get("domain_analysis") or {}

    if domain_analysis.get("reply_to_mismatch"):
        # Avoid double-counting because we already added
        # the Reply-To mismatch above.
        pass

    if domain_analysis.get("return_path_mismatch"):
        # Avoid double-counting.
        pass

    # -------------------------
    # Domain intelligence risk
    # -------------------------
    domain_intelligence = email_data.get(
        "domain_intelligence"
    ) or {}

    for domain, intelligence in domain_intelligence.items():

        risk = intelligence.get("risk") or {}

        domain_score = risk.get("risk_score", 0)

        if isinstance(domain_score, (int, float)) and domain_score > 0:
            score += min(int(domain_score), 30)

            reasons.append(
                f"Domain risk detected for {domain}: "
                f"{domain_score}/100"
            )

    # -------------------------
    # IP intelligence
    # -------------------------
    ip_intelligence = email_data.get("ip_intelligence") or []

    for ip_data in ip_intelligence:

        risk_score = ip_data.get("risk_score")

        if isinstance(risk_score, (int, float)) and risk_score > 0:
            score += min(int(risk_score), 30)

            reasons.append(
                f"IP risk detected for {ip_data.get('ip')}: "
                f"{risk_score}"
            )

        if ip_data.get("vpn") is True:
            score += 10
            reasons.append(
                f"VPN detected for IP {ip_data.get('ip')}"
            )

        if ip_data.get("proxy") is True:
            score += 10
            reasons.append(
                f"Proxy detected for IP {ip_data.get('ip')}"
            )

        if ip_data.get("tor") is True:
            score += 15
            reasons.append(
                f"TOR detected for IP {ip_data.get('ip')}"
            )

        if ip_data.get("hosting") is True:
            score += 5
            reasons.append(
                f"Hosting infrastructure detected for IP "
                f"{ip_data.get('ip')}"
            )

    # -------------------------
    # Cap score
    # -------------------------
    score = min(score, 100)

    # -------------------------
    # Classification
    # -------------------------
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
        "reasons": reasons
    }