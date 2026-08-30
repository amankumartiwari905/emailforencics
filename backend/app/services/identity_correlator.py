case_history = []


def correlate_email(email_data):

    matches = []

    current_domains = set()
    current_ips = set()
    current_urls = set()

    domain_analysis = email_data.get("domain_analysis", {})

    for key in [
        "sender_domain",
        "reply_to_domain",
        "return_path_domain"
    ]:
        value = domain_analysis.get(key)

        if value:
            current_domains.add(value)

    for ip in email_data.get("email", {}).get("ip_addresses", []):
        current_ips.add(ip)

    for url in email_data.get("email", {}).get("links", []):
        current_urls.add(url)

    for case in case_history:

        common_domains = current_domains.intersection(case["domains"])
        common_ips = current_ips.intersection(case["ips"])
        common_urls = current_urls.intersection(case["urls"])

        if common_domains or common_ips or common_urls:

            matches.append({
                "case_id": case["case_id"],
                "common_domains": list(common_domains),
                "common_ips": list(common_ips),
                "common_urls": list(common_urls)
            })

    case_id = f"CASE-{len(case_history) + 1:04d}"

    case_history.append({
        "case_id": case_id,
        "domains": current_domains,
        "ips": current_ips,
        "urls": current_urls
    })

    return {
        "case_id": case_id,
        "related_cases": matches,
        "correlation_found": len(matches) > 0
    }