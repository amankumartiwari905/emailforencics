def parse_authentication_results(msg):
    auth_headers = msg.get_all("Authentication-Results", [])

    result = {
        "spf": None,
        "dkim": None,
        "dmarc": None
    }

    for header in auth_headers:
        header = header.lower()

        if "spf=pass" in header:
            result["spf"] = "pass"
        elif "spf=fail" in header:
            result["spf"] = "fail"
        elif "spf=softfail" in header:
            result["spf"] = "softfail"
        elif "spf=neutral" in header:
            result["spf"] = "neutral"

        if "dkim=pass" in header:
            result["dkim"] = "pass"
        elif "dkim=fail" in header:
            result["dkim"] = "fail"

        if "dmarc=pass" in header:
            result["dmarc"] = "pass"
        elif "dmarc=fail" in header:
            result["dmarc"] = "fail"

    return result