"""
Interprets raw SPF/DKIM/DMARC results into a risk assessment.
Logic follows standard email-auth trust rules:
  - DMARC failing is the most serious (it's the policy the domain owner set)
  - SPF alone failing is common with legitimate forwarding, so weighted lower
  - DKIM failing means the message body/headers were altered in transit
"""

RISK_WEIGHTS = {
    "spf_fail": 20,
    "spf_softfail": 10,
    "spf_none": 8,
    "dkim_fail": 25,
    "dkim_none": 10,
    "dmarc_fail": 35,
    "dmarc_none_with_policy_reject": 15,  # DMARC missing but domain publishes p=reject elsewhere
}


def analyze_authentication(auth: dict) -> dict:
    """
    auth: the dict returned by header_parser.parse_authentication_results()
          i.e. {"spf": ..., "dkim": ..., "dmarc": ..., "dmarc_policy": ..., ...}
    """
    spf = (auth.get("spf") or "").lower()
    dkim = (auth.get("dkim") or "").lower()
    dmarc = (auth.get("dmarc") or "").lower()
    dmarc_policy = (auth.get("dmarc_policy") or "").lower()

    score = 0
    reasons = []

    # --- SPF ---
    if spf == "fail":
        score += RISK_WEIGHTS["spf_fail"]
        reasons.append("SPF failed — sending server is not authorized for this domain")
    elif spf == "softfail":
        score += RISK_WEIGHTS["spf_softfail"]
        reasons.append("SPF softfail — sender is suspicious but not explicitly disallowed")
    elif spf in ("", "none"):
        score += RISK_WEIGHTS["spf_none"]
        reasons.append("No SPF record found or not evaluated")

    # --- DKIM ---
    if dkim == "fail":
        score += RISK_WEIGHTS["dkim_fail"]
        reasons.append("DKIM signature invalid — message may have been altered")
    elif dkim in ("", "none"):
        score += RISK_WEIGHTS["dkim_none"]
        reasons.append("No DKIM signature present")

    # --- DMARC (most authoritative — combines SPF/DKIM + domain owner's policy) ---
    if dmarc == "fail":
        score += RISK_WEIGHTS["dmarc_fail"]
        reasons.append("DMARC failed — message does not comply with domain's authentication policy")
    elif dmarc in ("", "none") and dmarc_policy == "reject":
        score += RISK_WEIGHTS["dmarc_none_with_policy_reject"]
        reasons.append("Domain publishes a strict DMARC policy but this message wasn't evaluated against it")

    score = min(score, 100)

    if score >= 60:
        verdict = "high_risk"
    elif score >= 30:
        verdict = "suspicious"
    elif score > 0:
        verdict = "minor_issues"
    else:
        verdict = "authenticated"

    return {
        "spf": spf or None,
        "dkim": dkim or None,
        "dmarc": dmarc or None,
        "dmarc_policy": dmarc_policy or None,
        "auth_risk_score": score,
        "verdict": verdict,
        "reasons": reasons,
    }