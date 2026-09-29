"""
Interprets raw SPF/DKIM/DMARC results into a risk assessment.

Logic follows standard email-auth trust rules:
  - DMARC failing is the most serious (it's the policy the domain owner set)
  - SPF alone failing is common with legitimate forwarding, so weighted lower
  - DKIM failing means the message body/headers were altered in transit

Critical distinction this module makes explicit: "no Authentication-Results
header was present at all" (auth.get("spf") is None -- the receiving MTA
never evaluated anything, often because there's no Authentication-Results
header whatsoever) is NOT the same signal as "SPF was evaluated and the
result was explicitly 'none'" (spf == "none" -- meaning no SPF record
exists for the sending domain). The former means we have zero visibility
into authentication and should never be scored as merely a "minor issue"
-- an email with a completely absent Authentication-Results header is at
least as concerning as one with a bad-but-present result, since it often
means the message either bypassed the receiving MTA's normal auth
pipeline or the header was stripped somewhere in transit.
"""

from dataclasses import dataclass
from enum import Enum


class AuthVerdict(str, Enum):
    HIGH_RISK = "high_risk"
    SUSPICIOUS = "suspicious"
    MINOR_ISSUES = "minor_issues"
    UNVERIFIABLE = "unverifiable"  # no auth data available at all -- distinct
                                    # from "authenticated" or "minor_issues";
                                    # this is a visibility gap, not a clean bill
    AUTHENTICATED = "authenticated"


@dataclass(frozen=True)
class AuthRiskWeights:
    spf_fail: int = 20
    spf_softfail: int = 10
    spf_none: int = 8            # SPF evaluated, explicit result "none"
    spf_absent: int = 15         # SPF never evaluated -- no header at all
    dkim_fail: int = 25
    dkim_none: int = 10          # DKIM evaluated, explicit result "none"
    dkim_absent: int = 15        # DKIM never evaluated -- no header at all
    dmarc_fail: int = 35
    dmarc_none_with_policy_reject: int = 15
    dmarc_absent: int = 20       # DMARC never evaluated -- no header at all;
                                  # weighted highest of the "absent" cases since
                                  # DMARC is the authoritative aggregate signal


_DEFAULT_WEIGHTS = AuthRiskWeights()

# A completely missing Authentication-Results header (all three fields
# None) is treated as a hard floor at SUSPICIOUS regardless of the
# numeric score -- total absence of auth data should never silently
# round down to "minor_issues" just because the accumulated point total
# happens to land under a threshold.
_TOTAL_ABSENCE_MIN_VERDICT = AuthVerdict.SUSPICIOUS


def _classify_verdict(score: int, all_fields_absent: bool) -> AuthVerdict:
    if score >= 60:
        return AuthVerdict.HIGH_RISK
    if score >= 30:
        return AuthVerdict.SUSPICIOUS
    if all_fields_absent:
        # Never let "no data at all" resolve to "minor_issues" or
        # "authenticated" just because the point total is low -- an
        # absence of evidence is not evidence of a clean result.
        return AuthVerdict.UNVERIFIABLE
    if score > 0:
        return AuthVerdict.MINOR_ISSUES
    return AuthVerdict.AUTHENTICATED


def analyze_authentication(
    auth: dict,
    weights: AuthRiskWeights = _DEFAULT_WEIGHTS,
) -> dict:
    """
    auth: the dict returned by header_parser.parse_authentication_results(),
          i.e. {"spf": ..., "dkim": ..., "dmarc": ..., "dmarc_policy": ...}

    Distinguishes three states per mechanism, not two:
        None            -- no Authentication-Results header was present;
                            this mechanism was never evaluated at all
        ""  / "none"    -- header was present, mechanism explicitly
                            evaluated with no applicable record/result
        "pass"/"fail"/… -- header was present with a concrete result
    """
    if not isinstance(auth, dict):
        auth = {}

    spf_raw = auth.get("spf")
    dkim_raw = auth.get("dkim")
    dmarc_raw = auth.get("dmarc")
    dmarc_policy = (auth.get("dmarc_policy") or "").lower()

    spf_absent = spf_raw is None
    dkim_absent = dkim_raw is None
    dmarc_absent = dmarc_raw is None
    all_fields_absent = spf_absent and dkim_absent and dmarc_absent

    spf = (spf_raw or "").lower()
    dkim = (dkim_raw or "").lower()
    dmarc = (dmarc_raw or "").lower()

    score = 0
    reasons: list[str] = []

    # --- SPF ---
    if spf_absent:
        score += weights.spf_absent
        reasons.append("SPF was never evaluated — no Authentication-Results header found for SPF")
    elif spf == "fail":
        score += weights.spf_fail
        reasons.append("SPF failed — sending server is not authorized for this domain")
    elif spf == "softfail":
        score += weights.spf_softfail
        reasons.append("SPF softfail — sender is suspicious but not explicitly disallowed")
    elif spf in ("", "none"):
        score += weights.spf_none
        reasons.append("SPF evaluated: no applicable SPF record found for this domain")

    # --- DKIM ---
    if dkim_absent:
        score += weights.dkim_absent
        reasons.append("DKIM was never evaluated — no Authentication-Results header found for DKIM")
    elif dkim == "fail":
        score += weights.dkim_fail
        reasons.append("DKIM signature invalid — message may have been altered")
    elif dkim in ("", "none"):
        score += weights.dkim_none
        reasons.append("DKIM evaluated: no signature present")

    # --- DMARC (most authoritative -- combines SPF/DKIM + domain owner's policy) ---
    if dmarc_absent:
        score += weights.dmarc_absent
        reasons.append("DMARC was never evaluated — no Authentication-Results header found for DMARC")
    elif dmarc == "fail":
        score += weights.dmarc_fail
        reasons.append("DMARC failed — message does not comply with domain's authentication policy")
    elif dmarc in ("", "none") and dmarc_policy == "reject":
        score += weights.dmarc_none_with_policy_reject
        reasons.append("Domain publishes a strict DMARC policy but this message wasn't evaluated against it")

    score = min(score, 100)
    verdict = _classify_verdict(score, all_fields_absent)

    return {
        "spf": spf or None,
        "dkim": dkim or None,
        "dmarc": dmarc or None,
        "dmarc_policy": dmarc_policy or None,
        "spf_absent": spf_absent,
        "dkim_absent": dkim_absent,
        "dmarc_absent": dmarc_absent,
        "auth_risk_score": score,
        "verdict": verdict.value,
        "reasons": reasons,
    }