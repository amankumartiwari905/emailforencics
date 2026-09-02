"""
NLP-based fraud/social-engineering detection on email body text.

Two layers:
1. Pattern-based (always runs, instant, no API dependency) -- detects
   urgency language, BEC patterns (fake invoice, payment redirect,
   executive impersonation, credential harvesting).
2. Optional LLM-based layer (only if ANTHROPIC_API_KEY is set) -- catches
   subtler social engineering that fixed patterns miss, and gives a
   natural-language explanation of the manipulation tactics used.
"""

import os
import re
import json
import logging

logger = logging.getLogger(__name__)

# -------------------------
# Layer 1: Pattern-based detection
# -------------------------

URGENCY_PATTERNS = [
    r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bact now\b",
    r"\bwithin \d+\s*(hour|hr|minute|min)s?\b", r"\bexpir(es|ing|ed)\b",
    r"\btime[-\s]sensitive\b", r"\blast (chance|warning|notice)\b",
    r"\bfailure to (act|respond|comply)\b", r"\bsuspend(ed|sion)?\b",
    r"\baccount (will be|has been) (locked|suspended|terminated|closed)\b",
    r"\bverify (your|immediately)\b", r"\bconfirm (your|immediately)\b",
]

CREDENTIAL_HARVESTING_PATTERNS = [
    r"\b(click here|click below) to (verify|confirm|login|log in|sign in)\b",
    r"\bupdate your (password|account|billing|payment) (information|details)\b",
    r"\bre-?enter your (password|credentials|login)\b",
    r"\bconfirm your (identity|account|password)\b",
    r"\bunusual (activity|sign-?in|login)\b",
]

FINANCIAL_FRAUD_PATTERNS = [
    r"\b(wire|bank) transfer\b", r"\bchange(d)? (bank|payment) (details|account|information)\b",
    r"\bupdate(d)? (banking|payment) (details|information)\b",
    r"\boutstanding (invoice|payment|balance)\b", r"\battached invoice\b",
    r"\bgift card(s)?\b", r"\bpurchase.{0,20}gift card\b",
    r"\bprocess(ing)? (a )?payment\b", r"\bremit(tance)? (payment|advice)\b",
    r"\bnew (bank|account) details\b",
]

EXECUTIVE_IMPERSONATION_PATTERNS = [
    r"\b(are you (available|at your desk|free))\b",
    r"\bneed (this|it) done (asap|urgently|quickly|right away)\b",
    r"\bkeep this (confidential|between us|private)\b",
    r"\bdon'?t (tell|mention|discuss) (this )?(to )?(anyone|other staff)\b",
    r"\bi'?m (in a meeting|traveling|unavailable) (right now|currently)\b",
    r"\bcan you handle this for me\b",
]

GENERIC_GREETING_PATTERNS = [
    r"^\s*dear (customer|user|valued customer|sir/madam|account holder)\b",
]

_PATTERN_GROUPS = {
    "urgency": (URGENCY_PATTERNS, 8),
    "credential_harvesting": (CREDENTIAL_HARVESTING_PATTERNS, 15),
    "financial_fraud": (FINANCIAL_FRAUD_PATTERNS, 20),
    "executive_impersonation": (EXECUTIVE_IMPERSONATION_PATTERNS, 18),
    "generic_greeting": (GENERIC_GREETING_PATTERNS, 5),
}


def _run_pattern_layer(body: str, subject: str) -> dict:
    text = f"{subject or ''}\n{body or ''}".lower()

    score = 0
    matched_categories = []
    matched_phrases = []

    for category, (patterns, weight) in _PATTERN_GROUPS.items():
        hits = []
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                hits.append(match.group(0))

        if hits:
            score += weight
            matched_categories.append(category)
            matched_phrases.extend(hits[:2])  # cap to avoid huge lists

    score = min(score, 100)

    return {
        "pattern_score": score,
        "matched_categories": matched_categories,
        "matched_phrases": list(dict.fromkeys(matched_phrases))[:10],  # dedupe, cap
    }


# -------------------------
# Layer 2: Optional LLM-based deeper analysis
# -------------------------

async def _run_llm_layer(body: str, subject: str, sender: str) -> dict | None:
    """
    Uses Anthropic's API (if ANTHROPIC_API_KEY is set) to catch subtler
    social engineering that fixed patterns miss, and to explain the
    manipulation tactics in plain language for the forensic report.

    Returns None if no API key is configured -- pattern layer alone
    still works fine without this.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    try:
        import anthropic
    except ImportError:
        logger.warning("anthropic package not installed; skipping LLM layer")
        return None

    client = anthropic.AsyncAnthropic(api_key=api_key)

    prompt = f"""Analyze this email for social engineering, phishing, or business email compromise (BEC) indicators. Respond ONLY with valid JSON, no other text.

Subject: {subject or '(none)'}
From: {sender or '(none)'}
Body:
{(body or '')[:3000]}

Return JSON in exactly this shape:
{{
  "social_engineering_score": <integer 0-100>,
  "classification": "<one of: legitimate, suspicious, impersonated, phishing, fraud>",
  "tactics_identified": [<list of short strings naming tactics used, e.g. "urgency pressure", "authority impersonation">],
  "explanation": "<one or two sentence plain-language summary>"
}}"""

    try:
        response = await client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text.strip()
        text = re.sub(r"^```json\s*|\s*```$", "", text)  # strip markdown fences if present

        parsed = json.loads(text)
        return parsed

    except Exception as e:
        logger.warning("LLM threat analysis failed: %s", e)
        return None


# -------------------------
# Combined entry point
# -------------------------

async def analyze_nlp_threat(body: str, subject: str, sender: str = None) -> dict:
    pattern_result = _run_pattern_layer(body, subject)
    llm_result = await _run_llm_layer(body, subject, sender)

    if llm_result:
        # Blend: take the higher of the two scores (whichever layer
        # caught something, the risk is real), but keep both breakdowns
        # visible for transparency in the forensic report.
        combined_score = max(pattern_result["pattern_score"],
                           llm_result.get("social_engineering_score", 0))

        return {
            "threat_score": combined_score,
            "classification": llm_result.get("classification", "suspicious"),
            "pattern_layer": pattern_result,
            "llm_layer": llm_result,
            "tactics": llm_result.get("tactics_identified", []),
            "explanation": llm_result.get("explanation", ""),
        }
    else:
        # Fallback to pattern layer alone
        return {
            "threat_score": pattern_result["pattern_score"],
            "classification": "suspicious" if pattern_result["pattern_score"] > 50 else "legitimate",
            "pattern_layer": pattern_result,
            "llm_layer": None,
            "tactics": pattern_result["matched_categories"],
            "explanation": f"Detected patterns: {', '.join(pattern_result['matched_categories'])}",
        }