from fastapi import APIRouter, UploadFile, File
from app.services.email_parser import parse_email

router = APIRouter()


def analyze_threat(email_data):
    score = 0
    reasons = []

    # SPF
    spf = email_data.get("authentication", {}).get("spf")

    if spf == "fail":
        score += 20
        reasons.append("SPF authentication failed")

    # DKIM
    dkim = email_data.get("authentication", {}).get("dkim")

    if dkim == "fail":
        score += 15
        reasons.append("DKIM authentication failed")

    # DMARC
    dmarc = email_data.get("authentication", {}).get("dmarc")

    if dmarc == "fail":
        score += 20
        reasons.append("DMARC authentication failed")

    # Reply-To mismatch
    sender = email_data.get("from")
    reply_to = email_data.get("reply_to")

    if sender and reply_to:
        sender_domain = sender.split("@")[-1].lower()
        reply_domain = reply_to.split("@")[-1].lower()

        if sender_domain != reply_domain:
            score += 15
            reasons.append("Sender and Reply-To domains do not match")

    # Links
    links = email_data.get("links", [])

    if links:
        score += 10
        reasons.append("Email contains external links")

    # Attachments
    attachments = email_data.get("attachments", [])

    if attachments:
        score += 10
        reasons.append("Email contains attachments")

    score = min(score, 100)

    if score >= 70:
        classification = "PHISHING"
    elif score >= 40:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"

    return {
        "fraud_score": score,
        "classification": classification,
        "reasons": reasons
    }