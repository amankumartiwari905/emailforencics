"""
Flags suspicious attachments using three signals:
1. Known-malicious hash match (static demo blocklist -- swap for a real
   threat-intel feed like VirusTotal or MalwareBazaar in production)
2. Dangerous file extensions (executables, scripts, macros)
3. Extension/content-type mismatch (e.g. a .pdf that's actually a .exe --
   a classic "disguised executable" trick)
"""

import os

# Demo blocklist -- in production, query VirusTotal/MalwareBazaar/Abuse.ch
# by hash instead of a static list. This keeps the feature demoable
# offline without needing a paid API key.
KNOWN_MALICIOUS_SHA256 = {
    # "known_bad_hash_here": "EICAR test file" ,
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".msi", ".jar", ".hta",
    ".docm", ".xlsm", ".pptm",  # macro-enabled Office files
}

# Maps expected content-type prefixes to their "normal" extensions --
# used to catch a mismatch like filename="invoice.pdf" but
# content_type="application/x-msdownload"
SAFE_EXTENSION_CONTENT_TYPES = {
    ".pdf": ["application/pdf"],
    ".doc": ["application/msword"],
    ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    ".xls": ["application/vnd.ms-excel"],
    ".xlsx": ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
    ".png": ["image/png"],
    ".jpg": ["image/jpeg"], ".jpeg": ["image/jpeg"],
    ".zip": ["application/zip", "application/x-zip-compressed"],
}


def analyze_attachment(attachment: dict) -> dict:
    filename = attachment.get("filename") or ""
    content_type = (attachment.get("content_type") or "").lower()
    sha256_hash = attachment.get("sha256")

    ext = os.path.splitext(filename)[1].lower()

    reasons = []
    risk_score = 0

    # 1. Known-malicious hash
    if sha256_hash and sha256_hash in KNOWN_MALICIOUS_SHA256:
        risk_score += 100
        reasons.append(f"Matches known malicious file: {KNOWN_MALICIOUS_SHA256[sha256_hash]}")

    # 2. Dangerous extension
    if ext in DANGEROUS_EXTENSIONS:
        risk_score += 40
        reasons.append(f"Potentially dangerous file type: {ext}")

    # 3. Extension/content-type mismatch
    expected_types = SAFE_EXTENSION_CONTENT_TYPES.get(ext)
    if expected_types and content_type and content_type not in expected_types:
        risk_score += 35
        reasons.append(
            f"File extension {ext} does not match declared content type "
            f"({content_type}) — possible disguised file"
        )

    # 4. Double extension trick (invoice.pdf.exe)
    name_parts = filename.lower().split(".")
    if len(name_parts) > 2 and f".{name_parts[-1]}" in DANGEROUS_EXTENSIONS:
        risk_score += 30
        reasons.append(f"Suspicious double extension: {filename}")

    risk_score = min(risk_score, 100)

    return {
        "filename": filename,
        "sha256": sha256_hash,
        "risk_score": risk_score,
        "suspicious": risk_score > 0,
        "reasons": reasons,
    }


def analyze_attachments(attachments: list[dict]) -> list[dict]:
    return [analyze_attachment(a) for a in attachments]