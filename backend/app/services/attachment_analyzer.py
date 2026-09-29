"""
Attachment risk analysis.

Signals (all additive, capped at 100):
  1. Known-malicious SHA-256 (file or env-configured blocklist; plug in a
     threat-intel lookup in `lookup_hash`)
  2. Risky filename extension (executables, scripts, shortcuts, macros, ...)
  3. Filename spoofing (RTLO/zero-width chars, padding, trailing dots/spaces,
     decoy double extensions)
  4. Declared content-type inconsistencies
  5. True file type from magic bytes (only if `content` is provided)
  6. Deep inspection: ZIP/OOXML members, PDF active content, HTML forms/smuggling

Input is untrusted. Nothing is ever executed or extracted to disk.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import unicodedata
import zipfile
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ==========================================
# CONFIG
# ==========================================

MAX_HEAD_BYTES = 64 * 1024
MAX_PDF_SCAN_BYTES = 2 * 1024 * 1024
MAX_HTML_SCAN_BYTES = 256 * 1024
MAX_INSPECT_BYTES = 25 * 1024 * 1024     # skip deep archive inspection above this
MAX_ZIP_ENTRIES = 1000
ZIP_BOMB_TOTAL_BYTES = 1024 ** 3         # 1 GiB uncompressed
ZIP_BOMB_RATIO = 100

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


# ==========================================
# HASH BLOCKLIST
# ==========================================

def _load_blocklist() -> dict[str, str]:
    """Built-in EICAR entry plus optional file: '<sha256> [label]' per line."""
    entries = {EICAR_SHA256: "EICAR test file"}
    path = os.getenv("MALICIOUS_HASHES_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    digest, _, label = line.partition(" ")
                    digest = digest.lower()
                    if _SHA256_RE.fullmatch(digest):
                        entries[digest] = label.strip() or "known malicious file"
        except OSError as exc:
            logger.warning("Could not read MALICIOUS_HASHES_FILE: %s", exc)
    return entries


KNOWN_MALICIOUS_SHA256 = _load_blocklist()


def lookup_hash(sha256: str) -> Optional[str]:
    """Return a label if the hash is known-bad. Replace/extend with
    VirusTotal / MalwareBazaar (cache results, enforce timeouts)."""
    return KNOWN_MALICIOUS_SHA256.get(sha256)


# ==========================================
# EXTENSION RULES  (points, description)
# ==========================================

def _rules(points: int, label: str, *exts: str) -> dict[str, tuple[int, str]]:
    return {e: (points, label) for e in exts}


EXT_RULES: dict[str, tuple[int, str]] = {
    **_rules(50, "executable", ".exe", ".scr", ".com", ".pif", ".msi", ".msp", ".dll",
             ".cpl", ".jar", ".gadget", ".application", ".appx", ".msix", ".xll"),
    **_rules(45, "script", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
             ".wsc", ".sct", ".ps1", ".psm1", ".ps1xml", ".hta", ".reg", ".scf", ".inf"),
    **_rules(45, "shortcut/link", ".lnk", ".url", ".settingcontent-ms"),
    **_rules(40, "disk image", ".iso", ".img", ".vhd", ".vhdx"),
    **_rules(40, "macro-enabled Office", ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",
             ".potm", ".sldm", ".xlam", ".ppam"),
    **_rules(40, "compiled help", ".chm"),
    **_rules(30, "OneNote", ".one"),
    **_rules(25, "HTML/SVG (phishing page or smuggling)", ".html", ".htm", ".xhtml",
             ".shtml", ".svg"),
}

EXECUTABLE_EXTS = {e for e, (_, l) in EXT_RULES.items() if l == "executable"}
SCRIPT_EXTS = {e for e, (_, l) in EXT_RULES.items() if l == "script"}
MACRO_EXTS = {e for e, (_, l) in EXT_RULES.items() if l == "macro-enabled Office"}
HTML_EXTS = {".html", ".htm", ".xhtml", ".shtml", ".svg"}
ARCHIVE_MEMBER_BAD = set(EXT_RULES) - HTML_EXTS - {".one"}

DECOY_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
              ".csv", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".zip"}

# extension -> acceptable declared MIME types
EXT_CONTENT_TYPES: dict[str, set[str]] = {
    ".pdf": {"application/pdf", "application/x-pdf"},
    ".doc": {"application/msword"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ".xls": {"application/vnd.ms-excel"},
    ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    ".png": {"image/png"},
    ".jpg": {"image/jpeg", "image/jpg", "image/pjpeg"},
    ".jpeg": {"image/jpeg", "image/jpg", "image/pjpeg"},
    ".gif": {"image/gif"},
    ".zip": {"application/zip", "application/x-zip-compressed", "application/x-zip"},
}
GENERIC_TYPES = {"", "application/octet-stream", "binary/octet-stream",
                 "application/x-download", "application/force-download"}
DECLARED_EXECUTABLE_TYPES = {
    "application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
    "application/vnd.microsoft.portable-executable", "application/x-executable",
    "application/x-sh", "application/x-bat",
}

# extension -> acceptable *true* types (lenient on purpose: renamed docx/xlsx are common)
EXT_TRUE_TYPES: dict[str, set[str]] = {
    ".pdf": {"pdf"}, ".png": {"png"}, ".jpg": {"jpeg"}, ".jpeg": {"jpeg"}, ".gif": {"gif"},
    ".zip": {"zip"}, ".docx": {"zip"}, ".xlsx": {"zip"}, ".pptx": {"zip"},
    ".doc": {"ole", "rtf", "zip"}, ".xls": {"ole", "zip"}, ".ppt": {"ole", "zip"},
    ".rtf": {"rtf"}, ".rar": {"rar"}, ".7z": {"7z"},
}
EXEC_TRUE_TYPES = {"pe", "elf", "macho"}   # 'macho' also covers Java .class (0xCAFEBABE)


# ==========================================
# HELPERS
# ==========================================

_BIDI_ZW_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_PAD_RE = re.compile(r"[ \u00a0]{5,}")


def _clean(value: Any, limit: int = 120) -> str:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    text = _CTRL_RE.sub("", _BIDI_ZW_RE.sub("", text)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _normalize_filename(raw: Any) -> tuple[str, dict[str, bool]]:
    name = raw if isinstance(raw, str) else ""
    flags = {"hidden_chars": bool(_BIDI_ZW_RE.search(name)) or "\x00" in name}
    name = unicodedata.normalize("NFKC", name)
    name = _CTRL_RE.sub("", _BIDI_ZW_RE.sub("", name))
    name = re.split(r"[\\/]", name)[-1]
    flags["padded"] = bool(_PAD_RE.search(name))
    stripped = name.rstrip(" .")
    flags["trailing_junk"] = stripped != name
    return stripped, flags


def _extensions(name: str) -> list[str]:
    parts = name.lower().split(".")[1:]
    return [f".{p.strip()}" for p in parts if p.strip()]


def _sniff(head: bytes) -> str:
    """True file type from magic bytes."""
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                    b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe"):
        return "macho"
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    if head[:4] == b"L\x00\x00\x00" and head[4:20] == bytes.fromhex("0114020000000000c000000000000046"):
        return "lnk"
    if head.startswith(b"#!"):
        return "script"
    if len(head) > 0x8005 and head[0x8001:0x8006] == b"CD001":
        return "iso"
    lowered = head[:2048].lstrip().lower()
    if lowered.startswith(b"<!doctype html") or b"<html" in lowered:
        return "html"
    if b"<svg" in lowered:
        return "svg"
    return "unknown"


# ==========================================
# DEEP INSPECTION (never extracts or executes)
# ==========================================

def _inspect_zip(content: bytes, outer_ext: str) -> list[tuple[int, str]]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
        infos = zf.infolist()
    except Exception:
        return [(10, "Malformed or unreadable ZIP structure")]

    out: list[tuple[int, str]] = []
    if len(infos) > MAX_ZIP_ENTRIES:
        out.append((15, f"Archive has an unusually large number of entries ({len(infos)})"))
        infos = infos[:MAX_ZIP_ENTRIES]

    names = [i.filename.lower() for i in infos]
    if any(n.endswith("vbaproject.bin") for n in names) and outer_ext not in MACRO_EXTS:
        out.append((60, "Office file contains VBA macros despite a non-macro extension"))

    bad = next((n for n in names if os.path.splitext(n)[1] in ARCHIVE_MEMBER_BAD), None)
    if bad:
        out.append((40, f"Archive contains a risky file: {_clean(bad, 60)}"))

    if any(i.flag_bits & 0x1 for i in infos):
        out.append((25, "Password-protected archive (contents cannot be scanned)"))

    total = sum(i.file_size for i in infos)
    packed = max(sum(i.compress_size for i in infos), 1)
    if total > ZIP_BOMB_TOTAL_BYTES or (total > 100 * 1024 * 1024 and total / packed > ZIP_BOMB_RATIO):
        out.append((20, "Archive expands to an extreme size (possible zip bomb)"))
    return out


def _inspect_pdf(content: bytes) -> list[tuple[int, str]]:
    data = content[:MAX_PDF_SCAN_BYTES]
    found: list[tuple[int, str]] = []
    if re.search(rb"/Launch\b", data):
        found.append((35, "PDF contains a Launch action"))
    if re.search(rb"/(JavaScript|JS)\b", data):
        found.append((20, "PDF contains embedded JavaScript"))
    if re.search(rb"/EmbeddedFile\b", data):
        found.append((15, "PDF contains an embedded file"))
    if re.search(rb"/OpenAction\b", data):
        found.append((10, "PDF runs an action on open"))
    total = sum(p for p, _ in found)
    if total > 40:  # cap, keep reasons
        found = [(max(0, 40 - sum(p for p, _ in found[:i])) if False else p, r)
                 for i, (p, r) in enumerate(found)]
        scale = 40 / total
        found = [(int(p * scale), r) for p, r in found]
    return found


def _inspect_html(content: bytes) -> list[tuple[int, str]]:
    text = content[:MAX_HTML_SCAN_BYTES].decode("latin-1").lower()
    out = []
    if "<form" in text and re.search(r"type\s*=\s*[\"']?password", text):
        out.append((35, "HTML attachment contains a password form (credential harvesting)"))
    if re.search(r"atob\(|fromcharcode|new blob\(", text):
        out.append((25, "HTML attachment contains obfuscated/self-assembling script"))
    return out


# ==========================================
# ANALYSIS
# ==========================================

def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low" if score > 0 else "none"


def analyze_attachment(attachment: dict) -> dict:
    """Accepts: filename, content_type, sha256, and optionally `content` (bytes).
    Without `content`, only metadata signals run (see `content_inspected`)."""
    att = attachment if isinstance(attachment, dict) else {}
    signals: list[tuple[int, str]] = []

    def add(points: int, reason: str) -> None:
        signals.append((points, reason))

    # --- content + hash ---
    content = att.get("content")
    content = bytes(content) if isinstance(content, (bytes, bytearray)) else None
    sha256 = att.get("sha256")
    sha256 = sha256.strip().lower() if isinstance(sha256, str) else None
    if content is not None:
        sha256 = hashlib.sha256(content).hexdigest()   # never trust a supplied hash over real bytes
    if sha256 and not _SHA256_RE.fullmatch(sha256):
        sha256 = None

    label = lookup_hash(sha256) if sha256 else None
    if label:
        add(100, f"Matches known malicious file: {_clean(label, 60)}")

    # --- filename ---
    name, flags = _normalize_filename(att.get("filename"))
    exts = _extensions(name)
    ext = exts[-1] if exts else ""

    if flags["hidden_chars"]:
        add(45, "Filename contains hidden Unicode direction/zero-width characters (extension spoofing)")
    if flags["padded"]:
        add(20, "Filename padded with spaces to hide the real extension")
    if flags["trailing_junk"]:
        add(20, "Filename ends with dots/spaces (Windows strips them, hiding the real extension)")

    rule = EXT_RULES.get(ext)
    if rule:
        add(rule[0], f"Potentially dangerous file type ({rule[1]}): {ext}")
        if len(exts) >= 2 and exts[-2] in DECOY_EXTS and rule[0] >= 40:
            add(35, f"Decoy double extension: {_clean(name)}")

    # --- declared content-type ---
    declared = _clean(str(att.get("content_type") or "").split(";")[0].lower(), 80)
    inspected = content is not None
    if declared in DECLARED_EXECUTABLE_TYPES and ext not in EXECUTABLE_EXTS | SCRIPT_EXTS:
        add(50, f"Declared as executable content ({declared}) but named {ext or 'without extension'}")
    elif (ext in EXT_CONTENT_TYPES and declared not in GENERIC_TYPES
          and declared not in EXT_CONTENT_TYPES[ext]):
        add(10 if inspected else 20,
            f"Extension {ext} does not match declared content type ({declared})")

    # --- true type from bytes ---
    true_type = "not_inspected"
    if content is not None:
        true_type = _sniff(content[:MAX_HEAD_BYTES])
        if true_type in EXEC_TRUE_TYPES and ext not in EXECUTABLE_EXTS:
            add(90, f"Disguised executable: content is a native binary, not {ext or 'a document'}")
        elif true_type == "lnk" and ext != ".lnk":
            add(70, "Disguised Windows shortcut (.lnk) file")
        elif true_type == "iso" and ext not in {".iso", ".img"}:
            add(60, "Disguised disk image")
        elif true_type == "script" and ext not in SCRIPT_EXTS:
            add(25, "Content is a shell script but the filename suggests otherwise")
        elif (ext in EXT_TRUE_TYPES and true_type != "unknown"
              and true_type not in EXT_TRUE_TYPES[ext]):
            add(30, f"File content is {true_type}, which does not match extension {ext}")

        # --- deep inspection ---
        if len(content) <= MAX_INSPECT_BYTES:
            if true_type == "zip":
                signals.extend(_inspect_zip(content, ext))
            elif true_type == "pdf":
                signals.extend(_inspect_pdf(content))
            elif true_type in {"html", "svg"} or ext in HTML_EXTS:
                signals.extend(_inspect_html(content))

    signals.sort(key=lambda s: s[0], reverse=True)
    score = min(sum(p for p, _ in signals), 100)

    return {
        "filename": _clean(name),
        "sha256": sha256,
        "extension": ext,
        "detected_type": true_type,
        "content_inspected": inspected,
        "risk_score": score,
        "severity": _severity(score),
        "suspicious": score > 0,
        "reasons": [r for _, r in signals],
        "signals": [{"points": p, "reason": r} for p, r in signals],
    }


def analyze_attachments(attachments: Optional[list]) -> list[dict]:
    """One malformed attachment never breaks the batch, and fails closed."""
    results = []
    for att in attachments if isinstance(attachments, list) else []:
        try:
            results.append(analyze_attachment(att))
        except Exception:
            logger.exception("attachment analysis failed")
            fname = _clean(att.get("filename")) if isinstance(att, dict) else ""
            results.append({
                "filename": fname, "sha256": None, "extension": "",
                "detected_type": "error", "content_inspected": False,
                "risk_score": 20, "severity": "low", "suspicious": True,
                "reasons": ["Attachment could not be analyzed"],
                "signals": [{"points": 20, "reason": "Attachment could not be analyzed"}],
                "analysis_error": True,
            })
    return results