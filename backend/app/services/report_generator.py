"""
Generates a forensic PDF report from the full /analyze response.
Uses reportlab Platypus for structured, multi-section layout.
"""

from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)

styles = getSampleStyleSheet()

_TITLE = ParagraphStyle(
    "ReportTitle", parent=styles["Title"], fontSize=20, spaceAfter=6
)
_SECTION = ParagraphStyle(
    "SectionHeading", parent=styles["Heading2"], spaceBefore=16, spaceAfter=8,
    textColor=colors.HexColor("#1a1a2e")
)
_LABEL = ParagraphStyle(
    "Label", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=9
)
_BODY = ParagraphStyle(
    "Body", parent=styles["Normal"], fontSize=9, leading=13
)
_VERDICT_STYLES = {
    "CRITICAL": colors.HexColor("#8B0000"),
    "HIGH": colors.HexColor("#D9534F"),
    "SUSPICIOUS": colors.HexColor("#E0A800"),
    "SAFE": colors.HexColor("#2E7D32"),
}


def _kv_table(rows: list[tuple[str, str]], col_widths=(1.7 * inch, 4.8 * inch)) -> Table:
    """Renders a simple two-column key/value table."""
    data = [[Paragraph(f"<b>{k}</b>", _BODY), Paragraph(str(v) if v not in (None, "") else "—", _BODY)]
            for k, v in rows]
    t = Table(data, colWidths=list(col_widths))
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
    ]))
    return t


def _bullet_list(items: list[str]) -> list:
    if not items:
        return [Paragraph("None identified.", _BODY)]
    return [Paragraph(f"• {item}", _BODY) for item in items]


def generate_forensic_report(analysis: dict, output_path: str) -> str:
    """
    analysis: the full dict returned by /analyze
    output_path: where to write the PDF file
    Returns output_path for convenience.
    """
    buffer_or_path = output_path
    doc = SimpleDocTemplate(
        buffer_or_path, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
    )

    story = []

    email = analysis.get("email", {}) or {}
    threat = analysis.get("threat_analysis", {}) or {}
    auth = threat.get("auth_analysis", {}) or {}
    domain_intel = analysis.get("domain_intelligence", {}) or {}
    url_analysis = analysis.get("url_analysis", []) or []
    ip_intelligence = analysis.get("ip_intelligence", []) or []
    ip_locations = analysis.get("ip_locations", {}) or {}
    earliest_ip = analysis.get("earliest_reliable_ip") or {}
    relay_chain = analysis.get("relay_chain", []) or []
    attachment_analysis = analysis.get("attachment_analysis", []) or []
    lookalike_analysis = analysis.get("lookalike_analysis", []) or []
    identity_correlation = analysis.get("identity_correlation", {}) or {}

    # ===== HEADER =====
    story.append(Paragraph("Email Threat Forensic Report", _TITLE))
    story.append(Paragraph(
        f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} · "
        f"Case ID: {identity_correlation.get('case_id', 'N/A')}",
        _BODY
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc"), spaceBefore=10, spaceAfter=10))

    # ===== VERDICT BANNER =====
    classification = threat.get("classification", "UNKNOWN")
    fraud_score = threat.get("fraud_score", 0)
    verdict_color = _VERDICT_STYLES.get(classification, colors.grey)

    verdict_table = Table(
        [[Paragraph(f"<b>Classification: {classification}</b>", ParagraphStyle(
            "Verdict", parent=_BODY, textColor=colors.white, fontSize=13
        )),
          Paragraph(f"<b>Fraud Score: {fraud_score}/100</b>", ParagraphStyle(
              "VerdictScore", parent=_BODY, textColor=colors.white, fontSize=13, alignment=2
          ))]],
        colWidths=[3.5 * inch, 3.0 * inch]
    )
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (0, 0), 12),
        ("RIGHTPADDING", (-1, 0), (-1, 0), 12),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 14))

    # ===== EMAIL METADATA =====
    story.append(Paragraph("Email Metadata", _SECTION))
    story.append(_kv_table([
        ("From", email.get("from")),
        ("To", email.get("to")),
        ("Subject", email.get("subject")),
        ("Date", email.get("date")),
        ("Reply-To", email.get("reply_to")),
        ("Return-Path", email.get("return_path")),
    ]))
    story.append(Spacer(1, 8))

    # ===== AUTHENTICATION =====
    story.append(Paragraph("SPF / DKIM / DMARC Authentication", _SECTION))
    story.append(_kv_table([
        ("SPF", auth.get("spf") or "not evaluated"),
        ("DKIM", auth.get("dkim") or "not evaluated"),
        ("DMARC", auth.get("dmarc") or "not evaluated"),
        ("Verdict", auth.get("verdict", "—")),
    ]))
    story.extend(_bullet_list(auth.get("reasons", [])))
    story.append(Spacer(1, 8))

    # ===== RISK REASONS =====
    story.append(Paragraph("Risk Indicators Identified", _SECTION))
    story.extend(_bullet_list(threat.get("reasons", [])))
    story.append(Spacer(1, 8))

    # ===== IP TRACE / GEOLOCATION =====
    story.append(Paragraph("IP Trace & Geolocation", _SECTION))
    if earliest_ip:
        story.append(Paragraph(
            f"<b>Earliest reliable origin IP:</b> {earliest_ip.get('ip', 'N/A')} "
            f"(confidence: {earliest_ip.get('confidence', 'unverified')})",
            _BODY
        ))
        story.append(Spacer(1, 4))

    ip_rows = [["IP Address", "Country", "City", "VPN/Proxy/TOR", "Risk"]]
    intel_by_ip = {i.get("ip"): i for i in ip_intelligence}
    for ip, loc in ip_locations.items():
        intel = intel_by_ip.get(ip, {})
        flags = []
        if intel.get("vpn"): flags.append("VPN")
        if intel.get("proxy"): flags.append("Proxy")
        if intel.get("tor"): flags.append("TOR")
        if intel.get("hosting"): flags.append("Hosting")
        ip_rows.append([
            ip,
            loc.get("country") or "—",
            loc.get("city") or "—",
            ", ".join(flags) if flags else "None detected",
            str(intel.get("risk_score") or "—"),
        ])

    ip_table = Table(ip_rows, colWidths=[1.3 * inch, 1.1 * inch, 1.3 * inch, 1.6 * inch, 0.7 * inch])
    ip_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(ip_table)
    story.append(Spacer(1, 10))

    # ===== DOMAIN INTELLIGENCE =====
    story.append(Paragraph("Domain Intelligence", _SECTION))
    domain_rows = [["Domain", "Registrar", "Age (days)", "Risk Level"]]
    for domain, data in domain_intel.items():
        risk = data.get("risk", {})
        domain_rows.append([
            domain,
            data.get("registrar") or "—",
            str(data.get("domain_age_days") or "—"),
            risk.get("risk_level", "—"),
        ])
    domain_table = Table(domain_rows, colWidths=[2.0 * inch, 2.0 * inch, 1.0 * inch, 1.0 * inch])
    domain_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(domain_table)
    story.append(Spacer(1, 10))

    # ===== URL ANALYSIS =====
    if url_analysis:
        story.append(Paragraph("URL Analysis", _SECTION))
        for u in url_analysis:
            flag = "⚠ SUSPICIOUS" if u.get("suspicious") else "Clean"
            story.append(Paragraph(f"<b>{flag}</b> — {u.get('url')}", _BODY))
            if u.get("reasons"):
                story.extend(_bullet_list(u["reasons"]))
        story.append(Spacer(1, 8))

    # ===== ATTACHMENTS =====
    if attachment_analysis:
        story.append(Paragraph("Attachment Analysis", _SECTION))
        for att in attachment_analysis:
            flag = "⚠ SUSPICIOUS" if att.get("suspicious") else "Clean"
            story.append(Paragraph(
                f"<b>{flag}</b> — {att.get('filename', 'unknown')} "
                f"(SHA-256: {att.get('sha256', 'N/A')[:16]}...)",
                _BODY
            ))
            if att.get("reasons"):
                story.extend(_bullet_list(att["reasons"]))
        story.append(Spacer(1, 8))

    # ===== LOOKALIKE DOMAINS =====
    if lookalike_analysis:
        story.append(Paragraph("Lookalike / Typosquat Domains", _SECTION))
        for match in lookalike_analysis:
            story.append(Paragraph(
                f"<b>{match.get('domain')}</b> impersonates <b>{match.get('impersonated_brand')}</b> "
                f"— {match.get('reason')}",
                _BODY
            ))
        story.append(Spacer(1, 8))

    # ===== RELAY CHAIN =====
    if relay_chain:
        story.append(Paragraph("Relay Chain (Oldest → Newest)", _SECTION))
        relay_rows = [["Hop", "IP Address"]] + [
            [str(h.get("hop_index")), h.get("ip")] for h in relay_chain
        ]
        relay_table = Table(relay_rows, colWidths=[1.0 * inch, 3.0 * inch])
        relay_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(relay_table)
        story.append(Spacer(1, 8))

    # ===== IDENTITY CORRELATION =====
    story.append(Paragraph("Case Correlation", _SECTION))
    story.append(_kv_table([
        ("Case ID", identity_correlation.get("case_id")),
        ("Correlation Found", "Yes" if identity_correlation.get("correlation_found") else "No"),
    ]))
    related = identity_correlation.get("related_cases", [])
    if related:
        for case in related:
            story.append(Paragraph(
                f"Related to <b>{case.get('case_id')}</b> via shared domains: "
                f"{', '.join(case.get('common_domains', [])) or 'none'}",
                _BODY
            ))
    story.append(Spacer(1, 12))

    # ===== FOOTER DISCLAIMER =====
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report was generated automatically by an AI-assisted email threat detection "
        "system. Geolocation data reflects the ISP-registered location of routing infrastructure, "
        "not the physical location of the sender. IP trust confidence depends on correctly identifying "
        "the boundary between recipient-trusted mail infrastructure and unverified relay hops, and may "
        "be circumvented by a sufficiently sophisticated attacker. This report is intended to support, "
        "not replace, human forensic review.",
        ParagraphStyle("Disclaimer", parent=_BODY, fontSize=7, textColor=colors.grey)
    ))

    doc.build(story)
    return output_path