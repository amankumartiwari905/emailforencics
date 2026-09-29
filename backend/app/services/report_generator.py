"""
Generates a forensic PDF report from the full /analyze response.
Uses reportlab Platypus for structured, multi-section layout.

Production concerns addressed vs. a naive implementation:
- Every user-controlled string (subject, sender, filenames, domains --
  anything an attacker wrote) is XML-escaped before going into a
  Paragraph. reportlab's Paragraph interprets a small HTML-like markup
  subset, so an attacker-crafted subject line containing '<' or '&'
  can otherwise break layout or, in the worst case, be used to inject
  unintended markup into a report that's meant to be trustworthy
  evidence -- exactly the kind of thing a forensic report generator
  must not be fooled by.
- att.get("sha256", "N/A")[:16] in the original crashes when the key
  IS present but its value is None (dict.get's default only applies
  when the key is MISSING, not when it's None) -- a real bug hit by
  any attachment whose hash computation failed upstream.
- Report generation is wrapped so a failure in one optional section
  (e.g. malformed geolocation data) produces a report with that
  section noted as unavailable, rather than no report at all.
"""

import logging
from datetime import datetime, timezone
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether,
)

logger = logging.getLogger(__name__)

styles = getSampleStyleSheet()

_TITLE = ParagraphStyle(
    "ReportTitle", parent=styles["Title"], fontSize=20, spaceAfter=6
)
_SUBTITLE = ParagraphStyle(
    "ReportSubtitle", parent=styles["Normal"], fontSize=9,
    textColor=colors.HexColor("#555555"),
)
_SECTION = ParagraphStyle(
    "SectionHeading", parent=styles["Heading2"], fontSize=13,
    spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#1a1a2e"),
    keepWithNext=True,
)
_SUBSECTION = ParagraphStyle(
    "SubHeading", parent=styles["Heading3"], fontSize=10,
    spaceBefore=8, spaceAfter=4, textColor=colors.HexColor("#333333"),
    keepWithNext=True,
)
_BODY = ParagraphStyle(
    "Body", parent=styles["Normal"], fontSize=9, leading=13,
)
_BULLET = ParagraphStyle(
    "Bullet", parent=_BODY, leftIndent=12, spaceAfter=2,
)
_DISCLAIMER = ParagraphStyle(
    "Disclaimer", parent=_BODY, fontSize=7, textColor=colors.HexColor("#777777"),
)
_EMPTY_STATE = ParagraphStyle(
    "EmptyState", parent=_BODY, textColor=colors.HexColor("#888888"), fontStyle="italic",
)

_VERDICT_STYLES = {
    "CRITICAL": colors.HexColor("#8B0000"),
    "HIGH": colors.HexColor("#D9534F"),
    "SUSPICIOUS": colors.HexColor("#E0A800"),
    "SAFE": colors.HexColor("#2E7D32"),
}
_TABLE_HEADER_STYLE = [
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTSIZE", (0, 0), (-1, -1), 8),
    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("TOPPADDING", (0, 0), (-1, -1), 5),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
]


def _esc(value) -> str:
    """
    Escapes a value for safe inclusion in a Paragraph, which interprets
    a small HTML-like markup subset. ANY string that ultimately
    originates from the email being analyzed (subject, sender,
    filenames, domains, URLs, header text) MUST pass through this
    before being embedded in report markup -- otherwise a crafted
    subject line like "Report <b>FORGED: SAFE</b>" could visually
    inject false content into what's meant to be trustworthy evidence.
    """
    if value is None:
        return "—"
    return _xml_escape(str(value))


def _safe_get(d: dict, key: str, default=None):
    """dict.get() but treats an explicitly-None value the same as a
    missing key -- fixes the att.get('sha256', 'N/A')[:16] class of
    bug, where .get()'s default only applies to missing keys, not to
    keys present with value None."""
    value = d.get(key)
    return value if value is not None else default


def _short_hash(hash_value: str | None, length: int = 16) -> str:
    if not hash_value:
        return "not available"
    return f"{hash_value[:length]}…" if len(hash_value) > length else hash_value


def _kv_table(rows: list[tuple[str, object]], col_widths=(1.7 * inch, 4.8 * inch)) -> Table:
    data = [
        [Paragraph(f"<b>{_esc(k)}</b>", _BODY), Paragraph(_esc(v) if v not in (None, "") else "—", _BODY)]
        for k, v in rows
    ]
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
        return [Paragraph("None identified.", _EMPTY_STATE)]
    return [Paragraph(f"• {_esc(item)}", _BULLET) for item in items]


def _empty_state(message: str) -> Paragraph:
    return Paragraph(message, _EMPTY_STATE)


def _section(story: list, title: str, body_builder) -> None:
    """
    Renders one report section in isolation: if body_builder() raises,
    the section is replaced with a visible "data unavailable" note
    instead of crashing the entire report generation. A partial
    forensic report with one broken section is far more useful than
    no report at all.
    """
    story.append(Paragraph(title, _SECTION))
    try:
        content = body_builder()
        if content:
            story.extend(content if isinstance(content, list) else [content])
    except Exception:
        logger.exception("Report section failed to render: %s", title)
        story.append(_empty_state(f"This section could not be generated due to an internal error."))
    story.append(Spacer(1, 8))


def _page_footer(canvas, doc):
    """Draws a page number + generation timestamp on every page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#999999"))
    footer_text = f"Page {doc.page}"
    canvas.drawRightString(letter[0] - 0.7 * inch, 0.4 * inch, footer_text)
    canvas.drawString(
        0.7 * inch, 0.4 * inch,
        "CONFIDENTIAL — Forensic Analysis Report",
    )
    canvas.restoreState()


def generate_forensic_report(analysis: dict, output_path: str) -> str:
    """
    analysis: the full dict returned by /analyze
    output_path: where to write the PDF file
    Returns output_path for convenience.

    Every section is rendered defensively -- malformed or missing data
    in any one part of `analysis` degrades that section only, never
    aborts the whole report.
    """
    if not isinstance(analysis, dict):
        raise ValueError("analysis must be a dict")

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.7 * inch,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
    )

    story = []

    email = analysis.get("email") or {}
    threat = analysis.get("threat_analysis") or {}
    auth = threat.get("auth_analysis") or {}
    nlp = threat.get("nlp_analysis") or analysis.get("nlp_analysis") or {}
    ml_phishing = analysis.get("ml_phishing_analysis") or {}
    domain_intel = analysis.get("domain_intelligence") or {}
    url_analysis = analysis.get("url_analysis") or []
    ip_intelligence = analysis.get("ip_intelligence") or []
    ip_locations = analysis.get("ip_locations") or {}
    earliest_ip = analysis.get("earliest_reliable_ip") or {}
    relay_chain = analysis.get("relay_chain") or []
    trace_comparison = analysis.get("trace_comparison") or {}
    attachment_analysis = analysis.get("attachment_analysis") or []
    lookalike_analysis = analysis.get("lookalike_analysis") or []
    identity_correlation = analysis.get("identity_correlation") or {}

    # ===== HEADER =====
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    case_id = _esc(identity_correlation.get("case_id") or "N/A")

    story.append(Paragraph("Email Threat Forensic Report", _TITLE))
    story.append(Paragraph(f"Generated {generated_at} · Case ID: {case_id}", _SUBTITLE))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc"),
                             spaceBefore=10, spaceAfter=10))

    # ===== VERDICT BANNER =====
    classification = str(threat.get("classification") or "UNKNOWN")
    fraud_score = threat.get("fraud_score")
    fraud_score_display = f"{fraud_score}/100" if isinstance(fraud_score, (int, float)) else "N/A"
    verdict_color = _VERDICT_STYLES.get(classification, colors.grey)

    verdict_table = Table(
        [[
            Paragraph(f"<b>Classification: {_esc(classification)}</b>",
                      ParagraphStyle("Verdict", parent=_BODY, textColor=colors.white, fontSize=13)),
            Paragraph(f"<b>Fraud Score: {fraud_score_display}</b>",
                      ParagraphStyle("VerdictScore", parent=_BODY, textColor=colors.white,
                                     fontSize=13, alignment=2)),
        ]],
        colWidths=[3.5 * inch, 3.0 * inch],
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

    # ===== EXECUTIVE SUMMARY =====
    def _summary():
        parts = []
        nlp_tier = nlp.get("nlp_signal_tier")
        ml_pred = ml_phishing.get("prediction")
        auth_verdict = auth.get("verdict")

        summary_bits = []
        if auth_verdict:
            summary_bits.append(f"authentication check: <b>{_esc(auth_verdict)}</b>")
        if nlp_tier:
            summary_bits.append(f"language analysis: <b>{_esc(nlp_tier)}</b>")
        if ml_pred:
            summary_bits.append(f"ML classifier: <b>{_esc(ml_pred)}</b>")
        if trace_comparison.get("mismatch_detected"):
            summary_bits.append("<b>origin trace mismatch detected</b> between naive and reasoned analysis")

        if summary_bits:
            parts.append(Paragraph(
                "This email was classified as <b>" + _esc(classification) + "</b> "
                "based on the following signals: " + "; ".join(summary_bits) + ".",
                _BODY,
            ))
        else:
            parts.append(_empty_state("No summary signals available."))
        return parts

    _section(story, "Executive Summary", _summary)

    # ===== EMAIL METADATA =====
    def _metadata():
        return [_kv_table([
            ("From", email.get("from")),
            ("To", email.get("to")),
            ("Subject", email.get("subject")),
            ("Date", email.get("date")),
            ("Reply-To", email.get("reply_to")),
            ("Return-Path", email.get("return_path")),
        ])]

    _section(story, "Email Metadata", _metadata)

    # ===== AUTHENTICATION =====
    def _authentication():
        content = [_kv_table([
            ("SPF", auth.get("spf") if not auth.get("spf_absent") else "not evaluated"),
            ("DKIM", auth.get("dkim") if not auth.get("dkim_absent") else "not evaluated"),
            ("DMARC", auth.get("dmarc") if not auth.get("dmarc_absent") else "not evaluated"),
            ("Verdict", auth.get("verdict")),
        ])]
        content.append(Spacer(1, 4))
        content.extend(_bullet_list(auth.get("reasons") or []))
        return content

    _section(story, "SPF / DKIM / DMARC Authentication", _authentication)

    # ===== LANGUAGE / SOCIAL ENGINEERING ANALYSIS =====
    if nlp or ml_phishing:
        def _language_analysis():
            content = []
            rows = []
            if nlp:
                rows.append(("Pattern-based signal tier", nlp.get("nlp_signal_tier")))
                rows.append(("Pattern score", nlp.get("threat_score")))
            if ml_phishing:
                rows.append(("ML classifier prediction", ml_phishing.get("prediction")))
                prob = ml_phishing.get("phishing_probability")
                if isinstance(prob, (int, float)):
                    rows.append(("ML phishing probability", f"{prob * 100:.1f}%"))
            if rows:
                content.append(_kv_table(rows))
                content.append(Spacer(1, 4))
            tactics = nlp.get("tactics") or []
            if tactics:
                content.append(Paragraph("<b>Tactics identified:</b>", _SUBSECTION))
                content.extend(_bullet_list(tactics))
            return content

        _section(story, "Language & Social Engineering Analysis", _language_analysis)

    # ===== RISK INDICATORS =====
    def _risk_indicators():
        return _bullet_list(threat.get("reasons") or [])

    _section(story, "Risk Indicators Identified", _risk_indicators)

    # ===== ORIGIN TRACE =====
    def _origin_trace():
        content = []

        if earliest_ip:
            content.append(Paragraph(
                f"<b>Earliest reliable origin IP:</b> {_esc(earliest_ip.get('ip'))} "
                f"(confidence: {_esc(earliest_ip.get('confidence', 'unverified'))})",
                _BODY,
            ))
        else:
            content.append(_empty_state(
                "No reliable public origin IP could be identified from the relay chain."
            ))
        content.append(Spacer(1, 4))

        if trace_comparison.get("mismatch_detected"):
            content.append(Paragraph(
                "<b>⚠ Trace mismatch detected:</b> " + _esc(trace_comparison.get("explanation", "")),
                ParagraphStyle("MismatchWarning", parent=_BODY, textColor=colors.HexColor("#D9534F")),
            ))
            content.append(Spacer(1, 4))
        elif trace_comparison.get("explanation"):
            content.append(Paragraph(_esc(trace_comparison["explanation"]), _BODY))
            content.append(Spacer(1, 4))

        if not ip_locations:
            content.append(_empty_state("No IP addresses were extracted from this email's headers."))
            return content

        ip_rows = [["IP Address", "Country", "City", "VPN/Proxy/TOR", "Risk"]]
        intel_by_ip = {i.get("ip"): i for i in ip_intelligence if i.get("ip")}
        for ip, loc in ip_locations.items():
            intel = intel_by_ip.get(ip, {})
            flags = [name for name, present in (
                ("VPN", intel.get("vpn")), ("Proxy", intel.get("proxy")),
                ("TOR", intel.get("tor")), ("Hosting", intel.get("hosting")),
            ) if present]
            ip_rows.append([
                _esc(ip), _esc(loc.get("country") or "—"), _esc(loc.get("city") or "—"),
                ", ".join(flags) if flags else "None detected",
                _esc(intel.get("risk_score")) if intel.get("risk_score") is not None else "—",
            ])

        ip_table = Table(ip_rows, colWidths=[1.3 * inch, 1.1 * inch, 1.3 * inch, 1.6 * inch, 0.7 * inch])
        ip_table.setStyle(TableStyle(_TABLE_HEADER_STYLE))
        content.append(ip_table)
        return content

    _section(story, "IP Trace & Geolocation", _origin_trace)

    # ===== DOMAIN INTELLIGENCE =====
    def _domain_intelligence():
        if not domain_intel:
            return [_empty_state("No sender-related domains were identified for analysis.")]

        domain_rows = [["Domain", "Registrar", "Age (days)", "Risk Level"]]
        for domain, data in domain_intel.items():
            risk = data.get("risk") or {}
            domain_rows.append([
                _esc(domain),
                _esc(data.get("registrar") or "—"),
                _esc(data.get("domain_age_days")) if data.get("domain_age_days") is not None else "—",
                _esc(risk.get("risk_level") or "—"),
            ])
        table = Table(domain_rows, colWidths=[2.0 * inch, 2.0 * inch, 1.0 * inch, 1.0 * inch])
        table.setStyle(TableStyle(_TABLE_HEADER_STYLE))
        return [table]

    _section(story, "Domain Intelligence", _domain_intelligence)

    # ===== URL ANALYSIS =====
    if url_analysis:
        def _url_section():
            content = []
            for u in url_analysis:
                flag = "⚠ SUSPICIOUS" if u.get("suspicious") else "Clean"
                content.append(KeepTogether([
                    Paragraph(f"<b>{flag}</b> — {_esc(u.get('url'))}", _BODY),
                    *(_bullet_list(u.get("reasons") or []) if u.get("reasons") else []),
                    Spacer(1, 4),
                ]))
            return content

        _section(story, "URL Analysis", _url_section)

    # ===== ATTACHMENTS =====
    if attachment_analysis:
        def _attachment_section():
            content = []
            for att in attachment_analysis:
                flag = "⚠ SUSPICIOUS" if att.get("suspicious") else "Clean"
                filename = _esc(_safe_get(att, "filename", "unknown"))
                hash_display = _short_hash(_safe_get(att, "sha256"))
                content.append(KeepTogether([
                    Paragraph(f"<b>{flag}</b> — {filename} (SHA-256: {hash_display})", _BODY),
                    *(_bullet_list(att.get("reasons") or []) if att.get("reasons") else []),
                    Spacer(1, 4),
                ]))
            return content

        _section(story, "Attachment Analysis", _attachment_section)

    # ===== LOOKALIKE DOMAINS =====
    if lookalike_analysis:
        def _lookalike_section():
            content = []
            for match in lookalike_analysis:
                content.append(Paragraph(
                    f"<b>{_esc(match.get('domain'))}</b> impersonates "
                    f"<b>{_esc(match.get('impersonated_brand'))}</b> — {_esc(match.get('reason'))}",
                    _BODY,
                ))
            return content

        _section(story, "Lookalike / Typosquat Domains", _lookalike_section)

    # ===== RELAY CHAIN =====
    if relay_chain:
        def _relay_section():
            relay_rows = [["Hop", "IP Address"]] + [
                [_esc(h.get("hop_index")), _esc(h.get("ip"))] for h in relay_chain
            ]
            table = Table(relay_rows, colWidths=[1.0 * inch, 3.0 * inch])
            table.setStyle(TableStyle(_TABLE_HEADER_STYLE))
            return [table]

        _section(story, "Relay Chain (Oldest → Newest)", _relay_section)

    # ===== IDENTITY CORRELATION =====
    def _correlation_section():
        content = [_kv_table([
            ("Case ID", identity_correlation.get("case_id")),
            ("Correlation Found", "Yes" if identity_correlation.get("correlation_found") else "No"),
        ])]
        related = identity_correlation.get("related_cases") or []
        if related:
            content.append(Spacer(1, 4))
            for case in related:
                domains = ", ".join(case.get("common_domains") or []) or "none"
                content.append(Paragraph(
                    f"Related to <b>{_esc(case.get('case_id'))}</b> via shared domains: {_esc(domains)}",
                    _BODY,
                ))
        return content

    _section(story, "Case Correlation", _correlation_section)

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
        _DISCLAIMER,
    ))

    try:
        doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
    except Exception:
        logger.exception("PDF generation failed for case %s", case_id)
        raise

    return output_path