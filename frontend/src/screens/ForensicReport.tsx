import { Fragment } from "react";
import { ArrowLeft, Download, Printer, Share2, FileJson, CheckCircle, X } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

export default function ForensicReport({ navigate }: Props) {
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24, marginTop: -8 }}>
        <button className="btn-ghost" onClick={() => navigate("case-details")} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          <ArrowLeft size={14} /> Back to Case
        </button>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn-primary" style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
            <Download size={13} /> Download PDF
          </button>
          <button className="btn-secondary" style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
            <FileJson size={13} /> Export JSON
          </button>
          <button className="btn-secondary" style={{ padding: "9px 12px" }}><Printer size={13} /></button>
          <button className="btn-secondary" style={{ padding: "9px 12px" }}><Share2 size={13} /></button>
        </div>
      </div>

      {/* Report document */}
      <div style={{ maxWidth: 860, margin: "0 auto" }}>
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          {/* Report header */}
          <div style={{ padding: "36px 48px", background: "linear-gradient(135deg, #c8cfe0 0%, #eef0f7 100%)", borderBottom: "3px solid #4a7cff" }}>
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
                  <div style={{ width: 36, height: 36, borderRadius: 8, background: "linear-gradient(135deg,#4a7cff,#7a5cff)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                    <span style={{ fontSize: 16 }}>🛡️</span>
                  </div>
                  <div>
                    <div style={{ fontSize: 18, fontWeight: 700, color: "#e8eaf6" }}>MailTrace AI</div>
                    <div style={{ fontSize: 10, color: "#4a7cff", letterSpacing: "0.1em" }}>FORENSIC EMAIL ANALYSIS REPORT</div>
                  </div>
                </div>
                <div style={{ fontSize: 11, color: "#5a6a88", lineHeight: 2 }}>
                  <div>Generated: Sunday, 31 August 2026 · 09:20 UTC</div>
                  <div>Prepared by: Analyst 01</div>
                  <div>Organization: [Organization Name]</div>
                </div>
              </div>
              <div style={{ textAlign: "right" }}>
                <div className="mono" style={{ fontSize: 13, color: "#4a9eff" }}>CASE-2026-001284</div>
                <div style={{ fontSize: 22, fontWeight: 800, color: "#ff3b5c", marginTop: 8 }}>92 / 100</div>
                <div style={{ fontSize: 11, fontWeight: 700, color: "#ff3b5c" }}>HIGH RISK</div>
                <div style={{ marginTop: 10 }}>
                  <span className="badge-critical" style={{ padding: "3px 10px", borderRadius: 4, fontSize: 11, fontWeight: 700 }}>PHISHING / IMPERSONATION</span>
                </div>
              </div>
            </div>
          </div>

          {/* Report body */}
          <div style={{ padding: "36px 48px" }}>
            {/* Section helper */}
            {[
              {
                num: "1.", title: "Executive Summary",
                content: (
                  <p style={{ fontSize: 14, color: "#8b96b8", lineHeight: 1.8 }}>
                    Analysis of the submitted email (CASE-2026-001284) indicates a high-confidence phishing and impersonation attempt. The email originates from a fraudulent domain (paypa1-secure.com) registered 12 days prior and designed to impersonate PayPal. All three email authentication protocols (SPF, DKIM, DMARC) failed. The sending IP (185.220.101.47) is associated with 4 prior phishing campaigns. Recipient should not interact with any links or attachments. Immediate containment and user notification are recommended.
                  </p>
                )
              },
              {
                num: "2.", title: "Email Metadata",
                content: (
                  <div style={{ display: "grid", gridTemplateColumns: "180px 1fr", gap: 2 }}>
                    {[
                      ["From", "support@paypa1-secure.com"],
                      ["Reply-To", "security-alert@paypa1-secure.com"],
                      ["Subject", "Urgent: Verify Your Account"],
                      ["Date", "Sun, 31 Aug 2026 09:14:22 +0000"],
                      ["Message-ID", "<CA+xyz123@mail.paypa1-secure.com>"],
                      ["Source IP", "185.220.101.47"],
                    ].map(([k,v]) => (
                      <Fragment key={k}>
                        <span style={{ fontSize: 12, color: "#5a6a88", padding: "6px 0" }}>{k}</span>
                        <span className="mono" style={{ fontSize: 12, color: "#8b96b8", padding: "6px 0" }}>{v}</span>
                      </Fragment>
                    ))}
                  </div>
                )
              },
              {
                num: "3.", title: "Authentication Results",
                content: (
                  <div style={{ display: "flex", gap: 12 }}>
                    {[["SPF","FAIL","#ff3b5c"],["DKIM","FAIL","#ff3b5c"],["DMARC","FAIL","#ff3b5c"]].map(([label,result,color]) => (
                      <div key={label} style={{ flex: 1, padding: "14px 16px", background: "rgba(255,59,92,0.06)", border: "1px solid rgba(255,59,92,0.2)", borderRadius: 8, textAlign: "center" }}>
                        <X size={16} color={color as string} style={{ margin: "0 auto 8px" }} />
                        <div style={{ fontSize: 14, fontWeight: 700, color: "#e8eaf6" }}>{label}</div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: color as string }}>{result}</div>
                      </div>
                    ))}
                  </div>
                )
              },
              {
                num: "4.", title: "Threat Indicators",
                content: (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {[
                      { label: "Sender Spoofing", val: "DETECTED", fail: true },
                      { label: "Domain Lookalike (paypal.com → paypa1-secure.com)", val: "CONFIRMED", fail: true },
                      { label: "Domain Age", val: "12 days — newly registered", fail: true },
                      { label: "Urgency Language", val: "DETECTED in subject and body", fail: true },
                      { label: "Suspicious URL", val: "paypa1-secure.com/verify?token=... — MALICIOUS", fail: true },
                      { label: "Reply-To Mismatch", val: "DETECTED", fail: true },
                    ].map(ind => (
                      <div key={ind.label} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", background: "rgba(255,59,92,0.04)", borderRadius: 6, border: "1px solid rgba(255,59,92,0.15)" }}>
                        <X size={12} color="#ff3b5c" style={{ flexShrink: 0 }} />
                        <span style={{ fontSize: 13, color: "#8b96b8" }}>{ind.label}</span>
                        <span style={{ marginLeft: "auto", fontSize: 12, fontWeight: 600, color: "#ff3b5c" }}>{ind.val}</span>
                      </div>
                    ))}
                  </div>
                )
              },
              {
                num: "10.", title: "Recommended Actions",
                content: (
                  <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                    {[
                      "Block domain paypa1-secure.com at email gateway and DNS firewall",
                      "Block IP 185.220.101.47 and 194.165.16.4 at perimeter firewall",
                      "Notify recipient user and advise against clicking any links",
                      "Search mail logs for other emails from same domain or IP",
                      "Submit indicators to threat intelligence platform",
                      "File abuse report with domain registrar (Namecheap)",
                    ].map((action, i) => (
                      <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                        <span style={{ width: 20, height: 20, borderRadius: "50%", background: "rgba(74,124,255,0.1)", border: "1px solid rgba(74,124,255,0.25)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 10, fontWeight: 700, color: "#4a7cff", flexShrink: 0 }}>{i+1}</span>
                        <span style={{ fontSize: 13, color: "#8b96b8", lineHeight: 1.6 }}>{action}</span>
                      </div>
                    ))}
                  </div>
                )
              },
              {
                num: "12.", title: "Evidence Integrity",
                content: (
                  <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 16px", background: "rgba(45,199,122,0.06)", border: "1px solid rgba(45,199,122,0.2)", borderRadius: 8 }}>
                    <CheckCircle size={20} color="#2dc77a" />
                    <div>
                      <div style={{ fontSize: 14, fontWeight: 700, color: "#2dc77a" }}>Evidence Integrity Verified</div>
                      <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 4 }}>4 evidence items collected. SHA-256 hashes validated. Chain of custody intact.</div>
                    </div>
                  </div>
                )
              }
            ].map(section => (
              <div key={section.num} style={{ marginBottom: 32, paddingBottom: 32, borderBottom: "1px solid #252e4a" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                  <span className="mono" style={{ fontSize: 12, color: "#4a7cff" }}>{section.num}</span>
                  <h3 style={{ fontSize: 16, fontWeight: 700, color: "#e8eaf6", margin: 0 }}>{section.title}</h3>
                </div>
                {section.content}
              </div>
            ))}

            {/* Footer */}
            <div style={{ marginTop: 24, paddingTop: 20, borderTop: "1px solid #252e4a", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ fontSize: 11, color: "#4a5a78" }}>MailTrace AI · Threat Intelligence Platform · Report ID: RPT-2026-001284</div>
              <div style={{ fontSize: 11, color: "#4a5a78" }}>CONFIDENTIAL — RESTRICTED TO AUTHORIZED PERSONNEL</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
