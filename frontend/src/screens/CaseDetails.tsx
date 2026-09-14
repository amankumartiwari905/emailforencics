import { useState } from "react";
import { ArrowLeft, Shield, Clock, CheckCircle, Plus, FileText, Download } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const tabs = ["Overview", "Emails", "Indicators", "Infrastructure", "Timeline", "Evidence", "Reports"];

const timeline = [
  { time: "08:42", label: "Email received by target user", analyst: "System" },
  { time: "08:45", label: "High-risk threat detected (score: 92/100)", analyst: "AI Engine" },
  { time: "08:47", label: "Case created and assigned to Analyst 01", analyst: "System" },
  { time: "08:51", label: "Domain paypa1-secure.com investigated — 12 days old", analyst: "Analyst 01" },
  { time: "08:56", label: "IP 185.220.101.47 correlated with known campaign", analyst: "Analyst 01" },
  { time: "09:12", label: "Evidence EV-001 and EV-002 collected", analyst: "Analyst 01" },
  { time: "09:20", label: "Report draft generated", analyst: "Analyst 01" },
];

const evidence = [
  { id: "EV-001", type: "Email", source: "Uploaded .eml", hash: "sha256:3a7fc1b4e8d09…", collected: "Today 08:47", by: "Analyst 01", integrity: "Verified" },
  { id: "EV-002", type: "Domain WHOIS", source: "WHOIS lookup", hash: "sha256:9f4a2c6b1d83…", collected: "Today 08:51", by: "Analyst 01", integrity: "Verified" },
  { id: "EV-003", type: "IP Lookup", source: "Geo API", hash: "sha256:2e8b5f7c4a19…", collected: "Today 08:56", by: "Analyst 01", integrity: "Verified" },
  { id: "EV-004", type: "URL Scan", source: "URL intelligence API", hash: "sha256:7d3c9a1f6e42…", collected: "Today 09:05", by: "Analyst 01", integrity: "Verified" },
];

export default function CaseDetails({ navigate }: Props) {
  const [activeTab, setActiveTab] = useState("Overview");

  return (
    <div>
      {/* Back + header */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20, marginTop: -8 }}>
        <button className="btn-ghost" onClick={() => navigate("cases")} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          <ArrowLeft size={14} /> Cases
        </button>
      </div>

      {/* Case header */}
      <div className="card" style={{ padding: 24, marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <span className="mono" style={{ fontSize: 13, color: "#4a9eff" }}>CASE-2026-001284</span>
              <span className="badge-critical" style={{ padding: "2px 10px", borderRadius: 4, fontSize: 11, fontWeight: 700 }}>CRITICAL</span>
              <span className="badge-investigating" style={{ padding: "2px 10px", borderRadius: 4, fontSize: 11, fontWeight: 600 }}>INVESTIGATING</span>
            </div>
            <h2 style={{ fontSize: 20, fontWeight: 700, color: "#e8eaf6", margin: "0 0 8px" }}>Payment Fraud Campaign</h2>
            <div style={{ fontSize: 13, color: "#5a6a88" }}>Assigned to <span style={{ color: "#8b96b8" }}>Analyst 01</span> · Created Today 08:42</div>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn-secondary" style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }} onClick={() => navigate("forensic-report")}>
              <Download size={13} /> Export Report
            </button>
            <button className="btn-primary" style={{ fontSize: 13 }}>Update Status</button>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 2, marginBottom: 20, borderBottom: "1px solid #252e4a", paddingBottom: 0 }}>
        {tabs.map(t => (
          <button
            key={t}
            onClick={() => setActiveTab(t)}
            style={{
              padding: "9px 16px", border: "none", cursor: "pointer", fontSize: 13,
              background: "transparent", fontWeight: activeTab === t ? 600 : 400,
              color: activeTab === t ? "#111827" : "#64748b",
              borderBottom: activeTab === t ? "2px solid #4a7cff" : "2px solid transparent",
              transition: "all 0.15s"
            }}
          >{t}</button>
        ))}
      </div>

      {activeTab === "Overview" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 16 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 12 }}>Case Summary</div>
              <p style={{ fontSize: 14, color: "#8b96b8", lineHeight: 1.7, margin: 0 }}>
                A targeted phishing campaign impersonating PayPal was detected. The threat actor registered a lookalike domain (paypa1-secure.com) 12 days before the attack. The campaign employs urgency language and credential harvesting techniques. The sending infrastructure has been linked to 4 prior campaigns.
              </p>
            </div>
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 16 }}>Related Indicators</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
                {["paypa1-secure.com","185.220.101.47","194.165.16.4","security-alert@paypa1-secure.com","mailer@mx.paypa1-secure.com"].map(ind => (
                  <span key={ind} className="mono" style={{ fontSize: 12, padding: "4px 10px", background: "#151c2f", border: "1px solid #252e4a", borderRadius: 6, color: "#8b96b8" }}>{ind}</span>
                ))}
              </div>
            </div>
          </div>

          <div className="card" style={{ padding: 24, height: "fit-content" }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: "#5a6a88", letterSpacing: "0.06em", marginBottom: 16 }}>CASE METRICS</div>
            {[
              { label: "Threat Score", value: "92 / 100", color: "#ff3b5c" },
              { label: "Emails Linked", value: "3", color: "#e8eaf6" },
              { label: "Domains", value: "1 malicious", color: "#ff7a4a" },
              { label: "IPs", value: "2 suspicious", color: "#f5a623" },
              { label: "Evidence Items", value: "4", color: "#2dc77a" },
            ].map(m => (
              <div key={m.label} style={{ display: "flex", justifyContent: "space-between", padding: "10px 0", borderBottom: "1px solid #252e4a" }}>
                <span style={{ fontSize: 13, color: "#5a6a88" }}>{m.label}</span>
                <span style={{ fontSize: 13, fontWeight: 700, color: m.color }}>{m.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "Timeline" && (
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 20 }}>Investigation Timeline</div>
          <div style={{ display: "flex", flexDirection: "column" }}>
            {timeline.map((item, i) => (
              <div key={i} style={{ display: "flex", gap: 16 }}>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                  <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#4a7cff", flexShrink: 0, marginTop: 4 }} />
                  {i < timeline.length - 1 && <div style={{ width: 1, flex: 1, background: "#252e4a", marginTop: 4 }} />}
                </div>
                <div style={{ paddingBottom: i < timeline.length - 1 ? 20 : 0, display: "flex", gap: 16, flex: 1 }}>
                  <span className="mono" style={{ fontSize: 12, color: "#4a7cff", flexShrink: 0, width: 50 }}>{item.time}</span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 13, color: "#e8eaf6" }}>{item.label}</div>
                    <div style={{ fontSize: 11, color: "#4a5a78", marginTop: 2 }}>{item.analyst}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === "Evidence" && (
        <div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 16 }}>
            <button className="btn-primary" style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
              <Plus size={14} /> Add Evidence
            </button>
          </div>
          <div style={{ marginBottom: 16, padding: "12px 16px", background: "rgba(45,199,122,0.06)", border: "1px solid rgba(45,199,122,0.2)", borderRadius: 8, display: "flex", alignItems: "center", gap: 10 }}>
            <CheckCircle size={14} color="#2dc77a" />
            <span style={{ fontSize: 13, fontWeight: 600, color: "#2dc77a" }}>Evidence Integrity: VERIFIED</span>
            <span style={{ fontSize: 12, color: "#5a6a88", marginLeft: 4 }}>All 4 items have valid SHA-256 hashes and intact chain of custody</span>
          </div>
          <div className="card" style={{ padding: 0, overflow: "hidden" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid #252e4a" }}>
                  {["Evidence ID","Type","Source","Hash (SHA-256)","Collected","Collected By","Integrity"].map(h => (
                    <th key={h} style={{ padding: "11px 16px", textAlign: "left", fontSize: 11, color: "#5a6a88", fontWeight: 600, letterSpacing: "0.04em" }}>{h.toUpperCase()}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {evidence.map((ev, i) => (
                  <tr key={i} className="row-hover" style={{ borderBottom: i < evidence.length - 1 ? "1px solid #c8cfe0" : "none" }}>
                    <td style={{ padding: "12px 16px" }}><span className="mono" style={{ fontSize: 12, color: "#4a9eff" }}>{ev.id}</span></td>
                    <td style={{ padding: "12px 16px", fontSize: 13, color: "#8b96b8" }}>{ev.type}</td>
                    <td style={{ padding: "12px 16px", fontSize: 12, color: "#8b96b8" }}>{ev.source}</td>
                    <td style={{ padding: "12px 16px" }}><span className="mono" style={{ fontSize: 11, color: "#5a6a88" }}>{ev.hash}</span></td>
                    <td style={{ padding: "12px 16px", fontSize: 12, color: "#5a6a88" }}>{ev.collected}</td>
                    <td style={{ padding: "12px 16px", fontSize: 12, color: "#8b96b8" }}>{ev.by}</td>
                    <td style={{ padding: "12px 16px" }}>
                      <span className="badge-safe" style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600, display: "flex", alignItems: "center", gap: 4, width: "fit-content" }}>
                        <CheckCircle size={10} /> {ev.integrity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === "Reports" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {[
            { name: "Forensic Analysis Report — CASE-2026-001284", date: "Today 09:20", analyst: "Analyst 01", status: "Draft" },
          ].map((rep, i) => (
            <div key={i} className="card" style={{ padding: 20, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                <div style={{ width: 40, height: 40, borderRadius: 8, background: "rgba(74,124,255,0.1)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <FileText size={18} color="#4a7cff" />
                </div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600, color: "#e8eaf6" }}>{rep.name}</div>
                  <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 4 }}>{rep.date} · {rep.analyst}</div>
                </div>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <span className="badge-medium" style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600 }}>{rep.status}</span>
                <button className="btn-secondary" style={{ fontSize: 13, padding: "7px 16px" }} onClick={() => navigate("forensic-report")}>View Report</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {!["Overview","Timeline","Evidence","Reports"].includes(activeTab) && (
        <div style={{ textAlign: "center", padding: "60px 40px" }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: "#5a6a88", marginBottom: 8 }}>No {activeTab.toLowerCase()} data yet</div>
          <div style={{ fontSize: 13, color: "#4a5a78" }}>Add items to this investigation to populate this view</div>
        </div>
      )}
    </div>
  );
}
