import { AlertTriangle, ExternalLink, ArrowLeft, Shield, Calendar, Globe } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const urls = [
  { url: "http://paypa1-secure.com/verify?token=abc123def456", domain: "paypa1-secure.com", risk: "malicious", detection: "Phishing redirect", status: "Blocked" },
  { url: "http://paypa1-secure.com/images/logo.png", domain: "paypa1-secure.com", risk: "suspicious", detection: "Suspicious domain", status: "Warning" },
  { url: "https://unsubscribe.paypa1-secure.com/opt-out", domain: "paypa1-secure.com", risk: "suspicious", detection: "Same malicious domain", status: "Warning" },
];

export default function UrlDomainIntelligence({ navigate }: Props) {
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24, marginTop: -8 }}>
        <button className="btn-ghost" onClick={() => navigate("result")} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          <ArrowLeft size={14} /> Back to Result
        </button>
      </div>

      {/* Summary stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 20 }}>
        {[
          { label: "URLs Found", value: "3", color: "#4a9eff" },
          { label: "Suspicious", value: "2", color: "#f5a623" },
          { label: "Malicious", value: "1", color: "#ff3b5c" },
        ].map(s => (
          <div key={s.label} className="card" style={{ padding: 20, display: "flex", alignItems: "center", gap: 16 }}>
            <div style={{ fontSize: 32, fontWeight: 800, color: s.color }}>{s.value}</div>
            <div style={{ fontSize: 14, color: "#5a6a88" }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* URL table */}
      <div className="card" style={{ padding: 0, overflow: "hidden", marginBottom: 20 }}>
        <div style={{ padding: "20px 24px 16px", borderBottom: "1px solid #252e4a" }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6" }}>URL Analysis</div>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #252e4a" }}>
              {["URL","Domain","Risk","Detection","Status"].map(h => (
                <th key={h} style={{ padding: "10px 20px", textAlign: "left", fontSize: 11, color: "#5a6a88", fontWeight: 600, letterSpacing: "0.04em" }}>{h.toUpperCase()}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {urls.map((row, i) => (
              <tr key={i} className="row-hover" style={{ borderBottom: i < urls.length - 1 ? "1px solid #c8cfe0" : "none" }}>
                <td style={{ padding: "12px 20px", maxWidth: 300 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span className="mono" style={{ fontSize: 11, color: "#8b96b8", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block", maxWidth: 280 }}>{row.url}</span>
                    <ExternalLink size={12} color="#64748b" style={{ flexShrink: 0 }} />
                  </div>
                </td>
                <td style={{ padding: "12px 20px" }}>
                  <span className="mono" style={{ fontSize: 12, color: "#ff7a4a" }}>{row.domain}</span>
                </td>
                <td style={{ padding: "12px 20px" }}>
                  <span className={row.risk === "malicious" ? "badge-critical" : "badge-high"} style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600, textTransform: "capitalize" }}>{row.risk}</span>
                </td>
                <td style={{ padding: "12px 20px", fontSize: 12, color: "#8b96b8" }}>{row.detection}</td>
                <td style={{ padding: "12px 20px" }}>
                  <span className={row.status === "Blocked" ? "badge-critical" : "badge-medium"} style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600 }}>{row.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Domain intelligence */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 16 }}>
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 20 }}>Domain Intelligence</div>
          <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 16px", background: "rgba(255,59,92,0.06)", borderRadius: 8, border: "1px solid rgba(255,59,92,0.2)", marginBottom: 20 }}>
            <Shield size={20} color="#ff3b5c" />
            <div>
              <span className="mono" style={{ fontSize: 15, fontWeight: 700, color: "#ff7a4a" }}>paypa1-secure.com</span>
              <span className="badge-critical" style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, marginLeft: 10 }}>HIGH RISK</span>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
            {[
              { label: "Domain Age", value: "12 days", icon: Calendar, flagged: true },
              { label: "Registrar", value: "Namecheap Inc.", icon: Globe, flagged: false },
              { label: "Nameservers", value: "ns1.dns-cluster.net", icon: Globe, flagged: false },
              { label: "MX Record", value: "mail.paypa1-secure.com", icon: Globe, flagged: true },
              { label: "SSL Issued", value: "8 days ago", icon: Shield, flagged: true },
              { label: "Similarity Score", value: "98% to paypal.com", icon: AlertTriangle, flagged: true },
            ].map(f => {
              const Icon = f.icon;
              return (
                <div key={f.label} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                  <div style={{ width: 28, height: 28, borderRadius: 6, background: "#151c2f", border: "1px solid #252e4a", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                    <Icon size={13} color="#64748b" />
                  </div>
                  <div>
                    <div style={{ fontSize: 11, color: "#5a6a88" }}>{f.label}</div>
                    <div className="mono" style={{ fontSize: 13, color: f.flagged ? "#ff7a4a" : "#c8d0e8", fontWeight: f.flagged ? 600 : 400 }}>{f.value}</div>
                  </div>
                </div>
              );
            })}
          </div>

          <div style={{ marginTop: 20, display: "flex", flexWrap: "wrap", gap: 8 }}>
            {["Lookalike domain","Newly registered","Suspicious hosting","SSL recently issued","No org validation"].map(tag => (
              <span key={tag} className="badge-critical" style={{ padding: "3px 10px", borderRadius: 4, fontSize: 11 }}>{tag}</span>
            ))}
          </div>
        </div>

        {/* Similarity visual */}
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 20 }}>Domain Similarity</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <div style={{ fontSize: 11, color: "#5a6a88", marginBottom: 8 }}>TRUSTED DOMAIN</div>
              <div style={{ padding: "14px 16px", background: "rgba(45,199,122,0.06)", border: "1px solid rgba(45,199,122,0.2)", borderRadius: 8 }}>
                <span className="mono" style={{ fontSize: 18, fontWeight: 700, color: "#2dc77a", letterSpacing: "0.04em" }}>paypal.com</span>
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 8 }}>
              <div style={{ height: 1, flex: 1, background: "#252e4a" }} />
              <span style={{ fontSize: 11, color: "#5a6a88", padding: "4px 10px", background: "#151c2f", borderRadius: 12, border: "1px solid #252e4a" }}>98% similar</span>
              <div style={{ height: 1, flex: 1, background: "#252e4a" }} />
            </div>

            <div>
              <div style={{ fontSize: 11, color: "#5a6a88", marginBottom: 8 }}>SUSPICIOUS DOMAIN</div>
              <div style={{ padding: "14px 16px", background: "rgba(255,59,92,0.06)", border: "1px solid rgba(255,59,92,0.2)", borderRadius: 8 }}>
                <span className="mono" style={{ fontSize: 18, fontWeight: 700, letterSpacing: "0.04em" }}>
                  <span style={{ color: "#8b96b8" }}>payp</span>
                  <span style={{ color: "#ff3b5c", textDecoration: "underline", textDecorationStyle: "wavy", textDecorationColor: "#ff3b5c" }}>a1</span>
                  <span style={{ color: "#8b96b8" }}>-secure.com</span>
                </span>
              </div>
            </div>

            <div style={{ padding: "12px 14px", background: "rgba(245,166,35,0.08)", border: "1px solid rgba(245,166,35,0.2)", borderRadius: 8 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: "#f5a623", marginBottom: 6 }}>Character Substitution Detected</div>
              <div style={{ fontSize: 12, color: "#8b96b8" }}>
                The letter <span className="mono" style={{ color: "#e8eaf6", background: "#151c2f", padding: "1px 6px", borderRadius: 4 }}>l</span> has been replaced with the digit <span className="mono" style={{ color: "#ff3b5c", background: "rgba(255,59,92,0.1)", padding: "1px 6px", borderRadius: 4 }}>1</span> — a common homoglyph substitution technique used in phishing campaigns.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
