import { ArrowLeft, ArrowDown } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const nodes = [
  { label: "Sender", host: "paypa1-secure.com", ip: "—", country: "—", time: "—", provider: "Unknown", risk: "suspicious", detail: "Claimed origin domain" },
  { label: "Mail Relay 1", host: "mail.paypa1-secure.com", ip: "185.220.101.47", country: "🇸🇬 Singapore", time: "09:14:20 UTC", provider: "Vultr Holdings LLC", risk: "critical", detail: "Earliest reliable node — VPS infrastructure" },
  { label: "Cloud Infrastructure", host: "relay.bulk-send.net", ip: "194.165.16.4", country: "🇳🇱 Netherlands", time: "09:14:21 UTC", provider: "Combahton GmbH", risk: "suspicious", detail: "Bulk email relay service" },
  { label: "Destination MX", host: "mx.organization.com", ip: "203.0.113.12", country: "🇮🇳 India", time: "09:14:22 UTC", provider: "Organization ISP", risk: "safe", detail: "Recipient mail server" },
];

const riskColor = (r: string) => r === "critical" ? "#ff3b5c" : r === "suspicious" ? "#f5a623" : "#2dc77a";
const riskLabel = (r: string) => r === "critical" ? "SUSPICIOUS" : r === "suspicious" ? "UNCERTAIN" : "TRUSTED";

export default function RelayPath({ navigate }: Props) {
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24, marginTop: -8 }}>
        <button className="btn-ghost" onClick={() => navigate("result")} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          <ArrowLeft size={14} /> Back to Result
        </button>
      </div>

      <p style={{ fontSize: 14, color: "#5a6a88", margin: "0 0 28px" }}>
        Email transmission path reconstructed from Received headers. Each hop represents one mail server that processed the message.
      </p>

      {/* Relay chain */}
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginBottom: 28 }}>
        {nodes.map((node, i) => {
          const color = riskColor(node.risk);
          return (
            <div key={i} style={{ width: "100%", maxWidth: 720 }}>
              <div className="card" style={{
                padding: 20,
                borderColor: `${color}30`,
                background: node.risk === "critical" ? "rgba(255,59,92,0.04)" : node.risk === "suspicious" ? "rgba(245,166,35,0.03)" : "#1a2035"
              }}>
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                    <div style={{ width: 10, height: 10, borderRadius: "50%", background: color, boxShadow: `0 0 8px ${color}60`, flexShrink: 0 }} />
                    <div>
                      <div style={{ fontSize: 11, fontWeight: 700, color: "#5a6a88", letterSpacing: "0.08em" }}>{node.label}</div>
                      <div className="mono" style={{ fontSize: 14, fontWeight: 600, color: "#e8eaf6", marginTop: 2 }}>{node.host}</div>
                      {node.ip !== "—" && <div className="mono" style={{ fontSize: 12, color: "#4a9eff", marginTop: 2 }}>{node.ip}</div>}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: 24, flexWrap: "wrap" }}>
                    {[
                      { label: "Country", value: node.country },
                      { label: "Timestamp", value: node.time },
                      { label: "Provider", value: node.provider },
                    ].map(f => (
                      <div key={f.label}>
                        <div style={{ fontSize: 10, color: "#5a6a88" }}>{f.label}</div>
                        <div className="mono" style={{ fontSize: 12, color: "#8b96b8", marginTop: 2 }}>{f.value}</div>
                      </div>
                    ))}
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <span style={{
                        fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 4,
                        background: `${color}15`, border: `1px solid ${color}35`, color
                      }}>{riskLabel(node.risk)}</span>
                    </div>
                  </div>
                </div>
                {node.detail && (
                  <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 10, paddingTop: 10, borderTop: "1px solid #252e4a" }}>
                    {node.detail}
                  </div>
                )}
              </div>

              {i < nodes.length - 1 && (
                <div style={{ display: "flex", justifyContent: "center", padding: "8px 0" }}>
                  <ArrowDown size={16} color="#94a3b8" />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Legend + finding */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 16 }}>
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 12 }}>Earliest Reliable Sending Node</div>
          <div style={{ padding: "16px 20px", background: "rgba(255,59,92,0.06)", borderRadius: 8, border: "1px solid rgba(255,59,92,0.25)" }}>
            <div className="mono" style={{ fontSize: 18, fontWeight: 700, color: "#ff7a4a", marginBottom: 4 }}>185.220.101.47</div>
            <div className="mono" style={{ fontSize: 13, color: "#8b96b8" }}>mail.paypa1-secure.com</div>
            <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 8 }}>Singapore · AS20473 · Vultr Holdings LLC</div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 12 }}>
              <div style={{ flex: 1, height: 4, background: "#1e2848", borderRadius: 2 }}>
                <div style={{ height: "100%", width: "87%", background: "#f5a623", borderRadius: 2 }} />
              </div>
              <span style={{ fontSize: 12, fontWeight: 700, color: "#f5a623" }}>87% confidence</span>
            </div>
          </div>
        </div>

        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#e8eaf6", marginBottom: 16 }}>Risk Legend</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {[
              { color: "#2dc77a", label: "TRUSTED", desc: "Verified organization server" },
              { color: "#f5a623", label: "UNCERTAIN", desc: "Unknown / unverified relay" },
              { color: "#ff3b5c", label: "SUSPICIOUS", desc: "High-risk or threat-linked infrastructure" },
            ].map(item => (
              <div key={item.label} style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <div style={{ width: 10, height: 10, borderRadius: "50%", background: item.color, flexShrink: 0 }} />
                <div>
                  <span style={{ fontSize: 11, fontWeight: 700, color: item.color }}>{item.label}</span>
                  <span style={{ fontSize: 11, color: "#5a6a88", marginLeft: 6 }}>{item.desc}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
