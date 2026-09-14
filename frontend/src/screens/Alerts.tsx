import { useState } from "react";
import { Bell, CheckCircle, X, AlertTriangle, Info } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const allAlerts = [
  { id: 1, severity: "critical", title: "Possible BEC attempt detected", source: "AI Detection Engine", risk: 94, time: "4 min ago", status: "New", desc: "Email from ceo@company-financials.org requesting urgent wire transfer. Multiple BEC indicators detected." },
  { id: 2, severity: "high", title: "Lookalike domain registered", source: "Domain Monitor", risk: 86, time: "18 min ago", status: "New", desc: "New domain amaz0n-support.com registered 3 days ago. 97% similarity to amazon.com." },
  { id: 3, severity: "high", title: "DMARC failure — sustained campaign", source: "Auth Analysis", risk: 78, time: "1h ago", status: "Acknowledged", desc: "19 emails from the same sending domain failed DMARC validation in the past 6 hours." },
  { id: 4, severity: "high", title: "Malicious URL in email body", source: "URL Intelligence", risk: 91, time: "1h 15m ago", status: "New", desc: "URL http://credential-portal.xyz/login detected in email. Domain is 2 days old and flagged by 4 threat feeds." },
  { id: 5, severity: "medium", title: "Suspicious external URL detected", source: "URL Scanner", risk: 62, time: "2h ago", status: "Resolved", desc: "Link to an uncommon redirect service found in email to finance team." },
  { id: 6, severity: "medium", title: "New IP associated with known campaign", source: "Threat Intelligence", risk: 58, time: "3h ago", status: "Acknowledged", desc: "IP 45.142.212.199 added to existing PayPal-Phish-2026-08 campaign infrastructure." },
  { id: 7, severity: "low", title: "SPF softfail on internal domain", source: "Auth Analysis", risk: 32, time: "4h ago", status: "Resolved", desc: "Sending server not explicitly listed in SPF record. Softfail rather than hard failure." },
];

const sevIcon = (s: string) => s === "critical" || s === "high" ? AlertTriangle : s === "medium" ? Info : Bell;
const sevColor = (s: string) => ({ critical: "#ff3b5c", high: "#ff7a4a", medium: "#f5a623", low: "#7dce82" })[s] || "#4a9eff";

export default function Alerts({ navigate }: Props) {
  const [filter, setFilter] = useState("All");
  const [dismissed, setDismissed] = useState<number[]>([]);

  const filtered = allAlerts.filter(a => {
    if (dismissed.includes(a.id)) return false;
    if (filter === "All") return true;
    return a.severity === filter.toLowerCase();
  });

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24, marginTop: -8 }}>
        <p style={{ margin: 0, fontSize: 14, color: "#5a6a88" }}>Active security alerts requiring analyst attention.</p>
        <div style={{ display: "flex", gap: 4, background: "#151c2f", padding: 4, borderRadius: 8, border: "1px solid #252e4a" }}>
          {["All","Critical","High","Medium","Low"].map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              padding: "5px 12px", borderRadius: 6, border: "none", cursor: "pointer", fontSize: 12,
              background: filter === f ? "#1e2640" : "transparent",
              color: filter === f ? "#111827" : "#64748b", fontWeight: filter === f ? 600 : 400
            }}>{f}</button>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {filtered.map(alert => {
          const Icon = sevIcon(alert.severity);
          const color = sevColor(alert.severity);
          return (
            <div key={alert.id} className="card" style={{
              padding: 20,
              borderColor: `${color}25`,
              background: `${color}04`,
              transition: "all 0.15s"
            }}>
              <div style={{ display: "flex", gap: 14 }}>
                <div style={{ width: 36, height: 36, borderRadius: 8, background: `${color}15`, border: `1px solid ${color}30`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                  <Icon size={16} color={color} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                        <span className={`badge-${alert.severity}`} style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, textTransform: "uppercase" }}>{alert.severity}</span>
                        <span style={{ fontSize: 14, fontWeight: 600, color: "#e8eaf6" }}>{alert.title}</span>
                      </div>
                      <p style={{ fontSize: 13, color: "#8b96b8", margin: "0 0 8px", lineHeight: 1.5 }}>{alert.desc}</p>
                      <div style={{ display: "flex", gap: 16, fontSize: 12, color: "#5a6a88" }}>
                        <span>Source: {alert.source}</span>
                        <span>Risk Score: <span style={{ color, fontWeight: 700 }}>{alert.risk}</span></span>
                        <span>{alert.time}</span>
                      </div>
                    </div>
                    <div style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                      <span className={alert.status === "New" ? "badge-new" : alert.status === "Resolved" ? "badge-resolved" : "badge-investigating"} style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 500 }}>{alert.status}</span>
                      <button className="btn-ghost" style={{ padding: "5px" }} onClick={() => setDismissed([...dismissed, alert.id])}>
                        <X size={13} color="#64748b" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
        {filtered.length === 0 && (
          <div style={{ textAlign: "center", padding: "80px 40px" }}>
            <div style={{ width: 56, height: 56, borderRadius: "50%", background: "rgba(45,199,122,0.1)", border: "1px solid rgba(45,199,122,0.2)", margin: "0 auto 16px", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <CheckCircle size={24} color="#2dc77a" />
            </div>
            <div style={{ fontSize: 16, fontWeight: 600, color: "#5a6a88", marginBottom: 8 }}>No alerts in this category</div>
            <div style={{ fontSize: 13, color: "#4a5a78" }}>All clear — no active security alerts matching your filter</div>
          </div>
        )}
      </div>
    </div>
  );
}
