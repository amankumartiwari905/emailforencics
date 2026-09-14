import { X, CheckCircle, AlertTriangle, ArrowLeft } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const headers = [
  { name: "From", value: "support@paypa1-secure.com", assessment: "Suspicious", status: "fail" },
  { name: "Reply-To", value: "security-alert@paypa1-secure.com", assessment: "Mismatch", status: "fail" },
  { name: "Return-Path", value: "mailer@mx.paypa1-secure.com", assessment: "Suspicious", status: "fail" },
  { name: "Received", value: "from mail.paypa1-secure.com (185.220.101.47) by mx1.organization.com", assessment: "Analyzed", status: "warn" },
  { name: "Received", value: "from mx.paypa1-secure.com by mail.paypa1-secure.com", assessment: "Analyzed", status: "warn" },
  { name: "Message-ID", value: "<CA+xyz123@mail.paypa1-secure.com>", assessment: "Valid", status: "ok" },
  { name: "MIME-Version", value: "1.0", assessment: "Valid", status: "ok" },
  { name: "Date", value: "Sun, 31 Aug 2026 09:14:22 +0000", assessment: "Valid", status: "ok" },
  { name: "X-Mailer", value: "PHPMailer 6.6.4", assessment: "Automated", status: "warn" },
];

const anomalies = [
  "Sender domain (paypa1-secure.com) does not match the legitimate PayPal domain",
  "Reply-To header points to a different address than the From header — characteristic of phishing",
  "Relay sequence originates from a commercial VPS provider with prior threat history",
  "Authentication alignment fails: DMARC From domain does not align with SPF/DKIM",
  "X-Mailer indicates automated sending tool (PHPMailer), inconsistent with enterprise mail",
  "Received chain shows only 2 internal hops before reaching destination — insufficient for claimed source",
];

export default function HeaderForensics({ navigate }: Props) {
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24, marginTop: -8 }}>
        <button className="btn-ghost" onClick={() => navigate("result")} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          <ArrowLeft size={14} /> Back to Result
        </button>
        <span className="mono" style={{ fontSize: 12, color: "#4a5a78" }}>CASE-2026-001284</span>
      </div>

      {/* Auth cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 20 }}>
        {[
          { label: "SPF", result: "FAIL", reason: "Sending IP 185.220.101.47 is not authorized by the SPF record of paypa1-secure.com", detail: "v=spf1 include:spf.example.com ~all", icon: X, color: "#ff3b5c", bg: "rgba(255,59,92,0.08)", border: "rgba(255,59,92,0.25)" },
          { label: "DKIM", result: "FAIL", reason: "DKIM signature does not validate. Signature may have been stripped or modified in transit.", detail: "header.d=paypa1-secure.com  selector=mail  status=permerror", icon: X, color: "#ff3b5c", bg: "rgba(255,59,92,0.08)", border: "rgba(255,59,92,0.25)" },
          { label: "DMARC", result: "FAIL", reason: "Neither SPF nor DKIM produced an aligned passing result. DMARC policy is p=none (monitoring).", detail: "From domain: paypa1-secure.com  Policy: p=none  Disposition: none", icon: X, color: "#ff3b5c", bg: "rgba(255,59,92,0.08)", border: "rgba(255,59,92,0.25)" },
        ].map(auth => {
          const Icon = auth.icon;
          return (
            <div key={auth.label} className="card" style={{ padding: 24, background: auth.bg, borderColor: auth.border }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
                <div style={{ width: 32, height: 32, borderRadius: "50%", background: `${auth.color}22`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Icon size={16} color={auth.color} />
                </div>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: "#e8eaf6" }}>{auth.label}</div>
                  <div style={{ fontSize: 13, fontWeight: 700, color: auth.color }}>{auth.result}</div>
                </div>
              </div>
              <p style={{ fontSize: 13, color: "#8b96b8", lineHeight: 1.6, margin: "0 0 12px" }}>{auth.reason}</p>
              <div style={{ padding: "8px 12px", background: "#151c2f", borderRadius: 6 }}>
                <span className="mono" style={{ fontSize: 11, color: "#5a6a88" }}>{auth.detail}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Header table */}
      <div className="card" style={{ padding: 0, overflow: "hidden", marginBottom: 20 }}>
        <div style={{ padding: "20px 24px 16px", borderBottom: "1px solid #252e4a" }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6" }}>Header Analysis</div>
          <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 4 }}>Full header inspection and assessment</div>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #252e4a" }}>
              {["Header","Value","Assessment"].map(h => (
                <th key={h} style={{ padding: "10px 20px", textAlign: "left", fontSize: 11, color: "#5a6a88", fontWeight: 600, letterSpacing: "0.04em" }}>{h.toUpperCase()}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {headers.map((row, i) => (
              <tr key={i} className="row-hover" style={{ borderBottom: i < headers.length - 1 ? "1px solid #c8cfe0" : "none" }}>
                <td style={{ padding: "10px 20px", width: 140 }}>
                  <span className="mono" style={{ fontSize: 12, color: "#4a9eff" }}>{row.name}</span>
                </td>
                <td style={{ padding: "10px 20px" }}>
                  <span className="mono" style={{ fontSize: 12, color: "#8b96b8", wordBreak: "break-all" }}>{row.value}</span>
                </td>
                <td style={{ padding: "10px 20px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    {row.status === "fail" && <X size={12} color="#ff3b5c" />}
                    {row.status === "warn" && <AlertTriangle size={12} color="#f5a623" />}
                    {row.status === "ok" && <CheckCircle size={12} color="#2dc77a" />}
                    <span style={{ fontSize: 12, fontWeight: 600, color: row.status === "fail" ? "#ff3b5c" : row.status === "warn" ? "#f5a623" : "#2dc77a" }}>
                      {row.assessment}
                    </span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Anomalies */}
      <div className="card" style={{ padding: 24 }}>
        <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 16 }}>Header Anomalies</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {anomalies.map((a, i) => (
            <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 12, padding: "12px 16px", background: "rgba(245,166,35,0.06)", borderRadius: 8, border: "1px solid rgba(245,166,35,0.15)" }}>
              <AlertTriangle size={14} color="#f5a623" style={{ flexShrink: 0, marginTop: 1 }} />
              <span style={{ fontSize: 13, color: "#8b96b8", lineHeight: 1.6 }}>{a}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
