import { useState } from "react";
import { Search, Filter } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const history = [
  { date: "Aug 31 09:14", sender: "support@paypa1-secure.com", subject: "Urgent: Verify Your Account", classification: "Phishing", risk: 92, analyst: "Analyst 01", status: "Investigating" },
  { date: "Aug 31 06:55", sender: "hr@corperate-hq.com", subject: "Wire Transfer Authorization Needed", classification: "BEC", risk: 88, analyst: "Analyst 01", status: "Investigating" },
  { date: "Aug 30 18:30", sender: "noreply@docusignalert.net", subject: "Please sign the attached document", classification: "Phishing", risk: 76, analyst: "Analyst 02", status: "Resolved" },
  { date: "Aug 30 14:22", sender: "info@company-newsletter.com", subject: "Monthly Newsletter — August 2026", classification: "Legitimate", risk: 5, analyst: "Analyst 02", status: "Closed" },
  { date: "Aug 30 11:45", sender: "security@amaz0n-alerts.net", subject: "Your account access has been suspended", classification: "Impersonation", risk: 91, analyst: "Analyst 03", status: "Resolved" },
  { date: "Aug 29 16:08", sender: "payroll@finance-dept.org", subject: "Updated direct deposit form enclosed", classification: "BEC", risk: 84, analyst: "Analyst 01", status: "Closed" },
  { date: "Aug 29 10:33", sender: "admin@secure-login-portal.xyz", subject: "Login attempt from new device", classification: "Phishing", risk: 79, analyst: "Analyst 03", status: "Resolved" },
  { date: "Aug 28 09:12", sender: "boss@my-company.co", subject: "Confidential — see attachment", classification: "Malware", risk: 95, analyst: "Analyst 01", status: "Investigating" },
];

const classColor = (c: string) => ({
  Phishing: "#ff3b5c", BEC: "#f5a623", Impersonation: "#ff7a4a",
  Malware: "#9b6fff", Legitimate: "#2dc77a"
})[c] || "#4a9eff";

const statusBadge = (s: string) => {
  const m: Record<string, string> = { Investigating: "badge-investigating", Resolved: "badge-resolved", Closed: "badge-closed", New: "badge-new" };
  return m[s] || "badge-info";
};

export default function AnalysisHistory({ navigate }: Props) {
  const [search, setSearch] = useState("");

  const filtered = history.filter(h =>
    search.trim() === "" ||
    h.sender.toLowerCase().includes(search.toLowerCase()) ||
    h.subject.toLowerCase().includes(search.toLowerCase()) ||
    h.classification.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24, marginTop: -8 }}>
        <p style={{ margin: 0, fontSize: 14, color: "#5a6a88" }}>Complete record of analyzed emails and investigation outcomes.</p>
        <div style={{ position: "relative" }}>
          <Search size={13} color="#64748b" style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)" }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search..." style={{ paddingLeft: 30, width: 240, height: 36, fontSize: 13 }} />
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #252e4a" }}>
              {["Date","Sender","Subject","Classification","Risk","Analyst","Status"].map(h => (
                <th key={h} style={{ padding: "11px 16px", textAlign: "left", fontSize: 11, color: "#5a6a88", fontWeight: 600, letterSpacing: "0.04em" }}>{h.toUpperCase()}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((row, i) => (
              <tr key={i} className="row-hover" style={{ borderBottom: i < filtered.length - 1 ? "1px solid #c8cfe0" : "none", cursor: "pointer" }} onClick={() => navigate("result")}>
                <td style={{ padding: "11px 16px" }}><span className="mono" style={{ fontSize: 12, color: "#5a6a88" }}>{row.date}</span></td>
                <td style={{ padding: "11px 16px" }}><span className="mono" style={{ fontSize: 12, color: "#8b96b8" }}>{row.sender}</span></td>
                <td style={{ padding: "11px 16px", fontSize: 13, color: "#e8eaf6", maxWidth: 220 }}>
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>{row.subject}</span>
                </td>
                <td style={{ padding: "11px 16px" }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: classColor(row.classification) }}>{row.classification}</span>
                </td>
                <td style={{ padding: "11px 16px" }}>
                  <span style={{ fontSize: 13, fontWeight: 700, color: row.risk >= 80 ? "#ff3b5c" : row.risk >= 50 ? "#f5a623" : "#2dc77a" }}>{row.risk}</span>
                </td>
                <td style={{ padding: "11px 16px", fontSize: 12, color: "#8b96b8" }}>{row.analyst}</td>
                <td style={{ padding: "11px 16px" }}>
                  <span className={statusBadge(row.status)} style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 500 }}>{row.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div style={{ padding: "60px 40px", textAlign: "center" }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: "#5a6a88", marginBottom: 8 }}>No results found</div>
          </div>
        )}
      </div>
    </div>
  );
}
