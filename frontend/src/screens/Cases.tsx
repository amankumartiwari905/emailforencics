import { useState } from "react";
import { Plus, Search, Filter } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const cases = [
  { id: "CASE-2026-001284", title: "Payment Fraud Campaign", severity: "critical", type: "BEC", indicators: 14, analyst: "Analyst 01", created: "Today 08:42", status: "Investigating" },
  { id: "CASE-2026-001283", title: "PayPal Lookalike Domain", severity: "high", type: "Phishing", indicators: 8, analyst: "Analyst 02", created: "Today 06:15", status: "Investigating" },
  { id: "CASE-2026-001280", title: "CEO Impersonation – Wire Request", severity: "critical", type: "BEC", indicators: 11, analyst: "Analyst 01", created: "Yesterday", status: "Contained" },
  { id: "CASE-2026-001275", title: "Mass Credential Harvest Campaign", severity: "high", type: "Phishing", indicators: 27, analyst: "Analyst 03", created: "Aug 28", status: "Investigating" },
  { id: "CASE-2026-001268", title: "Invoice Fraud – Finance Dept", severity: "high", type: "BEC", indicators: 6, analyst: "Analyst 02", created: "Aug 26", status: "Resolved" },
  { id: "CASE-2026-001254", title: "Malware Delivery via PDF", severity: "critical", type: "Malware", indicators: 19, analyst: "Analyst 01", created: "Aug 22", status: "Closed" },
  { id: "CASE-2026-001241", title: "Executive Spoofing Campaign", severity: "medium", type: "Spoofing", indicators: 5, analyst: "Analyst 03", created: "Aug 18", status: "Resolved" },
];

const statusBadge = (s: string) => {
  const m: Record<string, string> = { New: "badge-new", Investigating: "badge-investigating", Contained: "badge-medium", Resolved: "badge-resolved", Closed: "badge-closed" };
  return m[s] || "badge-info";
};

export default function Cases({ navigate }: Props) {
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");

  const filtered = cases.filter(c => {
    const matchSearch = search.trim() === "" || c.title.toLowerCase().includes(search.toLowerCase()) || c.id.includes(search);
    const matchStatus = statusFilter === "All" || c.status === statusFilter;
    return matchSearch && matchStatus;
  });

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24, marginTop: -8 }}>
        <p style={{ margin: 0, fontSize: 14, color: "#5a6a88" }}>Manage ongoing threat investigations and forensic cases.</p>
        <button className="btn-primary" style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          <Plus size={14} /> New Case
        </button>
      </div>

      {/* Filters */}
      <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
        <div style={{ position: "relative" }}>
          <Search size={13} color="#64748b" style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)" }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search cases..." style={{ paddingLeft: 30, width: 240, height: 36, fontSize: 13 }} />
        </div>
        <div style={{ display: "flex", gap: 4, background: "#151c2f", padding: 4, borderRadius: 8, border: "1px solid #252e4a" }}>
          {["All","New","Investigating","Contained","Resolved","Closed"].map(s => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              style={{
                padding: "5px 12px", borderRadius: 6, border: "none", cursor: "pointer", fontSize: 12,
                background: statusFilter === s ? "#1e2640" : "transparent",
                color: statusFilter === s ? "#111827" : "#64748b",
                fontWeight: statusFilter === s ? 600 : 400
              }}
            >{s}</button>
          ))}
        </div>
      </div>

      {/* Cases table */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #252e4a" }}>
              {["Case ID","Title","Severity","Threat Type","Indicators","Assigned To","Created","Status"].map(h => (
                <th key={h} style={{ padding: "11px 16px", textAlign: "left", fontSize: 11, color: "#5a6a88", fontWeight: 600, letterSpacing: "0.04em" }}>{h.toUpperCase()}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((c, i) => (
              <tr key={i} className="row-hover" style={{ borderBottom: i < filtered.length - 1 ? "1px solid #c8cfe0" : "none", cursor: "pointer" }} onClick={() => navigate("case-details")}>
                <td style={{ padding: "12px 16px" }}>
                  <span className="mono" style={{ fontSize: 12, color: "#4a9eff" }}>{c.id}</span>
                </td>
                <td style={{ padding: "12px 16px", fontSize: 13, fontWeight: 500, color: "#e8eaf6" }}>{c.title}</td>
                <td style={{ padding: "12px 16px" }}>
                  <span className={`badge-${c.severity}`} style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, textTransform: "capitalize" }}>{c.severity}</span>
                </td>
                <td style={{ padding: "12px 16px", fontSize: 12, color: "#8b96b8" }}>{c.type}</td>
                <td style={{ padding: "12px 16px", fontSize: 14, fontWeight: 700, color: "#e8eaf6" }}>{c.indicators}</td>
                <td style={{ padding: "12px 16px", fontSize: 12, color: "#8b96b8" }}>{c.analyst}</td>
                <td style={{ padding: "12px 16px", fontSize: 12, color: "#5a6a88", whiteSpace: "nowrap" }}>{c.created}</td>
                <td style={{ padding: "12px 16px" }}>
                  <span className={statusBadge(c.status)} style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 500 }}>{c.status}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div style={{ padding: "60px 40px", textAlign: "center" }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: "#5a6a88", marginBottom: 8 }}>No cases match your filters</div>
            <div style={{ fontSize: 13, color: "#4a5a78" }}>Try adjusting your search or filter criteria</div>
          </div>
        )}
      </div>
    </div>
  );
}
