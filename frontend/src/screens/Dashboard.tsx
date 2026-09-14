import { Mail, AlertTriangle, ShieldAlert, FolderOpen, TrendingUp, TrendingDown, Clock, Activity } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from "recharts";
import type { Screen } from "../App";

const trendData = [
  { day: "Aug 1", legitimate: 320, suspicious: 45, phishing: 12, fraud: 4 },
  { day: "Aug 5", legitimate: 380, suspicious: 60, phishing: 18, fraud: 7 },
  { day: "Aug 10", legitimate: 290, suspicious: 52, phishing: 14, fraud: 5 },
  { day: "Aug 15", legitimate: 420, suspicious: 80, phishing: 28, fraud: 11 },
  { day: "Aug 20", legitimate: 360, suspicious: 68, phishing: 22, fraud: 9 },
  { day: "Aug 25", legitimate: 440, suspicious: 95, phishing: 35, fraud: 14 },
  { day: "Aug 31", legitimate: 390, suspicious: 72, phishing: 26, fraud: 10 },
];

const distData = [
  { name: "Phishing", value: 38, color: "#ff3b5c" },
  { name: "Spoofing", value: 22, color: "#ff6b35" },
  { name: "BEC", value: 18, color: "#f5a623" },
  { name: "Malware", value: 12, color: "#9b6fff" },
  { name: "Legitimate", value: 10, color: "#2dc77a" },
];

const threats = [
  { severity: "critical", sender: "billing@paypa1-secure.com", subject: "Invoice Payment Required", type: "Phishing", score: 96, time: "4 min ago", status: "Investigating" },
  { severity: "high", sender: "security@amaz0n-alerts.net", subject: "Account Access Suspended", type: "Impersonation", score: 88, time: "17 min ago", status: "New" },
  { severity: "high", sender: "hr-payroll@corperate-hq.com", subject: "Urgent: Wire Transfer Request", type: "BEC", score: 84, time: "43 min ago", status: "Investigating" },
  { severity: "medium", sender: "noreply@docs-share.info", subject: "Document ready to view", type: "Phishing", score: 67, time: "1h 12m ago", status: "Resolved" },
  { severity: "critical", sender: "ceo@company-financials.org", subject: "Confidential – Immediate Action", type: "BEC", score: 93, time: "2h 5m ago", status: "Investigating" },
];

const timeline = [
  { icon: AlertTriangle, color: "#ff3b5c", text: "High-risk email detected from billing@paypa1-secure.com", time: "4 min ago" },
  { icon: Activity, color: "#f5a623", text: "Suspicious domain paypa1-secure.com flagged by threat intel", time: "12 min ago" },
  { icon: FolderOpen, color: "#4a7cff", text: "New investigation CASE-2026-001284 created", time: "47 min ago" },
  { icon: Activity, color: "#9b6fff", text: "IP 185.220.101.47 linked to previous campaign", time: "1h 18m ago" },
  { icon: AlertTriangle, color: "#ff6b35", text: "BEC attempt detected from ceo@company-financials.org", time: "2h 5m ago" },
];

const infraRows = [
  { ip: "185.220.101.47", country: "🇸🇬 Singapore", isp: "AS-CHOOPA LLC", threats: 14, risk: "critical" },
  { ip: "194.165.16.4", country: "🇳🇱 Netherlands", isp: "COMBAHTON GmbH", threats: 9, risk: "high" },
  { ip: "45.142.212.100", country: "🇩🇪 Germany", isp: "PROTON66 OOO", threats: 7, risk: "high" },
  { ip: "198.96.155.3", country: "🇺🇸 United States", isp: "HZ Hosting Ltd", threats: 4, risk: "medium" },
];

const badgeClass = (sev: string) => {
  const m: Record<string, string> = { critical: "badge-critical", high: "badge-high", medium: "badge-medium", low: "badge-low" };
  return m[sev] || "badge-info";
};

const statusClass = (s: string) => {
  const m: Record<string, string> = { New: "badge-new", Investigating: "badge-investigating", Resolved: "badge-resolved" };
  return m[s] || "badge-info";
};

interface Props { navigate: (s: Screen) => void; }

export default function Dashboard({ navigate }: Props) {
  const kpis = [
    { icon: Mail, label: "Total Analyzed", value: "12,482", trend: "+12.4%", up: true, color: "#4a7cff" },
    { icon: AlertTriangle, label: "Threats Detected", value: "1,284", trend: "+8.1%", up: true, color: "#ff6b35" },
    { icon: ShieldAlert, label: "High Risk", value: "347", trend: "+3.2%", up: true, color: "#ff3b5c" },
    { icon: FolderOpen, label: "Under Investigation", value: "28", trend: "-2 cases", up: false, color: "#9b6fff" },
    { icon: Activity, label: "Detection Accuracy", value: "94.7%", trend: "+0.3%", up: true, color: "#2dc77a" },
  ];

  return (
    <div>
      {/* Subtitle */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24, marginTop: -8 }}>
        <p style={{ margin: 0, fontSize: 14, color: "#5a6a88" }}>Monitor email threats and investigation activity.</p>
        <button className="btn-secondary" style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <Clock size={13} />
          Last 30 Days
        </button>
      </div>

      {/* KPI cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 16, marginBottom: 24 }}>
        {kpis.map((k) => {
          const Icon = k.icon;
          return (
            <div key={k.label} className="card" style={{ padding: 20 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
                <div style={{ width: 36, height: 36, borderRadius: 8, background: `rgba(${hexToRgb(k.color)},0.1)`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Icon size={16} color={k.color} />
                </div>
                <span style={{ fontSize: 11, color: k.up ? "#2dc77a" : "#ff6b35", fontWeight: 500, display: "flex", alignItems: "center", gap: 3 }}>
                  {k.up ? <TrendingUp size={11} /> : <TrendingDown size={11} />}
                  {k.trend}
                </span>
              </div>
              <div style={{ fontSize: 26, fontWeight: 700, color: "#e8eaf6", marginBottom: 4 }}>{k.value}</div>
              <div style={{ fontSize: 12, color: "#5a6a88" }}>{k.label}</div>
              <div style={{ fontSize: 10, color: "#4a5a78", marginTop: 6 }}>vs. previous period</div>
            </div>
          );
        })}
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 16, marginBottom: 24 }}>
        <div className="card" style={{ padding: 24 }}>
          <div style={{ marginBottom: 20 }}>
            <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6" }}>Threat Detection Overview</div>
            <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 4 }}>Email classification trends over the past 30 days</div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={trendData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <defs>
                {[["legitimate","#2dc77a"],["suspicious","#f5a623"],["phishing","#ff3b5c"],["fraud","#9b6fff"]].map(([k,c]) => (
                  <linearGradient key={k} id={`grad-${k}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={c} stopOpacity={0.2} />
                    <stop offset="95%" stopColor={c} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#252e4a" />
              <XAxis dataKey="day" tick={{ fontSize: 11, fill: "#64748b" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: "#64748b" }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: "#151c2f", border: "1px solid #252e4a", borderRadius: 8, fontSize: 12 }} labelStyle={{ color: "#8b96b8" }} />
              <Area type="monotone" dataKey="legitimate" stroke="#2dc77a" fill="url(#grad-legitimate)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="suspicious" stroke="#f5a623" fill="url(#grad-suspicious)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="phishing" stroke="#ff3b5c" fill="url(#grad-phishing)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="fraud" stroke="#9b6fff" fill="url(#grad-fraud)" strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", gap: 16, marginTop: 12, flexWrap: "wrap" }}>
            {[["Legitimate","#2dc77a"],["Suspicious","#f5a623"],["Phishing","#ff3b5c"],["Fraud","#9b6fff"]].map(([label,color]) => (
              <div key={label} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: color as string }} />
                <span style={{ fontSize: 12, color: "#5a6a88" }}>{label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card" style={{ padding: 24 }}>
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6" }}>Threat Distribution</div>
            <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 4 }}>Classification breakdown</div>
          </div>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={distData} cx="50%" cy="50%" innerRadius={45} outerRadius={75} dataKey="value" paddingAngle={2}>
                {distData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: "#151c2f", border: "1px solid #252e4a", borderRadius: 8, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 8 }}>
            {distData.map(d => (
              <div key={d.name} style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color }} />
                  <span style={{ fontSize: 12, color: "#8b96b8" }}>{d.name}</span>
                </div>
                <span style={{ fontSize: 12, fontWeight: 600, color: "#e8eaf6" }}>{d.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Tables row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 16, marginBottom: 24 }}>
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "20px 24px 16px", borderBottom: "1px solid #252e4a", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div>
              <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6" }}>Recent Threats</div>
              <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 2 }}>Latest detected threat activity</div>
            </div>
            <button className="btn-ghost" style={{ fontSize: 13 }} onClick={() => navigate("history")}>View All</button>
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #252e4a" }}>
                {["Severity","Sender","Subject","Threat","Score","Time","Status"].map(h => (
                  <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 11, color: "#5a6a88", fontWeight: 600, letterSpacing: "0.04em" }}>{h.toUpperCase()}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {threats.map((t, i) => (
                <tr key={i} className="row-hover" style={{ borderBottom: "1px solid #252e4a", cursor: "pointer" }} onClick={() => navigate("result")}>
                  <td style={{ padding: "11px 16px" }}>
                    <span className={badgeClass(t.severity)} style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600, textTransform: "capitalize" }}>{t.severity}</span>
                  </td>
                  <td style={{ padding: "11px 16px" }}>
                    <span className="mono" style={{ fontSize: 12, color: "#8b96b8" }}>{t.sender}</span>
                  </td>
                  <td style={{ padding: "11px 16px", fontSize: 13, color: "#e8eaf6", maxWidth: 180 }}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block" }}>{t.subject}</span>
                  </td>
                  <td style={{ padding: "11px 16px", fontSize: 12, color: "#8b96b8" }}>{t.type}</td>
                  <td style={{ padding: "11px 16px" }}>
                    <span style={{ fontSize: 13, fontWeight: 700, color: t.score >= 80 ? "#ff3b5c" : t.score >= 60 ? "#f5a623" : "#2dc77a" }}>{t.score}</span>
                  </td>
                  <td style={{ padding: "11px 16px", fontSize: 12, color: "#5a6a88", whiteSpace: "nowrap" }}>{t.time}</td>
                  <td style={{ padding: "11px 16px" }}>
                    <span className={statusClass(t.status)} style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 500 }}>{t.status}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 4 }}>Threat Activity</div>
          <div style={{ fontSize: 12, color: "#5a6a88", marginBottom: 20 }}>Recent system events</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {timeline.map((item, i) => {
              const Icon = item.icon;
              return (
                <div key={i} style={{ display: "flex", gap: 12 }}>
                  <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                    <div style={{ width: 28, height: 28, borderRadius: "50%", background: `${item.color}1a`, border: `1px solid ${item.color}40`, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                      <Icon size={12} color={item.color} />
                    </div>
                    {i < timeline.length - 1 && <div style={{ width: 1, flex: 1, background: "#252e4a", marginTop: 4 }} />}
                  </div>
                  <div style={{ paddingBottom: i < timeline.length - 1 ? 16 : 0 }}>
                    <div style={{ fontSize: 12, color: "#8b96b8", lineHeight: 1.5 }}>{item.text}</div>
                    <div style={{ fontSize: 11, color: "#4a5a78", marginTop: 4 }}>{item.time}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Infra table */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "20px 24px 16px", borderBottom: "1px solid #252e4a" }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6" }}>Top Suspicious Infrastructure</div>
          <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 2 }}>IP addresses with highest threat activity</div>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #252e4a" }}>
              {["IP Address","Country","ISP / Organization","Threat Count","Risk Level"].map(h => (
                <th key={h} style={{ padding: "10px 20px", textAlign: "left", fontSize: 11, color: "#5a6a88", fontWeight: 600, letterSpacing: "0.04em" }}>{h.toUpperCase()}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {infraRows.map((r, i) => (
              <tr key={i} className="row-hover" style={{ borderBottom: i < infraRows.length - 1 ? "1px solid #c8cfe0" : "none", cursor: "pointer" }} onClick={() => navigate("ip-geo")}>
                <td style={{ padding: "12px 20px" }}><span className="mono" style={{ fontSize: 13, color: "#4a9eff" }}>{r.ip}</span></td>
                <td style={{ padding: "12px 20px", fontSize: 13, color: "#e8eaf6" }}>{r.country}</td>
                <td style={{ padding: "12px 20px", fontSize: 13, color: "#8b96b8" }}>{r.isp}</td>
                <td style={{ padding: "12px 20px", fontSize: 14, fontWeight: 700, color: "#e8eaf6" }}>{r.threats}</td>
                <td style={{ padding: "12px 20px" }}>
                  <span className={badgeClass(r.risk)} style={{ padding: "2px 10px", borderRadius: 4, fontSize: 11, fontWeight: 600, textTransform: "capitalize" }}>{r.risk}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function hexToRgb(hex: string) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `${r},${g},${b}`;
}
