import { useState } from "react";
import {
  BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell
} from "recharts";
import { Search, AlertTriangle, TrendingUp, Mail, Clock, Shield } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const freqData = [
  { day: "Aug 25", count: 2 }, { day: "Aug 26", count: 5 },
  { day: "Aug 27", count: 3 }, { day: "Aug 28", count: 8 },
  { day: "Aug 29", count: 14 }, { day: "Aug 30", count: 21 },
  { day: "Aug 31", count: 19 },
];

const hourlyData = [
  { hour: "00", count: 1 }, { hour: "02", count: 0 }, { hour: "04", count: 2 },
  { hour: "06", count: 5 }, { hour: "08", count: 14 }, { hour: "10", count: 11 },
  { hour: "12", count: 8 }, { hour: "14", count: 16 }, { hour: "16", count: 12 },
  { hour: "18", count: 9 }, { hour: "20", count: 6 }, { hour: "22", count: 3 },
];

const campaignData = [
  { name: "PayPal Phish", count: 28, color: "#e8284a" },
  { name: "Wire Fraud", count: 19, color: "#f05a20" },
  { name: "Credential Harvest", count: 14, color: "#d97706" },
  { name: "Malware Drop", count: 7, color: "#9b6fff" },
  { name: "Other", count: 4, color: "#4a5a78" },
];

const relatedSenders = [
  { email: "billing@paypa1-secure.com", count: 21, risk: "critical", lastSeen: "4 min ago" },
  { email: "support@paypa1-alerts.net", count: 14, risk: "high", lastSeen: "2h ago" },
  { email: "noreply@paypa1-secure.com", count: 9, risk: "high", lastSeen: "6h ago" },
  { email: "security@paypa1-verify.com", count: 6, risk: "high", lastSeen: "1d ago" },
  { email: "alert@paypa1-update.org", count: 3, risk: "medium", lastSeen: "2d ago" },
];

const heatmapDays = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
const heatmapHours = ["6am","9am","12pm","3pm","6pm","9pm"];
const heatmapData: number[][] = [
  [0,2,3,5,4,1,0], [1,3,8,12,9,3,1], [0,2,5,8,6,2,0],
  [2,5,11,16,12,4,1], [1,4,9,14,10,3,0], [0,1,3,5,4,2,0],
];

const riskColor = (r: string) => ({ critical:"#e8284a", high:"#f05a20", medium:"#d97706", low:"#16a34a" })[r] || "#64748b";

export default function SpamTracker({ navigate }: Props) {
  const [query, setQuery] = useState("paypa1-secure.com");
  const [searched, setSearched] = useState("paypa1-secure.com");

  const handleSearch = () => setSearched(query.trim() || searched);

  return (
    <div>
      <p style={{ margin: "0 0 24px", fontSize: 14, color: "#5a6a88", marginTop: -8 }}>
        Track spam and phishing frequency patterns for a specific sender, domain, or campaign.
      </p>

      {/* Search bar */}
      <div style={{ display: "flex", gap: 10, marginBottom: 28 }}>
        <div style={{ position: "relative", flex: 1, maxWidth: 520 }}>
          <Mail size={14} color="#64748b" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }} />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleSearch()}
            placeholder="Enter email address, domain, or campaign name..."
            style={{ width: "100%", paddingLeft: 36, height: 42, fontSize: 14 }}
          />
        </div>
        <button className="btn-primary" onClick={handleSearch} style={{ padding: "0 24px", height: 42, display: "flex", alignItems: "center", gap: 8 }}>
          <Search size={14} /> Track
        </button>
      </div>

      {/* Subject banner */}
      <div className="card" style={{ padding: "16px 24px", marginBottom: 20, display: "flex", alignItems: "center", justifyContent: "space-between", background: "#fff5f6", borderColor: "#fcc8d0" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 36, height: 36, borderRadius: 8, background: "rgba(232,40,74,0.1)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <AlertTriangle size={16} color="#e8284a" />
          </div>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: "#e8eaf6" }}>
              Tracking: <span style={{ fontFamily: "'JetBrains Mono', monospace", color: "#e8284a" }}>{searched}</span>
            </div>
            <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 2 }}>72 spam emails detected · Active campaign · Last seen 4 min ago</div>
          </div>
        </div>
        <span className="badge-critical" style={{ padding: "4px 12px", borderRadius: 6, fontSize: 12, fontWeight: 700 }}>HIGH VOLUME</span>
      </div>

      {/* KPI row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 20 }}>
        {[
          { label: "Total Spam Emails", value: "72", icon: Mail, color: "#e8284a", sub: "Last 7 days" },
          { label: "Peak Volume", value: "21/day", icon: TrendingUp, color: "#f05a20", sub: "Aug 30, 2026" },
          { label: "Active Since", value: "7 days", icon: Clock, color: "#d97706", sub: "First seen Aug 25" },
          { label: "Campaigns Linked", value: "3", icon: Shield, color: "#9b6fff", sub: "Across 3 threat feeds" },
        ].map(k => {
          const Icon = k.icon;
          return (
            <div key={k.label} className="card" style={{ padding: 20 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
                <div style={{ width: 32, height: 32, borderRadius: 8, background: `${k.color}15`, display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Icon size={15} color={k.color} />
                </div>
                <span style={{ fontSize: 11, color: "#5a6a88" }}>{k.label}</span>
              </div>
              <div style={{ fontSize: 24, fontWeight: 800, color: k.color }}>{k.value}</div>
              <div style={{ fontSize: 11, color: "#4a5a78", marginTop: 4 }}>{k.sub}</div>
            </div>
          );
        })}
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>
        {/* Daily frequency */}
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 4 }}>Daily Spam Frequency</div>
          <div style={{ fontSize: 12, color: "#5a6a88", marginBottom: 20 }}>Email volume over the past 7 days</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={freqData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#252e4a" vertical={false} />
              <XAxis dataKey="day" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: "#fff", border: "1px solid #e2e6f0", borderRadius: 8, fontSize: 12 }}
                formatter={(v: unknown) => [`${String(v)} emails`, "Count"]}
              />
              <Bar dataKey="count" radius={[4,4,0,0]}>
                {freqData.map((entry, i) => (
                  <Cell key={i} fill={entry.count >= 15 ? "#e8284a" : entry.count >= 8 ? "#f05a20" : "#4a7cff"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", gap: 16, marginTop: 8 }}>
            {[["#e8284a","High (15+)"],["#f05a20","Medium (8–14)"],["#4a7cff","Low (<8)"]].map(([c,l]) => (
              <div key={l} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <div style={{ width: 8, height: 8, borderRadius: 2, background: c as string }} />
                <span style={{ fontSize: 11, color: "#4a5a78" }}>{l}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Hourly pattern */}
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 4 }}>Hourly Send Pattern</div>
          <div style={{ fontSize: 12, color: "#5a6a88", marginBottom: 20 }}>Average emails sent per hour of day</div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={hourlyData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#252e4a" />
              <XAxis dataKey="hour" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false}
                tickFormatter={h => `${h}:00`} />
              <YAxis tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: "#fff", border: "1px solid #e2e6f0", borderRadius: 8, fontSize: 12 }}
                formatter={(v: unknown) => [`${String(v)} emails`, "Volume"]} labelFormatter={h => `${h}:00`} />
              <Line type="monotone" dataKey="count" stroke="#4a7cff" strokeWidth={2} dot={{ r: 3, fill: "#4a7cff" }} />
            </LineChart>
          </ResponsiveContainer>
          <div style={{ marginTop: 8, fontSize: 12, color: "#5a6a88" }}>
            Peak activity: <span style={{ color: "#e8284a", fontWeight: 600 }}>14:00–16:00 UTC</span> — typical of automated bulk sending
          </div>
        </div>
      </div>

      {/* Heatmap + campaigns */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 16, marginBottom: 20 }}>
        {/* Heatmap */}
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 4 }}>Activity Heatmap</div>
          <div style={{ fontSize: 12, color: "#5a6a88", marginBottom: 20 }}>Spam volume by day of week vs. time of day</div>
          <div style={{ display: "flex", gap: 0 }}>
            <div style={{ display: "flex", flexDirection: "column", justifyContent: "space-around", paddingRight: 10, paddingTop: 24 }}>
              {heatmapHours.map(h => (
                <span key={h} style={{ fontSize: 10, color: "#4a5a78", textAlign: "right" }}>{h}</span>
              ))}
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", marginBottom: 6 }}>
                {heatmapDays.map(d => (
                  <div key={d} style={{ flex: 1, textAlign: "center", fontSize: 11, color: "#4a5a78" }}>{d}</div>
                ))}
              </div>
              {heatmapData.map((row, ri) => (
                <div key={ri} style={{ display: "flex", gap: 3, marginBottom: 3 }}>
                  {row.map((val, ci) => {
                    const opacity = val === 0 ? 0.05 : val < 5 ? 0.2 : val < 10 ? 0.5 : val < 15 ? 0.75 : 1;
                    return (
                      <div
                        key={ci}
                        title={`${heatmapDays[ci]} ${heatmapHours[ri]}: ${val} emails`}
                        style={{
                          flex: 1, height: 28, borderRadius: 4,
                          background: `rgba(232,40,74,${opacity})`,
                          border: "1px solid rgba(232,40,74,0.1)",
                          cursor: "default",
                          transition: "opacity 0.1s"
                        }}
                      />
                    );
                  })}
                </div>
              ))}
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 10 }}>
                <span style={{ fontSize: 10, color: "#4a5a78" }}>Low</span>
                {[0.08, 0.2, 0.4, 0.65, 1].map((o, i) => (
                  <div key={i} style={{ width: 16, height: 12, borderRadius: 3, background: `rgba(232,40,74,${o})` }} />
                ))}
                <span style={{ fontSize: 10, color: "#4a5a78" }}>High</span>
              </div>
            </div>
          </div>
        </div>

        {/* Campaign breakdown */}
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 4 }}>Campaign Breakdown</div>
          <div style={{ fontSize: 12, color: "#5a6a88", marginBottom: 20 }}>Linked threat campaigns</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {campaignData.map(c => (
              <div key={c.name}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                  <span style={{ fontSize: 12, color: "#8b96b8" }}>{c.name}</span>
                  <span style={{ fontSize: 12, fontWeight: 700, color: c.color }}>{c.count}</span>
                </div>
                <div style={{ height: 6, background: "#151c2f", borderRadius: 3, overflow: "hidden" }}>
                  <div style={{
                    height: "100%", borderRadius: 3, background: c.color,
                    width: `${(c.count / 28) * 100}%`, transition: "width 0.3s"
                  }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Related senders table */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "18px 24px 14px", borderBottom: "1px solid #252e4a", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6" }}>Related Sender Identities</div>
            <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 2 }}>Other senders linked to the same infrastructure or campaign</div>
          </div>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #252e4a" }}>
              {["Sender Address","Emails Sent","Risk","Last Seen","Action"].map(h => (
                <th key={h} style={{ padding: "10px 20px", textAlign: "left", fontSize: 11, color: "#5a6a88", fontWeight: 600, letterSpacing: "0.04em" }}>{h.toUpperCase()}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {relatedSenders.map((s, i) => (
              <tr key={i} className="row-hover" style={{ borderBottom: i < relatedSenders.length - 1 ? "1px solid #c8cfe0" : "none" }}>
                <td style={{ padding: "12px 20px" }}>
                  <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#e8eaf6" }}>{s.email}</span>
                </td>
                <td style={{ padding: "12px 20px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <span style={{ fontSize: 14, fontWeight: 700, color: riskColor(s.risk) }}>{s.count}</span>
                    <div style={{ width: 60, height: 4, background: "#151c2f", borderRadius: 2 }}>
                      <div style={{ height: "100%", borderRadius: 2, background: riskColor(s.risk), width: `${(s.count / 21) * 100}%` }} />
                    </div>
                  </div>
                </td>
                <td style={{ padding: "12px 20px" }}>
                  <span className={`badge-${s.risk}`} style={{ padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600, textTransform: "capitalize" }}>{s.risk}</span>
                </td>
                <td style={{ padding: "12px 20px", fontSize: 12, color: "#5a6a88" }}>{s.lastSeen}</td>
                <td style={{ padding: "12px 20px" }}>
                  <button className="btn-secondary" style={{ padding: "5px 12px", fontSize: 12 }} onClick={() => navigate("result")}>
                    Investigate
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
