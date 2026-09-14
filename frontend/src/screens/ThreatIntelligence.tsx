import { useState } from "react";
import { Search, Database, Globe, ExternalLink, AlertTriangle } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const indicators = [
  {
    type: "IP", value: "185.220.101.47", reputation: "Malicious", sources: 3,
    firstSeen: "14 days ago", lastSeen: "2 hours ago", campaigns: 4, country: "🇸🇬 Singapore"
  },
  {
    type: "Domain", value: "paypa1-secure.com", reputation: "Malicious", sources: 5,
    firstSeen: "12 days ago", lastSeen: "4 hours ago", campaigns: 1, country: "—"
  },
  {
    type: "IP", value: "194.165.16.4", reputation: "Suspicious", sources: 2,
    firstSeen: "3 months ago", lastSeen: "1 day ago", campaigns: 2, country: "🇳🇱 Netherlands"
  },
  {
    type: "URL", value: "paypa1-secure.com/verify", reputation: "Malicious", sources: 4,
    firstSeen: "11 days ago", lastSeen: "6 hours ago", campaigns: 1, country: "—"
  },
];

const related = [
  { from: "paypa1-secure.com", relations: ["185.220.101.47", "194.165.16.4", "45.142.212.100", "paypa1-alert.com", "Campaign: PayPal-Phish-2026-08"] }
];

export default function ThreatIntelligence({ navigate }: Props) {
  const [search, setSearch] = useState("");

  const filtered = indicators.filter(i =>
    search.trim() === "" || i.value.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div>
      <p style={{ margin: "0 0 24px", fontSize: 14, color: "#5a6a88", marginTop: -8 }}>
        Correlate indicators against threat intelligence feeds and known campaign data.
      </p>

      {/* Search */}
      <div style={{ position: "relative", maxWidth: 500, marginBottom: 24 }}>
        <Search size={14} color="#64748b" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }} />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search IP, domain, URL, hash..."
          style={{ width: "100%", paddingLeft: 36, height: 40, fontSize: 14 }}
        />
      </div>

      {/* Indicator cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 16, marginBottom: 24 }}>
        {filtered.map((ind, i) => {
          const isMalicious = ind.reputation === "Malicious";
          return (
            <div key={i} className="card" style={{
              padding: 24,
              borderColor: isMalicious ? "rgba(255,59,92,0.2)" : "rgba(245,166,35,0.2)",
              background: isMalicious ? "rgba(255,59,92,0.03)" : "rgba(245,166,35,0.03)"
            }}>
              <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 16 }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                    {ind.type === "IP" ? <Database size={14} color="#4a9eff" /> : ind.type === "Domain" ? <Globe size={14} color="#9b6fff" /> : <ExternalLink size={14} color="#f5a623" />}
                    <span style={{ fontSize: 11, fontWeight: 600, color: "#5a6a88", letterSpacing: "0.06em" }}>{ind.type}</span>
                  </div>
                  <span className="mono" style={{ fontSize: 15, fontWeight: 700, color: "#e8eaf6" }}>{ind.value}</span>
                </div>
                <span className={isMalicious ? "badge-critical" : "badge-high"} style={{ padding: "3px 10px", borderRadius: 4, fontSize: 11, fontWeight: 700, whiteSpace: "nowrap" }}>
                  {ind.reputation}
                </span>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
                {[
                  { label: "Intel Sources", value: `${ind.sources} feeds` },
                  { label: "First Seen", value: ind.firstSeen },
                  { label: "Last Seen", value: ind.lastSeen },
                  { label: "Campaigns", value: `${ind.campaigns} related` },
                ].map(f => (
                  <div key={f.label}>
                    <div style={{ fontSize: 11, color: "#5a6a88" }}>{f.label}</div>
                    <div style={{ fontSize: 13, color: "#8b96b8", marginTop: 2 }}>{f.value}</div>
                  </div>
                ))}
              </div>
              {ind.country !== "—" && (
                <div style={{ marginTop: 12, paddingTop: 12, borderTop: "1px solid #252e4a", fontSize: 12, color: "#5a6a88" }}>
                  Origin: <span style={{ color: "#8b96b8" }}>{ind.country}</span>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Relationship graph */}
      <div className="card" style={{ padding: 24 }}>
        <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 20 }}>Infrastructure Relationships</div>
        {related.map((r, ri) => (
          <div key={ri}>
            {/* Center node */}
            <div style={{ display: "flex", justifyContent: "center", marginBottom: 16 }}>
              <div style={{ padding: "10px 20px", background: "rgba(155,111,255,0.1)", border: "2px solid rgba(155,111,255,0.3)", borderRadius: 8, display: "flex", alignItems: "center", gap: 8 }}>
                <Globe size={16} color="#9b6fff" />
                <span className="mono" style={{ fontSize: 14, fontWeight: 700, color: "#9b6fff" }}>{r.from}</span>
              </div>
            </div>
            {/* Lines */}
            <div style={{ display: "grid", gridTemplateColumns: `repeat(${r.relations.length}, 1fr)`, gap: 12 }}>
              {r.relations.map((rel, reli) => {
                const isIp = /^\d/.test(rel);
                const isCampaign = rel.startsWith("Campaign:");
                const isDomain = !isIp && !isCampaign;
                const color = isIp ? "#4a9eff" : isCampaign ? "#f5a623" : "#9b6fff";
                return (
                  <div key={reli} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
                    <div style={{ width: 1, height: 24, background: "#252e4a" }} />
                    <div style={{ padding: "8px 12px", background: `${color}10`, border: `1px solid ${color}25`, borderRadius: 6, textAlign: "center" }}>
                      <div style={{ fontSize: 10, color: "#5a6a88", marginBottom: 4 }}>
                        {isIp ? "IP" : isCampaign ? "CAMPAIGN" : "DOMAIN"}
                      </div>
                      <span className="mono" style={{ fontSize: 11, color, fontWeight: 600, wordBreak: "break-all" }}>{rel.replace("Campaign: ", "")}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}

        <div style={{ marginTop: 20, padding: "14px 16px", background: "rgba(245,166,35,0.06)", border: "1px solid rgba(245,166,35,0.15)", borderRadius: 8, display: "flex", gap: 10 }}>
          <AlertTriangle size={14} color="#f5a623" style={{ flexShrink: 0, marginTop: 1 }} />
          <p style={{ margin: 0, fontSize: 12, color: "#8b96b8", lineHeight: 1.6 }}>
            This domain is part of an active phishing campaign targeting financial services users. The infrastructure cluster was first identified 14 days ago. 5 related IPs and 3 related domains have been identified.
          </p>
        </div>
      </div>
    </div>
  );
}
