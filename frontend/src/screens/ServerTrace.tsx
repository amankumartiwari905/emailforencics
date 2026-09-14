import { useState } from "react";
import { Search, Server, CheckCircle, AlertTriangle, X, Clock, Globe, ArrowDown, Info, Wifi } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const hops = [
  {
    step: 1,
    label: "Originating Client",
    host: "unknown-client",
    ip: "185.220.101.47",
    rdns: "tor-exit-node.example.net",
    country: "🇸🇬 Singapore",
    org: "Vultr Holdings LLC",
    asn: "AS20473",
    timestamp: "2026-08-31 09:14:18 UTC",
    latency: null,
    protocol: "SMTP",
    port: 25,
    tls: false,
    risk: "critical",
    flags: ["TOR exit node", "Datacenter IP", "Prior phishing campaigns"],
    whois: "inetnum: 185.220.101.0/24\nnetname: AS-CHOOPA\norg: ORG-VHL1-RIPE",
  },
  {
    step: 2,
    label: "Sending Mail Server",
    host: "mail.paypa1-secure.com",
    ip: "185.220.101.47",
    rdns: "mail.paypa1-secure.com",
    country: "🇸🇬 Singapore",
    org: "Vultr Holdings LLC",
    asn: "AS20473",
    timestamp: "2026-08-31 09:14:20 UTC",
    latency: "2s",
    protocol: "ESMTP",
    port: 587,
    tls: true,
    risk: "critical",
    flags: ["Lookalike domain", "12-day-old domain", "No DKIM signing"],
    whois: "Domain: paypa1-secure.com\nCreated: 2026-08-19\nRegistrar: Namecheap",
  },
  {
    step: 3,
    label: "Bulk Relay / MTA",
    host: "relay.bulk-send.net",
    ip: "194.165.16.4",
    rdns: "relay.bulk-send.net",
    country: "🇳🇱 Netherlands",
    org: "Combahton GmbH",
    asn: "AS34135",
    timestamp: "2026-08-31 09:14:21 UTC",
    latency: "1s",
    protocol: "ESMTP",
    port: 25,
    tls: true,
    risk: "suspicious",
    flags: ["Bulk email relay", "Spam reports on record"],
    whois: "inetnum: 194.165.16.0/24\nnetname: COMBAHTON-NET\norg: Combahton GmbH",
  },
  {
    step: 4,
    label: "Intermediate MX",
    host: "mx2.mail-gateway.org",
    ip: "104.21.48.77",
    rdns: "mx2.mail-gateway.org",
    country: "🇺🇸 United States",
    org: "Cloudflare, Inc.",
    asn: "AS13335",
    timestamp: "2026-08-31 09:14:21 UTC",
    latency: "<1s",
    protocol: "ESMTP",
    port: 25,
    tls: true,
    risk: "neutral",
    flags: ["CDN / proxy layer"],
    whois: "inetnum: 104.21.0.0/17\nnetname: CLOUDFLARENET\norg: Cloudflare",
  },
  {
    step: 5,
    label: "Destination Mail Server",
    host: "mx.organization.com",
    ip: "203.0.113.12",
    rdns: "mx.organization.com",
    country: "🇮🇳 India",
    org: "Organization ISP",
    asn: "AS45609",
    timestamp: "2026-08-31 09:14:22 UTC",
    latency: "1s",
    protocol: "ESMTP",
    port: 25,
    tls: true,
    risk: "safe",
    flags: ["Recipient mail server", "Verified SPF"],
    whois: "inetnum: 203.0.113.0/24\nnetname: ORG-MAIL\norg: Organization Corp",
  },
];

const riskColor = (r: string) => ({
  critical: "#e8284a", suspicious: "#f05a20", neutral: "#64748b", safe: "#16a34a"
})[r] || "#64748b";

const riskBg = (r: string) => ({
  critical: "rgba(232,40,74,0.06)", suspicious: "rgba(240,90,32,0.05)",
  neutral: "rgba(100,116,139,0.05)", safe: "rgba(22,163,74,0.05)"
})[r] || "transparent";

const riskBorder = (r: string) => ({
  critical: "rgba(232,40,74,0.2)", suspicious: "rgba(240,90,32,0.18)",
  neutral: "#252e4a", safe: "rgba(22,163,74,0.18)"
})[r] || "#252e4a";

const riskLabel = (r: string) => ({
  critical: "MALICIOUS", suspicious: "SUSPICIOUS", neutral: "NEUTRAL", safe: "TRUSTED"
})[r] || "UNKNOWN";

export default function ServerTrace({ navigate }: Props) {
  const [expandedHop, setExpandedHop] = useState<number | null>(null);
  const [msgId, setMsgId] = useState("<CA+xyz123@mail.paypa1-secure.com>");

  const totalHops = hops.length;
  const riskHops = hops.filter(h => h.risk === "critical" || h.risk === "suspicious").length;

  return (
    <div>
      <p style={{ margin: "0 0 24px", fontSize: 14, color: "#5a6a88", marginTop: -8 }}>
        Reconstruct the full server-to-server delivery path of any email using Received headers. Each hop is verified against threat intelligence.
      </p>

      {/* Search */}
      <div style={{ display: "flex", gap: 10, marginBottom: 24 }}>
        <div style={{ position: "relative", flex: 1, maxWidth: 560 }}>
          <Search size={14} color="#64748b" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }} />
          <input
            value={msgId}
            onChange={e => setMsgId(e.target.value)}
            placeholder="Paste Message-ID or Received header chain..."
            style={{ width: "100%", paddingLeft: 36, height: 42, fontSize: 13, fontFamily: "'JetBrains Mono', monospace" }}
          />
        </div>
        <button className="btn-primary" style={{ padding: "0 24px", height: 42, display: "flex", alignItems: "center", gap: 8 }}>
          <Server size={14} /> Trace Route
        </button>
      </div>

      {/* Summary bar */}
      <div className="card" style={{ padding: "16px 24px", marginBottom: 20 }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 0 }}>
          {[
            { label: "Total Hops", value: totalHops, color: "#e8eaf6" },
            { label: "Suspicious Hops", value: riskHops, color: "#e8284a" },
            { label: "Total Delivery Time", value: "4 seconds", color: "#e8eaf6" },
            { label: "TLS Encrypted Hops", value: `${hops.filter(h => h.tls).length}/${totalHops}`, color: "#16a34a" },
            { label: "Earliest Reliable Node", value: "Hop 2", color: "#4a7cff" },
          ].map((s, i) => (
            <div key={s.label} style={{ textAlign: "center", padding: "0 16px", borderRight: i < 4 ? "1px solid #c8cfe0" : "none" }}>
              <div style={{ fontSize: 22, fontWeight: 800, color: s.color }}>{s.value}</div>
              <div style={{ fontSize: 11, color: "#4a5a78", marginTop: 4 }}>{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Hop-by-hop trace */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 16, alignItems: "start" }}>
        <div>
          {hops.map((hop, i) => {
            const expanded = expandedHop === i;
            const color = riskColor(hop.risk);
            return (
              <div key={i}>
                <div
                  className="card"
                  style={{
                    padding: 0, overflow: "hidden", cursor: "pointer",
                    background: riskBg(hop.risk), borderColor: riskBorder(hop.risk),
                    transition: "box-shadow 0.15s"
                  }}
                  onClick={() => setExpandedHop(expanded ? null : i)}
                >
                  {/* Hop header */}
                  <div style={{ padding: "16px 20px", display: "flex", alignItems: "center", gap: 14 }}>
                    {/* Step badge */}
                    <div style={{
                      width: 36, height: 36, borderRadius: 8, flexShrink: 0,
                      background: `${color}15`, border: `2px solid ${color}40`,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      fontSize: 13, fontWeight: 800, color
                    }}>{hop.step}</div>

                    {/* Host info */}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: "#4a5a78", letterSpacing: "0.06em" }}>{hop.label.toUpperCase()}</span>
                        <span style={{
                          fontSize: 10, fontWeight: 700, padding: "1px 7px", borderRadius: 4,
                          background: `${color}15`, border: `1px solid ${color}30`, color
                        }}>{riskLabel(hop.risk)}</span>
                        {hop.tls && (
                          <span style={{ fontSize: 10, fontWeight: 600, padding: "1px 7px", borderRadius: 4, background: "rgba(22,163,74,0.1)", border: "1px solid rgba(22,163,74,0.25)", color: "#16a34a", display: "flex", alignItems: "center", gap: 3 }}>
                            <Wifi size={9} /> TLS
                          </span>
                        )}
                      </div>
                      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 600, color: "#e8eaf6" }}>{hop.host}</div>
                    </div>

                    {/* Quick info */}
                    <div style={{ display: "flex", gap: 24, flexShrink: 0, textAlign: "right" }}>
                      <div>
                        <div style={{ fontSize: 10, color: "#4a5a78" }}>IP</div>
                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, fontWeight: 600, color: "#4a7cff" }}>{hop.ip}</div>
                      </div>
                      <div>
                        <div style={{ fontSize: 10, color: "#4a5a78" }}>LOCATION</div>
                        <div style={{ fontSize: 12, color: "#8b96b8" }}>{hop.country}</div>
                      </div>
                      {hop.latency && (
                        <div>
                          <div style={{ fontSize: 10, color: "#4a5a78" }}>LATENCY</div>
                          <div style={{ fontSize: 12, fontWeight: 600, color: "#e8eaf6" }}>{hop.latency}</div>
                        </div>
                      )}
                      <div style={{ display: "flex", alignItems: "center" }}>
                        <span style={{ fontSize: 11, color: "#4a5a78", transform: expanded ? "rotate(180deg)" : "none", transition: "transform 0.2s", display: "inline-block" }}>▼</span>
                      </div>
                    </div>
                  </div>

                  {/* Flags row */}
                  {hop.flags.length > 0 && (
                    <div style={{ padding: "0 20px 14px", display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {hop.flags.map(flag => (
                        <span key={flag} style={{
                          fontSize: 11, padding: "2px 8px", borderRadius: 4,
                          background: `${color}10`, border: `1px solid ${color}25`, color
                        }}>{flag}</span>
                      ))}
                    </div>
                  )}

                  {/* Expanded detail */}
                  {expanded && (
                    <div style={{ borderTop: `1px solid ${riskBorder(hop.risk)}`, padding: "20px" }}>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
                        {/* Server details */}
                        <div>
                          <div style={{ fontSize: 12, fontWeight: 600, color: "#5a6a88", letterSpacing: "0.06em", marginBottom: 12 }}>SERVER DETAILS</div>
                          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                            {[
                              { label: "rDNS", value: hop.rdns },
                              { label: "ASN", value: hop.asn },
                              { label: "Organization", value: hop.org },
                              { label: "Protocol", value: `${hop.protocol} (port ${hop.port})` },
                              { label: "TLS", value: hop.tls ? "Encrypted" : "Plaintext" },
                              { label: "Timestamp", value: hop.timestamp },
                            ].map(f => (
                              <div key={f.label} style={{ display: "flex", gap: 12 }}>
                                <span style={{ fontSize: 12, color: "#4a5a78", width: 100, flexShrink: 0 }}>{f.label}</span>
                                <span style={{ fontFamily: f.label === "rDNS" || f.label === "ASN" ? "'JetBrains Mono', monospace" : undefined, fontSize: 12, color: "#8b96b8" }}>{f.value}</span>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* WHOIS snippet */}
                        <div>
                          <div style={{ fontSize: 12, fontWeight: 600, color: "#5a6a88", letterSpacing: "0.06em", marginBottom: 12 }}>WHOIS / REGISTRATION</div>
                          <div style={{ padding: "12px 14px", background: "#151c2f", borderRadius: 8, border: "1px solid #252e4a" }}>
                            <pre style={{ margin: 0, fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: "#8b96b8", lineHeight: 1.8, whiteSpace: "pre-wrap" }}>{hop.whois}</pre>
                          </div>
                          {(hop.risk === "critical" || hop.risk === "suspicious") && (
                            <div style={{ marginTop: 12, padding: "10px 12px", background: "rgba(232,40,74,0.05)", border: "1px solid rgba(232,40,74,0.2)", borderRadius: 6, display: "flex", gap: 8 }}>
                              <AlertTriangle size={13} color="#e8284a" style={{ flexShrink: 0, marginTop: 1 }} />
                              <span style={{ fontSize: 12, color: "#5a6a88" }}>This server has been associated with known threat campaigns. Block recommended.</span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Arrow between hops */}
                {i < hops.length - 1 && (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", padding: "6px 0", gap: 8 }}>
                    <div style={{ height: 1, width: 40, background: "#252e4a" }} />
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                      <ArrowDown size={14} color="#94a3b8" />
                      {hops[i + 1].latency && (
                        <span style={{ fontSize: 10, color: "#4a5a78", marginTop: 2 }}>{hops[i + 1].latency}</span>
                      )}
                    </div>
                    <div style={{ height: 1, width: 40, background: "#252e4a" }} />
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Right panel */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {/* Earliest reliable node */}
          <div className="card" style={{ padding: 20, background: "#fff5f6", borderColor: "#fcc8d0" }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#5a6a88", letterSpacing: "0.06em", marginBottom: 10 }}>EARLIEST RELIABLE NODE</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 15, fontWeight: 700, color: "#e8284a", marginBottom: 4 }}>185.220.101.47</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: "#5a6a88", marginBottom: 8 }}>mail.paypa1-secure.com</div>
            <div style={{ fontSize: 12, color: "#5a6a88", marginBottom: 12 }}>🇸🇬 Singapore · AS20473 · Vultr</div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <div style={{ flex: 1, height: 4, background: "#151c2f", borderRadius: 2 }}>
                <div style={{ height: "100%", width: "87%", background: "#f05a20", borderRadius: 2 }} />
              </div>
              <span style={{ fontSize: 11, fontWeight: 700, color: "#f05a20" }}>87% confidence</span>
            </div>
          </div>

          {/* Risk legend */}
          <div className="card" style={{ padding: 20 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#5a6a88", letterSpacing: "0.06em", marginBottom: 14 }}>HOP RISK LEGEND</div>
            {[
              { color: "#e8284a", label: "MALICIOUS", desc: "Confirmed threat infrastructure" },
              { color: "#f05a20", label: "SUSPICIOUS", desc: "Unverified / threat-linked relay" },
              { color: "#5a6a88", label: "NEUTRAL", desc: "CDN or intermediary" },
              { color: "#16a34a", label: "TRUSTED", desc: "Verified org mail server" },
            ].map(item => (
              <div key={item.label} style={{ display: "flex", gap: 10, marginBottom: 10 }}>
                <div style={{ width: 10, height: 10, borderRadius: 3, background: item.color, flexShrink: 0, marginTop: 3 }} />
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: item.color }}>{item.label}</div>
                  <div style={{ fontSize: 11, color: "#4a5a78" }}>{item.desc}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Disclaimer */}
          <div style={{ padding: "14px 16px", background: "rgba(74,124,255,0.06)", border: "1px solid rgba(74,124,255,0.18)", borderRadius: 10 }}>
            <div style={{ display: "flex", gap: 8 }}>
              <Info size={14} color="#4a7cff" style={{ flexShrink: 0, marginTop: 1 }} />
              <p style={{ margin: 0, fontSize: 12, color: "#5a6a88", lineHeight: 1.6 }}>
                Server trace is reconstructed from Received headers. Hop attribution reflects network infrastructure only and does not identify the physical sender.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
