import { ArrowLeft, MapPin, AlertTriangle, Info } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const relayNodes = [
  { label: "Sender", host: "paypa1-secure.com", ip: "—", country: "Unknown", time: "09:14:18", risk: "suspicious" },
  { label: "Mail Relay 1", host: "mail.paypa1-secure.com", ip: "185.220.101.47", country: "🇸🇬 SG", time: "09:14:20", risk: "critical" },
  { label: "Mail Relay 2", host: "mx.organization.com", ip: "203.0.113.12", country: "🇮🇳 IN", time: "09:14:22", risk: "safe" },
  { label: "Destination", host: "mail.organization.internal", ip: "10.0.0.5", country: "Internal", time: "09:14:23", risk: "safe" },
];

export default function IpGeolocation({ navigate }: Props) {
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 24, marginTop: -8 }}>
        <button className="btn-ghost" onClick={() => navigate("result")} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }}>
          <ArrowLeft size={14} /> Back to Result
        </button>
      </div>

      {/* IP summary card */}
      <div className="card threat-fail" style={{ padding: 24, marginBottom: 20 }}>
        <div style={{ display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 24, alignItems: "center" }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 11, color: "#5a6a88", marginBottom: 8 }}>SOURCE IP</div>
            <span className="mono" style={{ fontSize: 22, fontWeight: 700, color: "#4a9eff" }}>185.220.101.47</span>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 20 }}>
            {[
              { label: "Risk Level", value: "HIGH", color: "#ff3b5c" },
              { label: "Country", value: "Singapore 🇸🇬", color: "#e8eaf6" },
              { label: "City", value: "Singapore", color: "#8b96b8" },
              { label: "ISP", value: "AS-CHOOPA LLC", color: "#8b96b8" },
              { label: "Organization", value: "Vultr Holdings LLC", color: "#8b96b8" },
              { label: "ASN", value: "AS20473", color: "#4a9eff" },
            ].map(f => (
              <div key={f.label}>
                <div style={{ fontSize: 11, color: "#5a6a88", marginBottom: 4 }}>{f.label}</div>
                <div className="mono" style={{ fontSize: 13, fontWeight: 600, color: f.color }}>{f.value}</div>
              </div>
            ))}
          </div>
          <span className="badge-critical" style={{ padding: "4px 12px", borderRadius: 6, fontSize: 12, fontWeight: 700, alignSelf: "flex-start" }}>HIGH RISK</span>
        </div>
      </div>

      {/* Map + relay */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 16, marginBottom: 20 }}>
        {/* Map visualization */}
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 16 }}>Geographic Origin</div>
          {/* SVG world map approximation */}
          <div style={{ position: "relative", height: 240, background: "#151c2f", borderRadius: 10, overflow: "hidden", border: "1px solid #252e4a" }}>
            <svg viewBox="0 0 800 400" style={{ width: "100%", height: "100%", opacity: 0.4 }}>
              {/* Simplified continent outlines */}
              <path d="M80,120 Q120,100 160,110 Q180,140 160,170 Q140,190 100,180 Q70,160 80,120Z" fill="none" stroke="#b4bdd4" strokeWidth="1.5" />
              <path d="M200,80 Q280,60 360,80 Q400,100 410,140 Q380,180 320,190 Q260,185 230,160 Q200,130 200,80Z" fill="none" stroke="#b4bdd4" strokeWidth="1.5" />
              <path d="M220,200 Q260,195 300,210 Q320,240 300,270 Q260,290 220,270 Q200,245 220,200Z" fill="none" stroke="#b4bdd4" strokeWidth="1.5" />
              <path d="M440,100 Q500,80 560,90 Q600,110 620,150 Q610,190 570,200 Q510,205 470,180 Q440,155 440,100Z" fill="none" stroke="#b4bdd4" strokeWidth="1.5" />
              <path d="M440,210 Q500,200 560,215 Q600,240 590,280 Q550,310 490,310 Q450,290 435,260 Q430,235 440,210Z" fill="none" stroke="#b4bdd4" strokeWidth="1.5" />
              <path d="M610,130 Q660,110 710,130 Q740,160 720,200 Q680,220 640,200 Q610,175 610,130Z" fill="none" stroke="#b4bdd4" strokeWidth="1.5" />
              {/* Grid lines */}
              {[100,200,300].map(y => <line key={y} x1="0" y1={y} x2="800" y2={y} stroke="#252e4a" strokeWidth="0.5" />)}
              {[100,200,300,400,500,600,700].map(x => <line key={x} x1={x} y1="0" x2={x} y2="400" stroke="#252e4a" strokeWidth="0.5" />)}
            </svg>
            {/* Origin marker - Singapore approx position */}
            <div style={{ position: "absolute", left: "73%", top: "45%", transform: "translate(-50%,-50%)" }}>
              <div style={{ width: 14, height: 14, borderRadius: "50%", background: "#ff3b5c", boxShadow: "0 0 12px rgba(255,59,92,0.6)", border: "2px solid #fff", cursor: "pointer" }} />
              <div style={{ position: "absolute", top: "100%", left: "50%", transform: "translateX(-50%)", marginTop: 6, whiteSpace: "nowrap" }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: "#ff3b5c", textAlign: "center" }}>185.220.101.47</div>
                <div style={{ fontSize: 10, color: "#5a6a88", textAlign: "center" }}>Singapore</div>
              </div>
            </div>
            {/* Destination marker */}
            <div style={{ position: "absolute", left: "62%", top: "35%", transform: "translate(-50%,-50%)" }}>
              <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#2dc77a", border: "2px solid #fff" }} />
            </div>
            {/* Connection line */}
            <svg style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none" }}>
              <line x1="62%" y1="35%" x2="73%" y2="45%" stroke="rgba(255,59,92,0.3)" strokeWidth="1.5" strokeDasharray="4 3" />
            </svg>
          </div>

          <div style={{ marginTop: 16, display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ flex: 1, padding: "10px 14px", background: "#151c2f", borderRadius: 8, border: "1px solid #252e4a" }}>
              <div style={{ fontSize: 11, color: "#5a6a88", marginBottom: 4 }}>GEOLOCATION CONFIDENCE</div>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{ flex: 1, height: 4, background: "#1e2848", borderRadius: 2 }}>
                  <div style={{ height: "100%", width: "82%", background: "#f5a623", borderRadius: 2 }} />
                </div>
                <span style={{ fontSize: 13, fontWeight: 700, color: "#f5a623" }}>82%</span>
              </div>
            </div>
          </div>

          <div style={{ marginTop: 12, padding: "10px 14px", background: "rgba(74,124,255,0.06)", border: "1px solid rgba(74,124,255,0.15)", borderRadius: 8, display: "flex", gap: 10 }}>
            <Info size={14} color="#4a9eff" style={{ flexShrink: 0, marginTop: 1 }} />
            <p style={{ fontSize: 12, color: "#5a6a88", margin: 0, lineHeight: 1.6 }}>
              Geolocation indicates probable network location and does not establish the physical identity of the sender. IP geolocation accuracy is limited to city/region level and may be affected by VPN or proxy usage.
            </p>
          </div>
        </div>

        {/* Relay chain */}
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 20 }}>Relay Path</div>
          <div style={{ display: "flex", flexDirection: "column" }}>
            {relayNodes.map((node, i) => (
              <div key={i} style={{ display: "flex", gap: 12 }}>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                  <div style={{
                    width: 28, height: 28, borderRadius: "50%", flexShrink: 0,
                    background: node.risk === "critical" ? "rgba(255,59,92,0.15)" : node.risk === "suspicious" ? "rgba(245,166,35,0.15)" : "rgba(45,199,122,0.1)",
                    border: `2px solid ${node.risk === "critical" ? "#ff3b5c" : node.risk === "suspicious" ? "#f5a623" : "#2dc77a"}`,
                    display: "flex", alignItems: "center", justifyContent: "center"
                  }}>
                    <MapPin size={12} color={node.risk === "critical" ? "#ff3b5c" : node.risk === "suspicious" ? "#f5a623" : "#2dc77a"} />
                  </div>
                  {i < relayNodes.length - 1 && <div style={{ width: 2, height: 32, background: "#252e4a", marginTop: 4 }} />}
                </div>
                <div style={{ paddingBottom: i < relayNodes.length - 1 ? 20 : 0 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: "#5a6a88", letterSpacing: "0.06em" }}>{node.label}</div>
                  <div className="mono" style={{ fontSize: 12, color: "#8b96b8", marginTop: 2 }}>{node.host}</div>
                  {node.ip !== "—" && <div className="mono" style={{ fontSize: 11, color: "#4a9eff" }}>{node.ip}</div>}
                  <div style={{ fontSize: 11, color: "#4a5a78", marginTop: 2 }}>{node.country} · {node.time}</div>
                </div>
              </div>
            ))}
          </div>

          <div style={{ marginTop: 20, padding: "14px 16px", background: "rgba(255,59,92,0.06)", borderRadius: 8, border: "1px solid rgba(255,59,92,0.2)" }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: "#5a6a88", letterSpacing: "0.06em", marginBottom: 8 }}>EARLIEST RELIABLE SENDING NODE</div>
            <div className="mono" style={{ fontSize: 14, fontWeight: 700, color: "#ff7a4a" }}>185.220.101.47</div>
            <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 4 }}>Singapore · AS20473 · Confidence: 87%</div>
          </div>
        </div>
      </div>

      {/* Threat history */}
      <div className="card" style={{ padding: 24 }}>
        <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 16 }}>IP Threat History</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
          {[
            { label: "First Seen", value: "14 days ago", color: "#8b96b8" },
            { label: "Last Seen", value: "2 hours ago", color: "#ff3b5c" },
            { label: "Related Campaigns", value: "4 campaigns", color: "#f5a623" },
            { label: "Threat Feeds", value: "3 sources", color: "#9b6fff" },
          ].map(f => (
            <div key={f.label} style={{ padding: "16px 20px", background: "#151c2f", borderRadius: 8, border: "1px solid #252e4a" }}>
              <div style={{ fontSize: 11, color: "#5a6a88", marginBottom: 8 }}>{f.label}</div>
              <div style={{ fontSize: 16, fontWeight: 700, color: f.color }}>{f.value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
