import { X, CheckCircle, AlertTriangle, Download, FolderPlus, Share2, RefreshCw, ChevronRight } from "lucide-react";
import type { Screen } from "../App";

interface Props { navigate: (s: Screen) => void; }

const indicators = [
  { label: "Sender Spoofing", status: "DETECTED", fail: true },
  { label: "SPF", status: "FAIL", fail: true },
  { label: "DKIM", status: "FAIL", fail: true },
  { label: "DMARC", status: "FAIL", fail: true },
  { label: "Reply-To Mismatch", status: "DETECTED", fail: true },
  { label: "Suspicious URL", status: "DETECTED", fail: true },
  { label: "Domain Lookalike", status: "HIGH", fail: true },
  { label: "Urgency Language", status: "DETECTED", fail: true },
];

function RiskGauge({ score }: { score: number }) {
  const r = 70;
  const cx = 90;
  const cy = 90;
  const startAngle = Math.PI * 0.75;
  const endAngle = Math.PI * 2.25;
  const totalArc = endAngle - startAngle;
  const fillArc = (score / 100) * totalArc;

  const polarToXY = (angle: number) => ({
    x: cx + r * Math.cos(angle),
    y: cy + r * Math.sin(angle),
  });

  const start = polarToXY(startAngle);
  const end = polarToXY(endAngle);
  const fillEnd = polarToXY(startAngle + fillArc);
  const largeArc = fillArc > Math.PI ? 1 : 0;

  return (
    <svg width={180} height={140} viewBox="0 0 180 140">
      {/* Track */}
      <path
        d={`M ${polarToXY(startAngle).x} ${polarToXY(startAngle).y} A ${r} ${r} 0 1 1 ${end.x} ${end.y}`}
        fill="none" stroke="#252e4a" strokeWidth={10} strokeLinecap="round"
      />
      {/* Fill */}
      <path
        d={`M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${fillEnd.x} ${fillEnd.y}`}
        fill="none" stroke="#ff3b5c" strokeWidth={10} strokeLinecap="round"
      />
      {/* Score */}
      <text x={cx} y={cy + 8} textAnchor="middle" fill="#ff3b5c" fontSize={36} fontWeight={700} fontFamily="Inter">{score}</text>
      <text x={cx} y={cy + 28} textAnchor="middle" fill="#64748b" fontSize={11} fontFamily="Inter">/ 100</text>
    </svg>
  );
}

export default function AnalysisResult({ navigate }: Props) {
  return (
    <div>
      {/* Header actions */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 24, marginTop: -8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="mono" style={{ fontSize: 12, color: "#5a6a88" }}>CASE-2026-001284</span>
          <span className="badge-critical" style={{ padding: "2px 10px", borderRadius: 4, fontSize: 11, fontWeight: 700 }}>HIGH RISK</span>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn-secondary" style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }} onClick={() => navigate("forensic-report")}>
            <Download size={13} /> Export Report
          </button>
          <button className="btn-primary" style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13 }} onClick={() => navigate("case-details")}>
            <FolderPlus size={13} /> Create Case
          </button>
          <button className="btn-secondary" style={{ padding: "9px 12px" }}><Share2 size={13} /></button>
          <button className="btn-secondary" style={{ padding: "9px 12px" }}><RefreshCw size={13} /></button>
        </div>
      </div>

      {/* Top row */}
      <div style={{ display: "grid", gridTemplateColumns: "320px 1fr", gap: 16, marginBottom: 16 }}>
        {/* Risk gauge card */}
        <div className="card threat-fail" style={{ padding: 28, display: "flex", flexDirection: "column", alignItems: "center" }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: "#5a6a88", letterSpacing: "0.08em", marginBottom: 4 }}>THREAT RISK SCORE</div>
          <RiskGauge score={92} />
          <div style={{ fontSize: 22, fontWeight: 800, color: "#ff3b5c", marginBottom: 4 }}>HIGH RISK</div>
          <div style={{ fontSize: 14, color: "#8b96b8", marginBottom: 12 }}>Phishing / Impersonation</div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 14px", background: "rgba(255,59,92,0.08)", borderRadius: 20, border: "1px solid rgba(255,59,92,0.2)" }}>
            <span style={{ fontSize: 12, color: "#8b96b8" }}>AI Confidence:</span>
            <span style={{ fontSize: 13, fontWeight: 700, color: "#ff3b5c" }}>94%</span>
          </div>
        </div>

        {/* Explanation + indicators */}
        <div className="card" style={{ padding: 28 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 12 }}>Threat Assessment</div>
          <div style={{ fontSize: 14, color: "#8b96b8", lineHeight: 1.7, marginBottom: 24, padding: "14px 16px", background: "#151c2f", borderRadius: 8, borderLeft: "3px solid #ff3b5c" }}>
            Multiple indicators suggest this email is attempting to impersonate a trusted organization and redirect the recipient to a suspicious domain. The sending IP has been previously associated with phishing infrastructure, and the domain was registered 12 days ago as a PayPal lookalike.
          </div>

          <div style={{ fontSize: 13, fontWeight: 600, color: "#5a6a88", letterSpacing: "0.06em", marginBottom: 14 }}>THREAT INDICATORS</div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
            {indicators.map((ind) => (
              <div key={ind.label} style={{
                padding: "12px 14px", borderRadius: 8,
                background: ind.fail ? "rgba(255,59,92,0.06)" : "rgba(45,199,122,0.06)",
                border: `1px solid ${ind.fail ? "rgba(255,59,92,0.2)" : "rgba(45,199,122,0.2)"}`,
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
                  {ind.fail ? <X size={12} color="#ff3b5c" /> : <CheckCircle size={12} color="#2dc77a" />}
                  <span style={{ fontSize: 11, color: "#5a6a88" }}>{ind.label}</span>
                </div>
                <div style={{ fontSize: 12, fontWeight: 700, color: ind.fail ? "#ff3b5c" : "#2dc77a" }}>{ind.status}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Navigation tabs to sub-screens */}
      <div className="card" style={{ padding: 20, marginBottom: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: "#5a6a88", letterSpacing: "0.06em", marginBottom: 14 }}>DETAILED ANALYSIS SECTIONS</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}>
          {[
            { label: "Header Forensics", sub: "SPF · DKIM · DMARC · Relay analysis", screen: "header-forensics" as Screen, color: "#f5a623" },
            { label: "URL & Domain Intel", sub: "3 URLs · 1 malicious domain detected", screen: "url-domain" as Screen, color: "#ff3b5c" },
            { label: "IP & GeoLocation", sub: "Origin: Singapore · High risk IP", screen: "ip-geo" as Screen, color: "#4a9eff" },
            { label: "Relay Path", sub: "3 relay hops · Suspicious hop detected", screen: "relay-path" as Screen, color: "#9b6fff" },
          ].map(item => (
            <button
              key={item.label}
              onClick={() => navigate(item.screen)}
              style={{
                padding: "16px", borderRadius: 10, border: `1px solid #252e4a`,
                background: "#151c2f", cursor: "pointer", textAlign: "left",
                display: "flex", alignItems: "center", justifyContent: "space-between",
                transition: "all 0.15s"
              }}
              onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = item.color + "50"; (e.currentTarget as HTMLButtonElement).style.background = "#1e2640"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = "#252e4a"; (e.currentTarget as HTMLButtonElement).style.background = "#151c2f"; }}
            >
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: "#e8eaf6", marginBottom: 4 }}>{item.label}</div>
                <div style={{ fontSize: 11, color: "#5a6a88" }}>{item.sub}</div>
              </div>
              <ChevronRight size={14} color={item.color} />
            </button>
          ))}
        </div>
      </div>

      {/* Email overview */}
      <div className="card" style={{ padding: 24 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6" }}>Email Overview</div>
          <button className="btn-ghost" style={{ fontSize: 12 }}>View Raw Email</button>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 0 }}>
          {[
            { label: "From", value: "support@paypa1-secure.com", mono: true, flag: true },
            { label: "Display Name", value: "PayPal Support", mono: false, flag: true },
            { label: "Reply-To", value: "security-alert@paypa1-secure.com", mono: true, flag: true },
            { label: "Return-Path", value: "mailer@mx.paypa1-secure.com", mono: true, flag: true },
            { label: "Subject", value: '"Urgent: Verify Your Account"', mono: false, flag: false },
            { label: "Date", value: "Sun, 31 Aug 2026 09:14:22 +0000", mono: true, flag: false },
            { label: "Message-ID", value: "<CA+xyz123@mail.paypa1-secure.com>", mono: true, flag: false },
            { label: "Attachments", value: "invoice.pdf (142 KB)", mono: false, flag: true },
          ].map((field, i) => (
            <div key={i} style={{ display: "flex", padding: "12px 0", borderBottom: i < 7 ? "1px solid #252e4a" : "none", gap: 16 }}>
              <span style={{ fontSize: 12, color: "#5a6a88", width: 120, flexShrink: 0, paddingTop: 1 }}>{field.label}</span>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span className={field.mono ? "mono" : ""} style={{ fontSize: 13, color: field.flag ? "#ff7a4a" : "#c8d0e8" }}>{field.value}</span>
                {field.flag && <AlertTriangle size={12} color="#f5a623" />}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
