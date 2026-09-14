import { useState } from "react";

const tabs = ["General","Detection","Threat Intelligence","Notifications","Privacy","Users","Audit Logs"];

const auditLogs = [
  { time: "09:20:14", user: "Analyst 01", action: "Generated report", resource: "CASE-2026-001284", ip: "10.0.1.42" },
  { time: "08:56:03", user: "Analyst 01", action: "Added evidence", resource: "CASE-2026-001284", ip: "10.0.1.42" },
  { time: "08:47:11", user: "System", action: "Case created", resource: "CASE-2026-001284", ip: "System" },
  { time: "08:42:30", user: "Analyst 01", action: "Email analyzed", resource: "CASE-2026-001284", ip: "10.0.1.42" },
  { time: "07:15:48", user: "Analyst 02", action: "Resolved alert", resource: "ALERT-8842", ip: "10.0.1.55" },
  { time: "06:58:22", user: "Analyst 02", action: "Analyzed email", resource: "EML-003912", ip: "10.0.1.55" },
];

export default function Settings() {
  const [tab, setTab] = useState("General");
  const [orgName, setOrgName] = useState("Acme Corporation");
  const [timezone, setTimezone] = useState("Asia/Kolkata (IST, UTC+5:30)");
  const [riskThreshold, setRiskThreshold] = useState(60);
  const [phishingSens, setPhishingSens] = useState(80);
  const [impersonationSens, setImpersonationSens] = useState(75);
  const [domainThreshold, setDomainThreshold] = useState(85);
  const [retention, setRetention] = useState("90");
  const [piiMask, setPiiMask] = useState(true);

  return (
    <div>
      <p style={{ margin: "0 0 24px", fontSize: 14, color: "#5a6a88", marginTop: -8 }}>
        Configure platform behavior, detection thresholds, and organization settings.
      </p>

      <div style={{ display: "flex", gap: 0, marginBottom: 24, borderBottom: "1px solid #252e4a" }}>
        {tabs.map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding: "9px 16px", border: "none", cursor: "pointer", fontSize: 13,
            background: "transparent", fontWeight: tab === t ? 600 : 400,
            color: tab === t ? "#111827" : "#64748b",
            borderBottom: tab === t ? "2px solid #4a7cff" : "2px solid transparent",
            whiteSpace: "nowrap"
          }}>{t}</button>
        ))}
      </div>

      {tab === "General" && (
        <div className="card" style={{ padding: 32, maxWidth: 600 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 24 }}>Organization Settings</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            <div>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, color: "#8b96b8", marginBottom: 8 }}>Organization Name</label>
              <input value={orgName} onChange={e => setOrgName(e.target.value)} style={{ width: "100%", height: 40, padding: "0 12px", fontSize: 14 }} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, color: "#8b96b8", marginBottom: 8 }}>Timezone</label>
              <select value={timezone} onChange={e => setTimezone(e.target.value)} style={{ width: "100%", height: 40, padding: "0 12px", fontSize: 14 }}>
                <option>Asia/Kolkata (IST, UTC+5:30)</option>
                <option>UTC</option>
                <option>America/New_York (EST, UTC-5:00)</option>
                <option>Europe/London (GMT, UTC+0:00)</option>
              </select>
            </div>
            <div>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, color: "#8b96b8", marginBottom: 8 }}>
                Default Risk Threshold: <span style={{ color: "#4a7cff", fontWeight: 700 }}>{riskThreshold}</span>
              </label>
              <input type="range" min={0} max={100} value={riskThreshold} onChange={e => setRiskThreshold(+e.target.value)} style={{ width: "100%", accentColor: "#4a7cff" }} />
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "#4a5a78", marginTop: 4 }}>
                <span>0 — Alert everything</span><span>100 — Only critical</span>
              </div>
            </div>
          </div>
          <button className="btn-primary" style={{ marginTop: 24 }}>Save Changes</button>
        </div>
      )}

      {tab === "Detection" && (
        <div className="card" style={{ padding: 32, maxWidth: 600 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 24 }}>Detection Sensitivity</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            {[
              { label: "Phishing Detection Sensitivity", val: phishingSens, setter: setPhishingSens },
              { label: "Impersonation Detection Sensitivity", val: impersonationSens, setter: setImpersonationSens },
              { label: "Domain Similarity Threshold", val: domainThreshold, setter: setDomainThreshold },
            ].map(s => (
              <div key={s.label}>
                <label style={{ display: "block", fontSize: 13, fontWeight: 500, color: "#8b96b8", marginBottom: 8 }}>
                  {s.label}: <span style={{ color: "#4a7cff", fontWeight: 700 }}>{s.val}%</span>
                </label>
                <input type="range" min={0} max={100} value={s.val} onChange={e => s.setter(+e.target.value)} style={{ width: "100%", accentColor: "#4a7cff" }} />
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "#4a5a78", marginTop: 4 }}>
                  <span>Low sensitivity</span><span>High sensitivity</span>
                </div>
              </div>
            ))}
            <div>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, color: "#8b96b8", marginBottom: 8 }}>URL Detection</label>
              <select style={{ width: "100%", height: 40, padding: "0 12px", fontSize: 14 }}>
                <option>Aggressive — flag all redirects</option>
                <option>Standard — flag known bad patterns</option>
                <option>Conservative — flag confirmed malicious only</option>
              </select>
            </div>
          </div>
          <button className="btn-primary" style={{ marginTop: 24 }}>Save Changes</button>
        </div>
      )}

      {tab === "Privacy" && (
        <div className="card" style={{ padding: 32, maxWidth: 600 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6", marginBottom: 24 }}>Data & Privacy</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            <div>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, color: "#8b96b8", marginBottom: 8 }}>Data Retention (days)</label>
              <select value={retention} onChange={e => setRetention(e.target.value)} style={{ width: "100%", height: 40, padding: "0 12px", fontSize: 14 }}>
                {["30","60","90","180","365"].map(v => <option key={v}>{v}</option>)}
              </select>
            </div>
            <label style={{ display: "flex", alignItems: "center", gap: 12, cursor: "pointer" }}>
              <input type="checkbox" checked={piiMask} onChange={e => setPiiMask(e.target.checked)} style={{ width: 16, height: 16, accentColor: "#4a7cff" }} />
              <div>
                <div style={{ fontSize: 13, fontWeight: 500, color: "#e8eaf6" }}>Enable PII Masking</div>
                <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 2 }}>Automatically mask recipient email addresses in reports and logs</div>
              </div>
            </label>
          </div>
          <button className="btn-primary" style={{ marginTop: 24 }}>Save Changes</button>
        </div>
      )}

      {tab === "Audit Logs" && (
        <div className="card" style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "20px 24px 16px", borderBottom: "1px solid #252e4a" }}>
            <div style={{ fontSize: 15, fontWeight: 600, color: "#e8eaf6" }}>Audit Logs</div>
            <div style={{ fontSize: 12, color: "#5a6a88", marginTop: 4 }}>All user actions are logged and immutable</div>
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #252e4a" }}>
                {["Timestamp","User","Action","Resource","IP"].map(h => (
                  <th key={h} style={{ padding: "10px 16px", textAlign: "left", fontSize: 11, color: "#5a6a88", fontWeight: 600, letterSpacing: "0.04em" }}>{h.toUpperCase()}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {auditLogs.map((log, i) => (
                <tr key={i} className="row-hover" style={{ borderBottom: i < auditLogs.length - 1 ? "1px solid #c8cfe0" : "none" }}>
                  <td style={{ padding: "10px 16px" }}><span className="mono" style={{ fontSize: 12, color: "#5a6a88" }}>{log.time}</span></td>
                  <td style={{ padding: "10px 16px", fontSize: 13, color: "#8b96b8" }}>{log.user}</td>
                  <td style={{ padding: "10px 16px", fontSize: 13, color: "#e8eaf6" }}>{log.action}</td>
                  <td style={{ padding: "10px 16px" }}><span className="mono" style={{ fontSize: 12, color: "#4a9eff" }}>{log.resource}</span></td>
                  <td style={{ padding: "10px 16px" }}><span className="mono" style={{ fontSize: 12, color: "#5a6a88" }}>{log.ip}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!["General","Detection","Privacy","Audit Logs"].includes(tab) && (
        <div className="card" style={{ padding: 32, maxWidth: 600 }}>
          <div style={{ fontSize: 14, color: "#5a6a88", textAlign: "center", padding: "40px 0" }}>
            {tab} settings are available in the full enterprise configuration.
          </div>
        </div>
      )}
    </div>
  );
}
