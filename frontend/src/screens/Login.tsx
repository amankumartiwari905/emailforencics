import { useState } from "react";
import { Shield, Mail, Lock, Eye, EyeOff, AlertCircle } from "lucide-react";

interface Props {
  onLogin: () => void;
}

export default function Login({ onLogin }: Props) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [remember, setRemember] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setTimeout(() => { setLoading(false); onLogin(); }, 1200);
  };

  return (
    <div style={{
      height: "100%", display: "flex", background: "#0b0d14", minHeight: "100vh"
    }}>
      {/* Left */}
      <div style={{
        flex: 1, background: "linear-gradient(135deg, #0d1020 0%, #101628 50%, #0d1020 100%)",
        borderRight: "1px solid #1e2235", display: "flex", flexDirection: "column",
        justifyContent: "center", padding: "60px 72px", position: "relative", overflow: "hidden"
      }}>
        {/* Abstract background elements */}
        <div style={{ position: "absolute", inset: 0, overflow: "hidden", pointerEvents: "none" }}>
          {[...Array(6)].map((_, i) => (
            <div key={i} style={{
              position: "absolute",
              width: 300 + i * 80,
              height: 300 + i * 80,
              borderRadius: "50%",
              border: `1px solid rgba(74,124,255,${0.03 + i * 0.015})`,
              left: `${-10 + i * 8}%`,
              top: `${20 + i * 5}%`,
              transform: "translate(-50%, -50%)"
            }} />
          ))}
          {/* Node dots */}
          {[
            { x: "20%", y: "25%" }, { x: "65%", y: "15%" }, { x: "80%", y: "45%" },
            { x: "30%", y: "70%" }, { x: "72%", y: "75%" }, { x: "50%", y: "40%" },
          ].map((pos, i) => (
            <div key={i} style={{
              position: "absolute", left: pos.x, top: pos.y,
              width: 6, height: 6, borderRadius: "50%",
              background: `rgba(74,124,255,${0.15 + i * 0.05})`
            }} />
          ))}
          {/* SVG connections */}
          <svg style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }}>
            <line x1="20%" y1="25%" x2="50%" y2="40%" stroke="rgba(74,124,255,0.06)" strokeWidth="1" />
            <line x1="65%" y1="15%" x2="50%" y2="40%" stroke="rgba(74,124,255,0.06)" strokeWidth="1" />
            <line x1="80%" y1="45%" x2="50%" y2="40%" stroke="rgba(74,124,255,0.06)" strokeWidth="1" />
            <line x1="30%" y1="70%" x2="50%" y2="40%" stroke="rgba(74,124,255,0.06)" strokeWidth="1" />
            <line x1="72%" y1="75%" x2="50%" y2="40%" stroke="rgba(74,124,255,0.06)" strokeWidth="1" />
          </svg>
        </div>

        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 64, position: "relative" }}>
          <div style={{
            width: 48, height: 48, borderRadius: 12,
            background: "linear-gradient(135deg, #4a7cff 0%, #7a5cff 100%)",
            display: "flex", alignItems: "center", justifyContent: "center"
          }}>
            <Shield size={24} color="#fff" />
          </div>
          <div>
            <div style={{ fontSize: 20, fontWeight: 700, color: "#e8eaf0" }}>MailTrace AI</div>
            <div style={{ fontSize: 11, color: "#4a7cff", letterSpacing: "0.12em", fontWeight: 500 }}>THREAT INTELLIGENCE PLATFORM</div>
          </div>
        </div>

        <div style={{ position: "relative" }}>
          <h1 style={{ fontSize: 40, fontWeight: 700, color: "#e8eaf0", lineHeight: 1.2, margin: "0 0 20px" }}>
            Investigate Every<br />
            <span style={{ color: "#4a7cff" }}>Suspicious Email.</span>
          </h1>
          <p style={{ fontSize: 16, color: "#8b92a8", lineHeight: 1.7, maxWidth: 420, margin: "0 0 48px" }}>
            AI-powered threat detection and forensic intelligence for modern email security. Built for SOC analysts and incident response teams.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {[
              { icon: "🛡️", text: "SPF / DKIM / DMARC authentication analysis" },
              { icon: "🔍", text: "Phishing and impersonation detection" },
              { icon: "🌐", text: "IP geolocation and relay path tracing" },
              { icon: "📋", text: "Forensic-grade evidence chain of custody" },
            ].map((feat, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{
                  width: 36, height: 36, borderRadius: 8, background: "rgba(74,124,255,0.08)",
                  border: "1px solid rgba(74,124,255,0.15)", display: "flex", alignItems: "center",
                  justifyContent: "center", fontSize: 16, flexShrink: 0
                }}>{feat.icon}</div>
                <span style={{ fontSize: 14, color: "#8b92a8" }}>{feat.text}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right */}
      <div style={{ width: 480, display: "flex", alignItems: "center", justifyContent: "center", padding: 40 }}>
        <div style={{ width: "100%", maxWidth: 400 }}>
          <div style={{ marginBottom: 32 }}>
            <h2 style={{ fontSize: 22, fontWeight: 700, color: "#e8eaf0", margin: "0 0 8px" }}>Sign In</h2>
            <p style={{ fontSize: 14, color: "#5a6175", margin: 0 }}>Access your security workspace</p>
          </div>

          <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, color: "#8b92a8", marginBottom: 6 }}>Work Email</label>
              <div style={{ position: "relative" }}>
                <Mail size={14} color="#5a6175" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }} />
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="analyst@organization.com"
                  style={{ width: "100%", paddingLeft: 36, paddingRight: 12, height: 42, fontSize: 14 }}
                  required
                />
              </div>
            </div>

            <div>
              <label style={{ display: "block", fontSize: 13, fontWeight: 500, color: "#8b92a8", marginBottom: 6 }}>Password</label>
              <div style={{ position: "relative" }}>
                <Lock size={14} color="#5a6175" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)" }} />
                <input
                  type={showPw ? "text" : "password"}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  style={{ width: "100%", paddingLeft: 36, paddingRight: 40, height: 42, fontSize: 14 }}
                  required
                />
                <button type="button" onClick={() => setShowPw(!showPw)} style={{ position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", cursor: "pointer", color: "#5a6175" }}>
                  {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}>
                <input type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)} style={{ width: 14, height: 14, accentColor: "#4a7cff" }} />
                <span style={{ fontSize: 13, color: "#8b92a8" }}>Remember me</span>
              </label>
              <button type="button" style={{ background: "none", border: "none", fontSize: 13, color: "#4a7cff", cursor: "pointer" }}>Forgot password?</button>
            </div>

            <button
              type="submit"
              className="btn-primary"
              disabled={loading}
              style={{ width: "100%", height: 44, fontSize: 15, marginTop: 4 }}
            >
              {loading ? (
                <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8 }}>
                  <span style={{ width: 14, height: 14, border: "2px solid rgba(255,255,255,0.3)", borderTopColor: "#fff", borderRadius: "50%", animation: "spin 0.7s linear infinite", display: "inline-block" }} />
                  Authenticating...
                </span>
              ) : "Sign In"}
            </button>
          </form>

          <div style={{ marginTop: 24, padding: "16px 20px", background: "rgba(74,124,255,0.06)", border: "1px solid rgba(74,124,255,0.15)", borderRadius: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
              <Shield size={12} color="#4a7cff" />
              <span style={{ fontSize: 11, fontWeight: 600, color: "#4a7cff", letterSpacing: "0.05em" }}>SECURE ACCESS</span>
            </div>
            <p style={{ fontSize: 12, color: "#5a6175", margin: 0, lineHeight: 1.6 }}>
              This platform is restricted to authorized security analysts. All access is logged and monitored.
            </p>
          </div>
        </div>
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
