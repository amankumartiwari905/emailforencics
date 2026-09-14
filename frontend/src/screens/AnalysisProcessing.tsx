import { useEffect, useState } from "react";
import { CheckCircle, Circle, Loader } from "lucide-react";

interface Props { onComplete: () => void; }

const steps = [
  { label: "Email parsed", time: "12:42:01" },
  { label: "Headers extracted", time: "12:42:01" },
  { label: "Authentication analyzed", time: "12:42:02" },
  { label: "Threat detection running", time: "12:42:03" },
  { label: "URL intelligence", time: "12:42:04" },
  { label: "IP geolocation", time: "12:42:05" },
  { label: "Threat intelligence correlation", time: "12:42:06" },
];

const logs = [
  { time: "12:42:01", msg: "Parsing email MIME structure (multipart/mixed)" },
  { time: "12:42:01", msg: "Extracting Received headers — found 3 relay hops" },
  { time: "12:42:02", msg: "Checking SPF record for domain paypa1-secure.com" },
  { time: "12:42:02", msg: "Validating DKIM signature — header.d=paypa1-secure.com" },
  { time: "12:42:02", msg: "Evaluating DMARC policy — p=none alignment check" },
  { time: "12:42:03", msg: "Running classification model v2.4.1 (phishing/BEC/spoofing)" },
  { time: "12:42:03", msg: "Analyzing 3 URLs found in message body" },
  { time: "12:42:04", msg: "Extracting source IP from earliest Received header" },
  { time: "12:42:04", msg: "Querying geolocation: 185.220.101.47 → Singapore (AS-CHOOPA)" },
  { time: "12:42:05", msg: "Checking domain age: paypa1-secure.com — registered 12 days ago" },
  { time: "12:42:06", msg: "Correlating indicators with threat intelligence feeds" },
  { time: "12:42:06", msg: "Analysis complete — generating threat report" },
];

export default function AnalysisProcessing({ onComplete }: Props) {
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState(0);
  const [visibleLogs, setVisibleLogs] = useState<typeof logs>([]);

  useEffect(() => {
    const total = 3200;
    const interval = 50;
    let elapsed = 0;

    const timer = setInterval(() => {
      elapsed += interval;
      const pct = Math.min((elapsed / total) * 100, 100);
      setProgress(pct);
      setCurrentStep(Math.floor((pct / 100) * steps.length));

      const logIdx = Math.floor((pct / 100) * logs.length);
      setVisibleLogs(logs.slice(0, logIdx + 1));

      if (elapsed >= total) {
        clearInterval(timer);
        setTimeout(onComplete, 400);
      }
    }, interval);

    return () => clearInterval(timer);
  }, [onComplete]);

  return (
    <div style={{ maxWidth: 720, margin: "0 auto", paddingTop: 20 }}>
      {/* Header */}
      <div style={{ textAlign: "center", marginBottom: 40 }}>
        <div style={{ width: 60, height: 60, borderRadius: "50%", background: "rgba(74,124,255,0.1)", border: "1px solid rgba(74,124,255,0.2)", margin: "0 auto 16px", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Loader size={24} color="#4a7cff" style={{ animation: "spin 1s linear infinite" }} />
        </div>
        <h2 style={{ fontSize: 22, fontWeight: 700, color: "#e8eaf6", margin: "0 0 8px" }}>Analyzing Email</h2>
        <p style={{ fontSize: 14, color: "#5a6a88", margin: 0 }}>Processing email and running threat detection pipeline</p>
      </div>

      {/* Progress bar */}
      <div style={{ marginBottom: 36 }}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
          <span style={{ fontSize: 12, color: "#5a6a88" }}>Analysis progress</span>
          <span style={{ fontSize: 12, fontWeight: 600, color: "#4a7cff" }}>{Math.round(progress)}%</span>
        </div>
        <div style={{ height: 6, background: "#252e4a", borderRadius: 3, overflow: "hidden" }}>
          <div style={{ height: "100%", width: `${progress}%`, background: "linear-gradient(90deg, #4a7cff, #7a5cff)", borderRadius: 3, transition: "width 0.1s linear" }} />
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Steps */}
        <div className="card" style={{ padding: 24 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#8b96b8", letterSpacing: "0.05em", marginBottom: 18 }}>PIPELINE STATUS</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            {steps.map((step, i) => {
              const done = i < currentStep;
              const active = i === currentStep;
              return (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ flexShrink: 0 }}>
                    {done ? (
                      <CheckCircle size={16} color="#2dc77a" />
                    ) : active ? (
                      <Loader size={16} color="#4a7cff" style={{ animation: "spin 1s linear infinite" }} />
                    ) : (
                      <Circle size={16} color="#94a3b8" />
                    )}
                  </div>
                  <span style={{ fontSize: 13, color: done ? "#4b5675" : active ? "#111827" : "#94a3b8" }}>
                    {step.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Activity log */}
        <div className="card" style={{ padding: 24, overflow: "hidden" }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: "#8b96b8", letterSpacing: "0.05em", marginBottom: 18 }}>ACTIVITY LOG</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 300, overflowY: "auto" }}>
            {visibleLogs.map((log, i) => (
              <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <span className="mono" style={{ fontSize: 11, color: "#4a5a78", flexShrink: 0, paddingTop: 1 }}>[{log.time}]</span>
                <span style={{ fontSize: 12, color: i === visibleLogs.length - 1 ? "#4b5675" : "#64748b", lineHeight: 1.5 }}>{log.msg}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
