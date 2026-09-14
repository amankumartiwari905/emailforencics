import {
  X,
  CheckCircle,
  AlertTriangle,
  Download,
  FolderPlus,
  Share2,
  RefreshCw,
  ChevronRight,
} from "lucide-react";

import {
  downloadForensicReport,
} from "../services/api";

import type { Screen } from "../App";
import type { AnalysisResponse } from "../services/api";

interface Props {
  navigate: (s: Screen) => void;
  analysis: AnalysisResponse;
  analyzedFile: File | null;
  onCreateCase: () => void;
  activeCaseId?: string;
}
function RiskGauge({
  score,
}: {
  score: number;
}) {
  const safeScore = Math.max(
    0,
    Math.min(100, score)
  );

  const r = 70;
  const cx = 90;
  const cy = 90;

  const startAngle = Math.PI * 0.75;
  const endAngle = Math.PI * 2.25;

  const totalArc =
    endAngle - startAngle;

  const fillArc =
    (safeScore / 100) * totalArc;

  const polarToXY = (
    angle: number
  ) => ({
    x:
      cx +
      r * Math.cos(angle),

    y:
      cy +
      r * Math.sin(angle),
  });

  const start =
    polarToXY(startAngle);

  const end =
    polarToXY(endAngle);

  const fillEnd =
    polarToXY(
      startAngle + fillArc
    );

  const largeArc =
    fillArc > Math.PI ? 1 : 0;

  return (
    <svg
      width={180}
      height={140}
      viewBox="0 0 180 140"
    >
      <path
        d={`M ${start.x} ${start.y} A ${r} ${r} 0 1 1 ${end.x} ${end.y}`}
        fill="none"
        stroke="#252e4a"
        strokeWidth={10}
        strokeLinecap="round"
      />

      <path
        d={`M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${fillEnd.x} ${fillEnd.y}`}
        fill="none"
        stroke="#ff3b5c"
        strokeWidth={10}
        strokeLinecap="round"
      />

      <text
        x={cx}
        y={cy + 8}
        textAnchor="middle"
        fill="#ff3b5c"
        fontSize={36}
        fontWeight={700}
        fontFamily="Inter"
      >
        {safeScore}
      </text>

      <text
        x={cx}
        y={cy + 28}
        textAnchor="middle"
        fill="#64748b"
        fontSize={11}
        fontFamily="Inter"
      >
        / 100
      </text>
    </svg>
  );
}

function statusText(value: any) {
  if (
    value === null ||
    value === undefined
  ) {
    return "NOT FOUND";
  }

  if (
    value === "fail" ||
    value === "FAIL"
  ) {
    return "FAIL";
  }

  if (
    value === "pass" ||
    value === "PASS"
  ) {
    return "PASS";
  }

  return String(value).toUpperCase();
}

export default function AnalysisResult({
  navigate,
  analysis,
  analyzedFile,
  onCreateCase,
  activeCaseId,
}: Props) {
  const threat =
    analysis.threat_analysis || {};

  const email =
    analysis.email || {};

  const domain =
    analysis.domain_analysis || {};

  const nlp =
    analysis.nlp_analysis || {};

  const ml =
    analysis.ml_phishing_analysis || {};

  const auth =
    threat.auth_analysis || {};

  const score =
    Number(threat.fraud_score ?? 0);

  const classification =
    String(
      threat.classification ??
        "UNKNOWN"
    );

  const phishingProbability =
    Number(
      ml.phishing_probability ?? 0
    );

  const aiConfidence = Math.round(
    phishingProbability * 100
  );

  const replyMismatch =
    domain.reply_to_mismatch === true;

  const returnMismatch =
    domain.return_path_mismatch ===
    true;

  const suspiciousUrls =
    Array.isArray(
      analysis.url_analysis
    )
      ? analysis.url_analysis.filter(
          (item: any) =>
            item.suspicious === true
        )
      : [];

  const lookalikes =
    Array.isArray(
      analysis.lookalike_analysis
    )
      ? analysis.lookalike_analysis
      : [];

  const urgencyDetected =
    Array.isArray(nlp.tactics) &&
    nlp.tactics.includes("urgency");

  const indicators = [
    {
      label: "Sender Mismatch",
      status:
        replyMismatch ||
        returnMismatch
          ? "DETECTED"
          : "CLEAR",
      fail:
        replyMismatch ||
        returnMismatch,
    },

    {
      label: "SPF",
      status: statusText(auth.spf),
      fail:
        auth.spf !== "pass" &&
        auth.spf !== "PASS",
    },

    {
      label: "DKIM",
      status: statusText(auth.dkim),
      fail:
        auth.dkim !== "pass" &&
        auth.dkim !== "PASS",
    },

    {
      label: "DMARC",
      status: statusText(auth.dmarc),
      fail:
        auth.dmarc !== "pass" &&
        auth.dmarc !== "PASS",
    },

    {
      label: "Suspicious URL",
      status:
        suspiciousUrls.length > 0
          ? "DETECTED"
          : "CLEAR",
      fail:
        suspiciousUrls.length > 0,
    },

    {
      label: "Domain Lookalike",
      status:
        lookalikes.length > 0
          ? "DETECTED"
          : "CLEAR",
      fail:
        lookalikes.length > 0,
    },

    {
      label: "Urgency Language",
      status:
        urgencyDetected
          ? "DETECTED"
          : "CLEAR",
      fail: urgencyDetected,
    },

    {
      label: "Return-Path",
      status:
        returnMismatch
          ? "MISMATCH"
          : "MATCH",
      fail: returnMismatch,
    },
  ];

  const reasons =
    Array.isArray(threat.reasons)
      ? threat.reasons
      : [];

  const originIP =
    analysis
      .earliest_reliable_ip
      ?.ip || "Unknown";

  const originLocation =
    analysis.ip_locations?.[
      originIP
    ];

  const caseId =
  activeCaseId ||
  analysis.identity_correlation?.case_id ||
  "CASE-UNKNOWN";

  const subject =
    email.subject || "Unknown";

  const from =
    email.from || "Unknown";

  const replyTo =
    email.reply_to || "None";

  const returnPath =
    email.return_path || "None";

  const links =
    Array.isArray(email.links)
      ? email.links
      : [];

  const attachments =
    Array.isArray(email.attachments)
      ? email.attachments
      : [];

  // --------------------------------
  // EXPORT FORENSIC REPORT
  // --------------------------------
  const handleExportReport =
    async () => {
      if (!analyzedFile) {
        alert(
          "Original email file is not available."
        );
        return;
      }

      try {
        const blob =
          await downloadForensicReport(
            analyzedFile
          );

        const url =
          window.URL.createObjectURL(
            blob
          );

        const link =
          document.createElement("a");

        link.href = url;

        link.download =
          `${caseId}-forensic-report.pdf`;

        document.body.appendChild(
          link
        );

        link.click();

        document.body.removeChild(
          link
        );

        window.URL.revokeObjectURL(
          url
        );
      } catch (error) {
        console.error(
          "Report export failed:",
          error
        );

        alert(
          "Failed to generate forensic report."
        );
      }
    };

  return (
    <div>
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent:
            "space-between",
          marginBottom: 24,
          marginTop: -8,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <span
            className="mono"
            style={{
              fontSize: 12,
              color: "#5a6a88",
            }}
          >
            {caseId}
          </span>

          <span
           className={
  score >= 80
    ? "badge-critical"
    : score >= 60
      ? "badge-high"
      : score >= 30
        ? "badge-medium"
        : "badge-low"
}
            style={{
              padding: "2px 10px",
              borderRadius: 4,
              fontSize: 11,
              fontWeight: 700,
            }}
          >
            {classification}
          </span>
        </div>

        <div
          style={{
            display: "flex",
            gap: 8,
          }}
        >
          {/* REAL EXPORT BUTTON */}
          <button
            className="btn-secondary"
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              fontSize: 13,
            }}
            onClick={
              handleExportReport
            }
          >
            <Download size={13} />
            Export Report
          </button>

         <button
  className="btn-primary"
  style={{
    display: "flex",
    alignItems: "center",
    gap: 6,
    fontSize: 13,
  }}
  onClick={onCreateCase}
>
  <FolderPlus size={13} />
  Create Case
</button>

          <button
            className="btn-secondary"
            style={{
              padding: "9px 12px",
            }}
          >
            <Share2 size={13} />
          </button>

          <button
            className="btn-secondary"
            style={{
              padding: "9px 12px",
            }}
            onClick={() =>
              navigate("analyze")
            }
          >
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      {/* Main result */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "320px 1fr",
          gap: 16,
          marginBottom: 16,
        }}
      >
        {/* Risk */}
        <div
          className="card threat-fail"
          style={{
            padding: 28,
            display: "flex",
            flexDirection:
              "column",
            alignItems: "center",
          }}
        >
          <div
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: "#5a6a88",
              letterSpacing:
                "0.08em",
              marginBottom: 4,
            }}
          >
            THREAT RISK SCORE
          </div>

          <RiskGauge score={score} />

          <div
            style={{
              fontSize: 22,
              fontWeight: 800,
              color: "#ff3b5c",
              marginBottom: 4,
            }}
          >
            {classification}
          </div>

          <div
            style={{
              fontSize: 14,
              color: "#8b96b8",
              marginBottom: 12,
              textAlign: "center",
            }}
          >
            {ml.prediction
              ? `ML: ${ml.prediction}`
              : "Threat analysis"}
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "6px 14px",
              background:
                "rgba(255,59,92,0.08)",
              borderRadius: 20,
              border:
                "1px solid rgba(255,59,92,0.2)",
            }}
          >
            <span
              style={{
                fontSize: 12,
                color: "#8b96b8",
              }}
            >
              ML Probability:
            </span>

            <span
              style={{
                fontSize: 13,
                fontWeight: 700,
                color: "#ff3b5c",
              }}
            >
              {aiConfidence}%
            </span>
          </div>
        </div>

        {/* Assessment */}
        <div
          className="card"
          style={{
            padding: 28,
          }}
        >
          <div
            style={{
              fontSize: 15,
              fontWeight: 600,
              color: "#e8eaf6",
              marginBottom: 12,
            }}
          >
            Threat Assessment
          </div>

          <div
            style={{
              fontSize: 14,
              color: "#8b96b8",
              lineHeight: 1.7,
              marginBottom: 24,
              padding:
                "14px 16px",
              background: "#151c2f",
              borderRadius: 8,
              borderLeft:
                "3px solid #ff3b5c",
            }}
          >
            {reasons.length > 0
              ? reasons.join(". ") +
                "."
              : "No specific threat reasons were returned by the backend."}
          </div>

          <div
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: "#5a6a88",
              letterSpacing:
                "0.06em",
              marginBottom: 14,
            }}
          >
            THREAT INDICATORS
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns:
                "repeat(4, 1fr)",
              gap: 10,
            }}
          >
            {indicators.map(
              (ind) => (
                <div
                  key={ind.label}
                  style={{
                    padding:
                      "12px 14px",
                    borderRadius: 8,
                    background:
                      ind.fail
                        ? "rgba(255,59,92,0.06)"
                        : "rgba(45,199,122,0.06)",
                    border: `1px solid ${
                      ind.fail
                        ? "rgba(255,59,92,0.2)"
                        : "rgba(45,199,122,0.2)"
                    }`,
                  }}
                >
                  <div
                    style={{
                      display:
                        "flex",
                      alignItems:
                        "center",
                      gap: 6,
                      marginBottom: 6,
                    }}
                  >
                    {ind.fail ? (
                      <X
                        size={12}
                        color="#ff3b5c"
                      />
                    ) : (
                      <CheckCircle
                        size={12}
                        color="#2dc77a"
                      />
                    )}

                    <span
                      style={{
                        fontSize: 11,
                        color:
                          "#5a6a88",
                      }}
                    >
                      {ind.label}
                    </span>
                  </div>

                  <div
                    style={{
                      fontSize: 12,
                      fontWeight: 700,
                      color: ind.fail
                        ? "#ff3b5c"
                        : "#2dc77a",
                    }}
                  >
                    {ind.status}
                  </div>
                </div>
              )
            )}
          </div>
        </div>
      </div>

      {/* Detailed sections */}
      <div
        className="card"
        style={{
          padding: 20,
          marginBottom: 16,
        }}
      >
        <div
          style={{
            fontSize: 13,
            fontWeight: 600,
            color: "#5a6a88",
            letterSpacing:
              "0.06em",
            marginBottom: 14,
          }}
        >
          DETAILED ANALYSIS SECTIONS
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              "repeat(4, 1fr)",
            gap: 12,
          }}
        >
          {[
            {
              label:
                "Header Forensics",
              sub:
                "SPF · DKIM · DMARC · Relay analysis",
              screen:
                "header-forensics" as Screen,
              color: "#f5a623",
            },

            {
              label:
                "URL & Domain Intel",
              sub: `${links.length} URL(s) detected`,
              screen:
                "url-domain" as Screen,
              color: "#ff3b5c",
            },

            {
              label:
                "IP & GeoLocation",
              sub:
                originLocation
                  ? `${originLocation.city || "Unknown"}, ${originLocation.country_code || ""}`
                  : `Origin: ${originIP}`,
              screen:
                "ip-geo" as Screen,
              color: "#4a9eff",
            },

            {
              label:
                "Relay Path",
              sub: `${analysis.relay_chain?.length || 0} relay hops`,
              screen:
                "relay-path" as Screen,
              color: "#9b6fff",
            },
          ].map(
            (item) => (
              <button
                key={item.label}
                onClick={() =>
                  navigate(
                    item.screen
                  )
                }
                style={{
                  padding: 16,
                  borderRadius: 10,
                  border:
                    "1px solid #252e4a",
                  background:
                    "#151c2f",
                  cursor: "pointer",
                  textAlign:
                    "left",
                  display:
                    "flex",
                  alignItems:
                    "center",
                  justifyContent:
                    "space-between",
                }}
              >
                <div>
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 600,
                      color:
                        "#e8eaf6",
                      marginBottom: 4,
                    }}
                  >
                    {item.label}
                  </div>

                  <div
                    style={{
                      fontSize: 11,
                      color:
                        "#5a6a88",
                    }}
                  >
                    {item.sub}
                  </div>
                </div>

                <ChevronRight
                  size={14}
                  color={item.color}
                />
              </button>
            )
          )}
        </div>
      </div>

      {/* Origin information */}
      <div
        className="card"
        style={{
          padding: 24,
          marginBottom: 16,
        }}
      >
        <div
          style={{
            fontSize: 15,
            fontWeight: 600,
            color: "#e8eaf6",
            marginBottom: 20,
          }}
        >
          Origin Intelligence
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              "1fr 1fr 1fr",
            gap: 16,
          }}
        >
          <div>
            <div
              style={{
                fontSize: 11,
                color: "#5a6a88",
                marginBottom: 6,
              }}
            >
              EARLIEST RELIABLE IP
            </div>

            <div
              className="mono"
              style={{
                fontSize: 14,
                color: "#4a9eff",
              }}
            >
              {originIP}
            </div>
          </div>

          <div>
            <div
              style={{
                fontSize: 11,
                color: "#5a6a88",
                marginBottom: 6,
              }}
            >
              LOCATION
            </div>

            <div
              style={{
                fontSize: 14,
                color: "#c8d0e8",
              }}
            >
              {originLocation
                ? `${originLocation.city || "Unknown"}, ${originLocation.country || "Unknown"}`
                : "Unknown"}
            </div>
          </div>

          <div>
            <div
              style={{
                fontSize: 11,
                color: "#5a6a88",
                marginBottom: 6,
              }}
            >
              CONFIDENCE
            </div>

            <div
              style={{
                fontSize: 14,
                color: "#2dc77a",
                fontWeight: 600,
              }}
            >
              {analysis
                .earliest_reliable_ip
                ?.confidence ||
                "Unknown"}
            </div>
          </div>
        </div>
      </div>

      {/* Email Overview */}
      <div
        className="card"
        style={{
          padding: 24,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems:
              "center",
            justifyContent:
              "space-between",
            marginBottom: 20,
          }}
        >
          <div
            style={{
              fontSize: 15,
              fontWeight: 600,
              color: "#e8eaf6",
            }}
          >
            Email Overview
          </div>

          <span
            style={{
              fontSize: 12,
              color: "#5a6a88",
            }}
          >
            Live backend data
          </span>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              "1fr 1fr",
            gap: 0,
          }}
        >
          {[
            {
              label: "From",
              value: from,
              mono: true,
              flag: false,
            },

            {
              label: "Reply-To",
              value: replyTo,
              mono: true,
              flag: replyMismatch,
            },

            {
              label: "Return-Path",
              value: returnPath,
              mono: true,
              flag: returnMismatch,
            },

            {
              label: "Subject",
              value: subject,
              mono: false,
              flag: false,
            },

            {
              label: "Date",
              value:
                email.date ||
                "Unknown",
              mono: true,
              flag: false,
            },

            {
              label: "Links",
              value: `${links.length} detected`,
              mono: false,
              flag:
                suspiciousUrls.length >
                0,
            },

            {
              label: "Attachments",
              value:
                attachments.length >
                0
                  ? `${attachments.length} detected`
                  : "None",
              mono: false,
              flag:
                attachments.length >
                0,
            },

            {
              label: "Origin IP",
              value: originIP,
              mono: true,
              flag: false,
            },
          ].map(
            (field, i) => (
              <div
                key={field.label}
                style={{
                  display:
                    "flex",
                  padding:
                    "12px 0",
                  borderBottom:
                    i < 6
                      ? "1px solid #252e4a"
                      : "none",
                  gap: 16,
                }}
              >
                <span
                  style={{
                    fontSize: 12,
                    color:
                      "#5a6a88",
                    width: 120,
                    flexShrink: 0,
                  }}
                >
                  {field.label}
                </span>

                <div
                  style={{
                    display:
                      "flex",
                    alignItems:
                      "center",
                    gap: 8,
                  }}
                >
                  <span
                    className={
                      field.mono
                        ? "mono"
                        : ""
                    }
                    style={{
                      fontSize: 13,
                      color:
                        field.flag
                          ? "#ff7a4a"
                          : "#c8d0e8",
                    }}
                  >
                    {field.value}
                  </span>

                  {field.flag && (
                    <AlertTriangle
                      size={12}
                      color="#f5a623"
                    />
                  )}
                </div>
              </div>
            )
          )}
        </div>
      </div>
    </div>
  );
}