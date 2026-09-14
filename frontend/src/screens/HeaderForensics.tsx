import {
  X,
  CheckCircle,
  AlertTriangle,
  ArrowLeft,
} from "lucide-react";

import type { Screen } from "../App";
import type { AnalysisResponse } from "../services/api";

interface Props {
  navigate: (s: Screen) => void;
  analysis: AnalysisResponse;
}

export default function HeaderForensics({
  navigate,
  analysis,
}: Props) {
  const email = analysis.email || {};
  const auth =
    analysis.threat_analysis?.auth_analysis || {};

  const receivedHeaders =
    Array.isArray(email.received_headers)
      ? email.received_headers
      : [];

  const getStatus = (value: any) => {
    if (value === "pass" || value === "PASS") {
      return "ok";
    }

    if (
      value === "fail" ||
      value === "FAIL" ||
      value === null ||
      value === undefined
    ) {
      return "fail";
    }

    return "warn";
  };

  const authCards = [
    {
      label: "SPF",
      value: auth.spf,
      reason:
        auth.spf
          ? `SPF result returned by the analysis engine: ${auth.spf}.`
          : "No SPF result was found or evaluated.",
    },
    {
      label: "DKIM",
      value: auth.dkim,
      reason:
        auth.dkim
          ? `DKIM result returned by the analysis engine: ${auth.dkim}.`
          : "No DKIM signature was found.",
    },
    {
      label: "DMARC",
      value: auth.dmarc,
      reason:
        auth.dmarc
          ? `DMARC result returned by the analysis engine: ${auth.dmarc}.`
          : "No DMARC result was found or evaluated.",
    },
  ];

  const headers = [
    {
      name: "From",
      value: email.from || "Not available",
      assessment: "Sender",
      status: "ok",
    },
    {
      name: "Reply-To",
      value: email.reply_to || "Not available",
      assessment:
        analysis.domain_analysis?.reply_to_mismatch
          ? "Mismatch"
          : "Match",
      status:
        analysis.domain_analysis?.reply_to_mismatch
          ? "fail"
          : "ok",
    },
    {
      name: "Return-Path",
      value: email.return_path || "Not available",
      assessment:
        analysis.domain_analysis?.return_path_mismatch
          ? "Mismatch"
          : "Match",
      status:
        analysis.domain_analysis?.return_path_mismatch
          ? "fail"
          : "ok",
    },
    ...receivedHeaders.map(
      (header: string, index: number) => ({
        name: `Received ${index + 1}`,
        value: header,
        assessment: "Analyzed",
        status: "warn",
      })
    ),
    {
      name: "Date",
      value: email.date || "Not available",
      assessment: "Parsed",
      status: "ok",
    },
  ];

  const reasons =
    analysis.threat_analysis?.reasons || [];

  return (
    <div>
      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          marginBottom: 24,
          marginTop: -8,
        }}
      >
        <button
          className="btn-ghost"
          onClick={() => navigate("result")}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            fontSize: 13,
          }}
        >
          <ArrowLeft size={14} />
          Back to Result
        </button>

        <span
          className="mono"
          style={{
            fontSize: 12,
            color: "#4a5a78",
          }}
        >
          {analysis.identity_correlation?.case_id ||
            "CASE"}
        </span>
      </div>

      {/* Authentication */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(3, 1fr)",
          gap: 16,
          marginBottom: 20,
        }}
      >
        {authCards.map((item) => {
          const status =
            getStatus(item.value);

          const failed =
            status === "fail";

          return (
            <div
              key={item.label}
              className="card"
              style={{
                padding: 24,
                background: failed
                  ? "rgba(255,59,92,0.08)"
                  : "rgba(45,199,122,0.06)",
                borderColor: failed
                  ? "rgba(255,59,92,0.25)"
                  : "rgba(45,199,122,0.2)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  marginBottom: 12,
                }}
              >
                <div
                  style={{
                    width: 32,
                    height: 32,
                    borderRadius: "50%",
                    background: failed
                      ? "rgba(255,59,92,0.15)"
                      : "rgba(45,199,122,0.12)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent:
                      "center",
                  }}
                >
                  {failed ? (
                    <X
                      size={16}
                      color="#ff3b5c"
                    />
                  ) : (
                    <CheckCircle
                      size={16}
                      color="#2dc77a"
                    />
                  )}
                </div>

                <div>
                  <div
                    style={{
                      fontSize: 16,
                      fontWeight: 700,
                      color: "#e8eaf6",
                    }}
                  >
                    {item.label}
                  </div>

                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 700,
                      color: failed
                        ? "#ff3b5c"
                        : "#2dc77a",
                    }}
                  >
                    {item.value
                      ? String(
                          item.value
                        ).toUpperCase()
                      : "NOT FOUND"}
                  </div>
                </div>
              </div>

              <p
                style={{
                  fontSize: 13,
                  color: "#8b96b8",
                  lineHeight: 1.6,
                  margin: 0,
                }}
              >
                {item.reason}
              </p>
            </div>
          );
        })}
      </div>

      {/* Header table */}
      <div
        className="card"
        style={{
          padding: 0,
          overflow: "hidden",
          marginBottom: 20,
        }}
      >
        <div
          style={{
            padding:
              "20px 24px 16px",
            borderBottom:
              "1px solid #252e4a",
          }}
        >
          <div
            style={{
              fontSize: 15,
              fontWeight: 600,
              color: "#e8eaf6",
            }}
          >
            Header Analysis
          </div>

          <div
            style={{
              fontSize: 12,
              color: "#5a6a88",
              marginTop: 4,
            }}
          >
            Real headers extracted from the uploaded
            email
          </div>
        </div>

        <table
          style={{
            width: "100%",
            borderCollapse:
              "collapse",
          }}
        >
          <thead>
            <tr
              style={{
                borderBottom:
                  "1px solid #252e4a",
              }}
            >
              {[
                "Header",
                "Value",
                "Assessment",
              ].map((h) => (
                <th
                  key={h}
                  style={{
                    padding:
                      "10px 20px",
                    textAlign: "left",
                    fontSize: 11,
                    color: "#5a6a88",
                    fontWeight: 600,
                  }}
                >
                  {h.toUpperCase()}
                </th>
              ))}
            </tr>
          </thead>

          <tbody>
            {headers.map(
              (row, index) => (
                <tr
                  key={index}
                  style={{
                    borderBottom:
                      index <
                      headers.length - 1
                        ? "1px solid #252e4a"
                        : "none",
                  }}
                >
                  <td
                    style={{
                      padding:
                        "10px 20px",
                      width: 140,
                    }}
                  >
                    <span
                      className="mono"
                      style={{
                        fontSize: 12,
                        color: "#4a9eff",
                      }}
                    >
                      {row.name}
                    </span>
                  </td>

                  <td
                    style={{
                      padding:
                        "10px 20px",
                    }}
                  >
                    <span
                      className="mono"
                      style={{
                        fontSize: 12,
                        color: "#8b96b8",
                        wordBreak:
                          "break-all",
                      }}
                    >
                      {row.value}
                    </span>
                  </td>

                  <td
                    style={{
                      padding:
                        "10px 20px",
                    }}
                  >
                    <div
                      style={{
                        display:
                          "flex",
                        alignItems:
                          "center",
                        gap: 6,
                      }}
                    >
                      {row.status ===
                        "fail" && (
                        <X
                          size={12}
                          color="#ff3b5c"
                        />
                      )}

                      {row.status ===
                        "warn" && (
                        <AlertTriangle
                          size={12}
                          color="#f5a623"
                        />
                      )}

                      {row.status ===
                        "ok" && (
                        <CheckCircle
                          size={12}
                          color="#2dc77a"
                        />
                      )}

                      <span
                        style={{
                          fontSize: 12,
                          fontWeight: 600,
                          color:
                            row.status ===
                            "fail"
                              ? "#ff3b5c"
                              : row.status ===
                                "warn"
                              ? "#f5a623"
                              : "#2dc77a",
                        }}
                      >
                        {row.assessment}
                      </span>
                    </div>
                  </td>
                </tr>
              )
            )}
          </tbody>
        </table>
      </div>

      {/* Anomalies */}
      <div
        className="card"
        style={{
          padding: 24,
        }}
      >
        <div
          style={{
            fontSize: 15,
            fontWeight: 600,
            color: "#e8eaf6",
            marginBottom: 16,
          }}
        >
          Detected Header Threats
        </div>

        {reasons.length === 0 ? (
          <div
            style={{
              color: "#5a6a88",
              fontSize: 13,
            }}
          >
            No header-related threats were returned.
          </div>
        ) : (
          <div
            style={{
              display: "flex",
              flexDirection:
                "column",
              gap: 12,
            }}
          >
            {reasons.map(
              (reason: string, i: number) => (
                <div
                  key={i}
                  style={{
                    display:
                      "flex",
                    alignItems:
                      "flex-start",
                    gap: 12,
                    padding:
                      "12px 16px",
                    background:
                      "rgba(245,166,35,0.06)",
                    borderRadius: 8,
                    border:
                      "1px solid rgba(245,166,35,0.15)",
                  }}
                >
                  <AlertTriangle
                    size={14}
                    color="#f5a623"
                  />

                  <span
                    style={{
                      fontSize: 13,
                      color: "#8b96b8",
                      lineHeight: 1.6,
                    }}
                  >
                    {reason}
                  </span>
                </div>
              )
            )}
          </div>
        )}
      </div>
    </div>
  );
}