import {
  AlertTriangle,
  ExternalLink,
  ArrowLeft,
  Shield,
  Calendar,
  Globe,
} from "lucide-react";

import type { Screen } from "../App";
import type { AnalysisResponse } from "../services/api";

interface Props {
  navigate: (s: Screen) => void;
  analysis: AnalysisResponse;
}

export default function UrlDomainIntelligence({
  navigate,
  analysis,
}: Props) {
  const urls = Array.isArray(
    analysis.url_analysis
  )
    ? analysis.url_analysis
    : [];

  const domains =
    analysis.domain_intelligence || {};

  const domainAnalysis =
    analysis.domain_analysis || {};

  const domainNames =
    Object.keys(domains);

  const suspiciousCount =
    urls.filter(
      (u: any) => u.suspicious
    ).length;

  const senderDomain =
    domainAnalysis.sender_domain ||
    "Unknown";

  const senderInfo =
    domains[senderDomain];

  const replyDomain =
    domainAnalysis.reply_to_domain;

  const replyInfo =
    replyDomain
      ? domains[replyDomain]
      : null;

  const getRiskColor = (
    score: number
  ) => {
    if (score >= 70)
      return "#ff3b5c";

    if (score >= 30)
      return "#f5a623";

    return "#2dc77a";
  };

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
      </div>

      {/* Summary */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(3, 1fr)",
          gap: 16,
          marginBottom: 20,
        }}
      >
        {[
          {
            label: "URLs Found",
            value: urls.length,
            color: "#4a9eff",
          },
          {
            label: "Suspicious",
            value: suspiciousCount,
            color: "#f5a623",
          },
          {
            label: "Domains Analyzed",
            value: domainNames.length,
            color: "#ff3b5c",
          },
        ].map((s) => (
          <div
            key={s.label}
            className="card"
            style={{
              padding: 20,
              display: "flex",
              alignItems: "center",
              gap: 16,
            }}
          >
            <div
              style={{
                fontSize: 32,
                fontWeight: 800,
                color: s.color,
              }}
            >
              {s.value}
            </div>

            <div
              style={{
                fontSize: 14,
                color: "#5a6a88",
              }}
            >
              {s.label}
            </div>
          </div>
        ))}
      </div>

      {/* URL table */}
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
            URL Analysis
          </div>
        </div>

        {urls.length === 0 ? (
          <div
            style={{
              padding: 24,
              color: "#5a6a88",
            }}
          >
            No URLs were detected.
          </div>
        ) : (
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
                  "URL",
                  "Domain",
                  "Risk",
                  "Detection",
                ].map((h) => (
                  <th
                    key={h}
                    style={{
                      padding:
                        "10px 20px",
                      textAlign:
                        "left",
                      fontSize: 11,
                      color:
                        "#5a6a88",
                    }}
                  >
                    {h.toUpperCase()}
                  </th>
                ))}
              </tr>
            </thead>

            <tbody>
              {urls.map(
                (
                  row: any,
                  index: number
                ) => (
                  <tr
                    key={index}
                    style={{
                      borderBottom:
                        "1px solid #252e4a",
                    }}
                  >
                    <td
                      style={{
                        padding:
                          "12px 20px",
                        maxWidth: 360,
                      }}
                    >
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
                          className="mono"
                          style={{
                            fontSize: 11,
                            color:
                              "#8b96b8",
                            overflow:
                              "hidden",
                            textOverflow:
                              "ellipsis",
                            whiteSpace:
                              "nowrap",
                          }}
                        >
                          {row.url}
                        </span>

                        <ExternalLink
                          size={12}
                          color="#64748b"
                        />
                      </div>
                    </td>

                    <td
                      style={{
                        padding:
                          "12px 20px",
                      }}
                    >
                      <span
                        className="mono"
                        style={{
                          fontSize: 12,
                          color:
                            "#ff7a4a",
                        }}
                      >
                        {row.domain ||
                          "Unknown"}
                      </span>
                    </td>

                    <td
                      style={{
                        padding:
                          "12px 20px",
                      }}
                    >
                      <span
                        style={{
                          padding:
                            "3px 9px",
                          borderRadius: 4,
                          fontSize: 11,
                          fontWeight: 700,
                          color:
                            row.suspicious
                              ? "#ff3b5c"
                              : "#2dc77a",
                          background:
                            row.suspicious
                              ? "rgba(255,59,92,0.1)"
                              : "rgba(45,199,122,0.1)",
                        }}
                      >
                        {row.suspicious
                          ? "SUSPICIOUS"
                          : "CLEAR"}
                      </span>
                    </td>

                    <td
                      style={{
                        padding:
                          "12px 20px",
                        fontSize: 12,
                        color:
                          "#8b96b8",
                      }}
                    >
                      {Array.isArray(
                        row.reasons
                      )
                        ? row.reasons.join(
                            ", "
                          )
                        : "No specific reason"}
                    </td>
                  </tr>
                )
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Domain Intelligence */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "1fr 1fr",
          gap: 16,
        }}
      >
        {domainNames.map(
          (name) => {
            const info =
              domains[name] || {};

            const risk =
              info.risk || {};

            const riskScore =
              Number(
                risk.risk_score ?? 0
              );

            const riskColor =
              getRiskColor(
                riskScore
              );

            return (
              <div
                className="card"
                key={name}
                style={{
                  padding: 24,
                }}
              >
                <div
                  style={{
                    display:
                      "flex",
                    alignItems:
                      "center",
                    justifyContent:
                      "space-between",
                    marginBottom: 20,
                  }}
                >
                  <div
                    style={{
                      display:
                        "flex",
                      alignItems:
                        "center",
                      gap: 10,
                    }}
                  >
                    <Shield
                      size={20}
                      color={
                        riskColor
                      }
                    />

                    <span
                      className="mono"
                      style={{
                        fontSize: 16,
                        fontWeight: 700,
                        color:
                          "#e8eaf6",
                      }}
                    >
                      {name}
                    </span>
                  </div>

                  <span
                    style={{
                      padding:
                        "3px 9px",
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 700,
                      color:
                        riskColor,
                      background:
                        `${riskColor}15`,
                    }}
                  >
                    {risk.level ||
                      "SCORE " +
                        riskScore}
                  </span>
                </div>

                <div
                  style={{
                    display:
                      "grid",
                    gridTemplateColumns:
                      "1fr 1fr",
                    gap: 16,
                  }}
                >
                  <div>
                    <div
                      style={{
                        fontSize: 11,
                        color:
                          "#5a6a88",
                      }}
                    >
                      RISK SCORE
                    </div>

                    <div
                      style={{
                        fontSize: 18,
                        fontWeight: 700,
                        color:
                          riskColor,
                      }}
                    >
                      {riskScore}/100
                    </div>
                  </div>

                  <div>
                    <div
                      style={{
                        fontSize: 11,
                        color:
                          "#5a6a88",
                      }}
                    >
                      DOMAIN AGE
                    </div>

                    <div
                      className="mono"
                      style={{
                        fontSize: 13,
                        color:
                          "#c8d0e8",
                      }}
                    >
                      {info.domain_age_days !=
                      null
                        ? `${info.domain_age_days} days`
                        : "Unknown"}
                    </div>
                  </div>

                  <div>
                    <div
                      style={{
                        fontSize: 11,
                        color:
                          "#5a6a88",
                      }}
                    >
                      REGISTRAR
                    </div>

                    <div
                      style={{
                        fontSize: 13,
                        color:
                          "#c8d0e8",
                      }}
                    >
                      {info.registrar ||
                        "Unknown"}
                    </div>
                  </div>

                  <div>
                    <div
                      style={{
                        fontSize: 11,
                        color:
                          "#5a6a88",
                      }}
                    >
                      STATUS
                    </div>

                    <div
                      style={{
                        fontSize: 13,
                        color:
                          "#c8d0e8",
                      }}
                    >
                      {info.status ||
                        "Unknown"}
                    </div>
                  </div>
                </div>

                <div
                  style={{
                    marginTop: 20,
                    display:
                      "flex",
                    flexDirection:
                      "column",
                    gap: 8,
                  }}
                >
                  <div
                    style={{
                      fontSize: 11,
                      color:
                        "#5a6a88",
                    }}
                  >
                    A RECORDS
                  </div>

                  <div
                    className="mono"
                    style={{
                      fontSize: 12,
                      color:
                        "#8b96b8",
                    }}
                  >
                    {Array.isArray(
                      info.a_records
                    )
                      ? info.a_records.join(
                          ", "
                        )
                      : "None"}
                  </div>

                  <div
                    style={{
                      fontSize: 11,
                      color:
                        "#5a6a88",
                      marginTop: 8,
                    }}
                  >
                    MX RECORDS
                  </div>

                  <div
                    className="mono"
                    style={{
                      fontSize: 12,
                      color:
                        "#8b96b8",
                    }}
                  >
                    {Array.isArray(
                      info.mx_records
                    )
                      ? info.mx_records.join(
                          ", "
                        )
                      : "None"}
                  </div>
                </div>

                {Array.isArray(
                  risk.reasons
                ) &&
                  risk.reasons.length >
                    0 && (
                    <div
                      style={{
                        marginTop: 20,
                        padding:
                          "12px 14px",
                        background:
                          "rgba(245,166,35,0.06)",
                        border:
                          "1px solid rgba(245,166,35,0.15)",
                        borderRadius: 8,
                      }}
                    >
                      {risk.reasons.map(
                        (
                          reason: string,
                          i: number
                        ) => (
                          <div
                            key={i}
                            style={{
                              display:
                                "flex",
                              gap: 8,
                              marginBottom:
                                i <
                                risk
                                  .reasons
                                  .length -
                                  1
                                  ? 6
                                  : 0,
                            }}
                          >
                            <AlertTriangle
                              size={13}
                              color="#f5a623"
                            />

                            <span
                              style={{
                                fontSize: 12,
                                color:
                                  "#8b96b8",
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
            );
          }
        )}
      </div>

      {/* Relationship */}
      <div
        className="card"
        style={{
          padding: 24,
          marginTop: 16,
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
          Sender / Reply-To Domain Relationship
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              "1fr 1fr",
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
              SENDER DOMAIN
            </div>

            <div
              className="mono"
              style={{
                fontSize: 15,
                color: "#4a9eff",
              }}
            >
              {senderDomain}
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
              REPLY-TO DOMAIN
            </div>

            <div
              className="mono"
              style={{
                fontSize: 15,
                color: domainAnalysis
                  .reply_to_mismatch
                  ? "#ff3b5c"
                  : "#2dc77a",
              }}
            >
              {replyDomain ||
                "None"}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}