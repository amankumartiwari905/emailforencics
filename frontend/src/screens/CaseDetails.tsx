import { useState } from "react";

import {
  ArrowLeft,
  Shield,
  Clock,
  CheckCircle,
  AlertTriangle,
  Globe,
  Database,
  Mail,
  Link as LinkIcon,
  FileText,
} from "lucide-react";

import type { Screen } from "../App";
import type { CaseRecord } from "../App";

interface Props {
  navigate: (s: Screen) => void;
  activeCase: CaseRecord;
}

export default function CaseDetails({
  navigate,
  activeCase,
}: Props) {
  const [activeTab, setActiveTab] =
    useState("Overview");

  const analysis =
    activeCase.analysis;

  const threat =
    analysis.threat_analysis || {};

  const email =
    analysis.email || {};

  const domain =
    analysis.domain_analysis || {};

  /*
    Your backend's actual threat analysis
    contains the authentication results in
    the threat object.

    We check several possible names so the
    UI doesn't break if the backend uses
    slightly different field names.
  */
 const getStatus = (
  ...values: any[]
) => {
  for (const value of values) {
    if (
      value !== undefined &&
      value !== ""
    ) {
      if (value === null) {
        return "NOT FOUND";
      } 

      return String(
        value
      ).toUpperCase();
    }
  }

  return "UNKNOWN";
};

  const spfStatus =
    getStatus(
      threat.spf,
      threat.spf_result,
      threat.spf_status,
      threat.auth_analysis?.spf
    );

  const dkimStatus =
    getStatus(
      threat.dkim,
      threat.dkim_result,
      threat.dkim_status,
      threat.auth_analysis?.dkim
    );

  const dmarcStatus =
    getStatus(
      threat.dmarc,
      threat.dmarc_result,
      threat.dmarc_status,
      threat.auth_analysis?.dmarc
    );

  const originIP =
    analysis
      .earliest_reliable_ip
      ?.ip || "Unknown";

  const location =
    analysis.ip_locations?.[
      originIP
    ];

  const urls =
    Array.isArray(
      analysis.url_analysis
    )
      ? analysis.url_analysis
      : [];

  const suspiciousUrls =
    urls.filter(
      (item: any) =>
        item.suspicious === true
    );

  const relayChain =
    Array.isArray(
      analysis.relay_chain
    )
      ? analysis.relay_chain
      : [];

  const reasons =
    Array.isArray(
      threat.reasons
    )
      ? threat.reasons
      : [];

  const attachments =
    Array.isArray(
      analysis.attachment_analysis
    )
      ? analysis.attachment_analysis
      : [];

  const indicators = [
    {
      label: "SPF",
      value: spfStatus,
      bad:
        spfStatus !== "PASS" &&
        spfStatus !== "FOUND",
    },
    {
      label: "DKIM",
      value: dkimStatus,
      bad:
        dkimStatus !== "PASS" &&
        dkimStatus !== "FOUND",
    },
    {
      label: "DMARC",
      value: dmarcStatus,
      bad:
        dmarcStatus !== "PASS" &&
        dmarcStatus !== "FOUND",
    },
    {
      label: "Suspicious URLs",
      value:
        suspiciousUrls.length,
      bad:
        suspiciousUrls.length > 0,
    },
  ];

  return (
    <div>
      {/* Back */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          marginBottom: 20,
          marginTop: -8,
        }}
      >
        <button
          className="btn-ghost"
          onClick={() =>
            navigate("cases")
          }
          style={{
            display: "flex",
            alignItems: "center",
            gap: 6,
            fontSize: 13,
          }}
        >
          <ArrowLeft size={14} />
          Cases
        </button>
      </div>

      {/* Header */}
      <div
        className="card"
        style={{
          padding: 24,
          marginBottom: 20,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            justifyContent:
              "space-between",
            gap: 20,
            flexWrap: "wrap",
          }}
        >
          <div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                marginBottom: 10,
              }}
            >
              <Shield
                size={20}
                color="#ff3b5c"
              />

              <span
                className="mono"
                style={{
                  color: "#4a9eff",
                  fontSize: 13,
                }}
              >
                {activeCase.id}
              </span>

              <span
                className={`badge-${activeCase.severity}`}
                style={{
                  padding:
                    "3px 10px",
                  borderRadius: 4,
                  fontSize: 11,
                  fontWeight: 700,
                  textTransform:
                    "uppercase",
                }}
              >
                {activeCase.severity}
              </span>
            </div>

            <div
              style={{
                fontSize: 22,
                fontWeight: 800,
                color: "#e8eaf6",
              }}
            >
              {activeCase.title}
            </div>

            <div
              style={{
                marginTop: 8,
                fontSize: 13,
                color: "#5a6a88",
              }}
            >
              {activeCase.type}
              {" · "}
              {activeCase.status}
              {" · "}
              Assigned to{" "}
              {activeCase.analyst}
            </div>
          </div>

          <div
            style={{
              textAlign: "right",
            }}
          >
            <div
              style={{
                fontSize: 11,
                color: "#5a6a88",
                letterSpacing:
                  "0.08em",
              }}
            >
              THREAT SCORE
            </div>

            <div
              style={{
                fontSize: 32,
                fontWeight: 800,
                color: "#ff3b5c",
              }}
            >
              {activeCase.score}
              <span
                style={{
                  fontSize: 14,
                  color: "#5a6a88",
                }}
              >
                {" "}
                /100
              </span>
            </div>

            <div
              style={{
                fontSize: 11,
                fontWeight: 700,
                color: "#ff3b5c",
              }}
            >
              {activeCase.classification}
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div
        style={{
          display: "flex",
          gap: 4,
          marginBottom: 20,
          borderBottom:
            "1px solid #252e4a",
        }}
      >
        {[
          "Overview",
          "Indicators",
          "Infrastructure",
          "Timeline",
          "Evidence",
        ].map((tab) => (
          <button
            key={tab}
            onClick={() =>
              setActiveTab(tab)
            }
            style={{
              padding:
                "10px 16px",
              background:
                activeTab === tab
                  ? "#1e2640"
                  : "transparent",
              color:
                activeTab === tab
                  ? "#ffffff"
                  : "#64748b",
              border: "none",
              borderRadius:
                "7px 7px 0 0",
              cursor: "pointer",
              fontSize: 12,
              fontWeight:
                activeTab === tab
                  ? 600
                  : 400,
            }}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* OVERVIEW */}
      {activeTab === "Overview" && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              "1fr 1fr",
            gap: 16,
          }}
        >
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
                marginBottom: 18,
              }}
            >
              Email Information
            </div>

            {[
              [
                "From",
                email.from ||
                  "Unknown",
              ],
              [
                "To",
                email.to ||
                  "Unknown",
              ],
              [
                "Reply-To",
                email.reply_to ||
                  "None",
              ],
              [
                "Return-Path",
                email.return_path ||
                  "None",
              ],
              [
                "Subject",
                email.subject ||
                  "Unknown",
              ],
              [
                "Date",
                email.date ||
                  "Unknown",
              ],
            ].map(
              ([label, value]) => (
                <div
                  key={label}
                  style={{
                    display: "flex",
                    gap: 16,
                    padding:
                      "10px 0",
                    borderBottom:
                      "1px solid #252e4a",
                  }}
                >
                  <span
                    style={{
                      width: 100,
                      color:
                        "#5a6a88",
                      fontSize: 12,
                    }}
                  >
                    {label}
                  </span>

                  <span
                    className="mono"
                    style={{
                      color:
                        "#c8d0e8",
                      fontSize: 12,
                      wordBreak:
                        "break-all",
                    }}
                  >
                    {String(value)}
                  </span>
                </div>
              )
            )}
          </div>

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
                marginBottom: 18,
              }}
            >
              Threat Assessment
            </div>

            <div
              style={{
                padding: 16,
                borderRadius: 8,
                background:
                  "rgba(255,59,92,0.06)",
                border:
                  "1px solid rgba(255,59,92,0.2)",
                marginBottom: 16,
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  color: "#5a6a88",
                  marginBottom: 6,
                }}
              >
                CLASSIFICATION
              </div>

              <div
                style={{
                  fontSize: 18,
                  fontWeight: 700,
                  color: "#ff3b5c",
                }}
              >
                {activeCase.classification}
              </div>
            </div>

            {reasons.length > 0 ? (
              reasons.map(
                (
                  reason: any,
                  index: number
                ) => (
                  <div
                    key={index}
                    style={{
                      display:
                        "flex",
                      gap: 8,
                      marginBottom: 10,
                      fontSize: 12,
                      color:
                        "#8b96b8",
                    }}
                  >
                    <AlertTriangle
                      size={13}
                      color="#f5a623"
                    />

                    {String(reason)}
                  </div>
                )
              )
            ) : (
              <div
                style={{
                  color:
                    "#64748b",
                  fontSize: 12,
                }}
              >
                No additional threat
                reasons returned.
              </div>
            )}
          </div>
        </div>
      )}

      {/* INDICATORS */}
      {activeTab === "Indicators" && (
        <div
          className="card"
          style={{
            padding: 24,
          }}
        >
          <div
            style={{
              display: "grid",
              gridTemplateColumns:
                "repeat(4, 1fr)",
              gap: 12,
            }}
          >
            {indicators.map(
              (indicator) => (
                <div
                  key={indicator.label}
                  style={{
                    padding: 18,
                    borderRadius: 8,
                    background:
                      indicator.bad
                        ? "rgba(255,59,92,0.06)"
                        : "rgba(45,199,122,0.06)",
                    border:
                      indicator.bad
                        ? "1px solid rgba(255,59,92,0.2)"
                        : "1px solid rgba(45,199,122,0.2)",
                  }}
                >
                  {indicator.bad ? (
                    <AlertTriangle
                      size={15}
                      color="#ff3b5c"
                    />
                  ) : (
                    <CheckCircle
                      size={15}
                      color="#2dc77a"
                    />
                  )}

                  <div
                    style={{
                      marginTop: 10,
                      fontSize: 11,
                      color:
                        "#5a6a88",
                    }}
                  >
                    {indicator.label}
                  </div>

                  <div
                    style={{
                      marginTop: 4,
                      fontSize: 15,
                      fontWeight: 700,
                      color:
                        indicator.bad
                          ? "#ff3b5c"
                          : "#2dc77a",
                    }}
                  >
                    {String(
                      indicator.value
                    ).toUpperCase()}
                  </div>
                </div>
              )
            )}
          </div>
        </div>
      )}

      {/* INFRASTRUCTURE */}
      {activeTab ===
        "Infrastructure" && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              "1fr 1fr",
            gap: 16,
          }}
        >
          <div
            className="card"
            style={{
              padding: 24,
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                marginBottom: 18,
              }}
            >
              <Globe
                size={16}
                color="#9b6fff"
              />

              <span
                style={{
                  fontSize: 15,
                  fontWeight: 600,
                  color:
                    "#e8eaf6",
                }}
              >
                Domain Intelligence
              </span>
            </div>

            {[
              [
                "Domain",
                domain.domain ||
                  "Unknown",
              ],
              [
                "Registrar",
                domain.registrar ||
                  "Unknown",
              ],
              [
                "Origin IP",
                originIP,
              ],
              [
                "Location",
                location
                  ? `${location.city || "Unknown"}, ${location.country || "Unknown"}`
                  : "Unknown",
              ],
            ].map(
              ([label, value]) => (
                <div
                  key={label}
                  style={{
                    padding:
                      "9px 0",
                    display:
                      "flex",
                    gap: 12,
                    borderBottom:
                      "1px solid #252e4a",
                  }}
                >
                  <span
                    style={{
                      width: 100,
                      fontSize: 11,
                      color:
                        "#5a6a88",
                    }}
                  >
                    {label}
                  </span>

                  <span
                    className="mono"
                    style={{
                      fontSize: 12,
                      color:
                        "#c8d0e8",
                    }}
                  >
                    {String(value)}
                  </span>
                </div>
              )
            )}
          </div>

          <div
            className="card"
            style={{
              padding: 24,
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                marginBottom: 18,
              }}
            >
              <Database
                size={16}
                color="#4a9eff"
              />

              <span
                style={{
                  fontSize: 15,
                  fontWeight: 600,
                  color:
                    "#e8eaf6",
                }}
              >
                Relay Path
              </span>
            </div>

            {relayChain.length ===
            0 ? (
              <div
                style={{
                  color:
                    "#64748b",
                  fontSize: 12,
                }}
              >
                No relay hops
                returned.
              </div>
            ) : (
              relayChain.map(
                (
                  hop: any,
                  index: number
                ) => (
                  <div
                    key={index}
                    style={{
                      display:
                        "flex",
                      gap: 10,
                      marginBottom: 12,
                    }}
                  >
                    <div
                      style={{
                        width: 24,
                        height: 24,
                        borderRadius:
                          "50%",
                        background:
                          "rgba(74,158,255,0.1)",
                        display:
                          "flex",
                        alignItems:
                          "center",
                        justifyContent:
                          "center",
                        fontSize: 10,
                        color:
                          "#4a9eff",
                      }}
                    >
                      {index + 1}
                    </div>

                    <div
                      className="mono"
                      style={{
                        fontSize: 12,
                        color:
                          "#c8d0e8",
                      }}
                    >
                      {hop.ip ||
                        hop.host ||
                        hop.server ||
                        "Unknown"}
                    </div>
                  </div>
                )
              )
            )}
          </div>
        </div>
      )}

      {/* TIMELINE */}
      {activeTab === "Timeline" && (
        <div
          className="card"
          style={{
            padding: 24,
          }}
        >
          {[
            "Email analyzed by AI threat detection engine",
            `Threat score calculated: ${activeCase.score}/100`,
            "Case created from live email analysis",
            `Earliest reliable IP: ${originIP}`,
          ].map(
            (event, index) => (
              <div
                key={index}
                style={{
                  display:
                    "flex",
                  gap: 14,
                  marginBottom: 20,
                }}
              >
                <Clock
                  size={15}
                  color="#4a9eff"
                />

                <div>
                  <div
                    style={{
                      fontSize: 13,
                      color:
                        "#c8d0e8",
                    }}
                  >
                    {event}
                  </div>

                  <div
                    style={{
                      fontSize: 11,
                      color:
                        "#5a6a88",
                      marginTop: 4,
                    }}
                  >
                    AI Forensic Engine
                  </div>
                </div>
              </div>
            )
          )}
        </div>
      )}

      {/* EVIDENCE */}
      {activeTab === "Evidence" && (
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
              color:
                "#e8eaf6",
              marginBottom: 18,
            }}
          >
            Collected Evidence
          </div>

          <div
            style={{
              display: "grid",
              gap: 10,
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems:
                  "center",
                gap: 12,
                padding: 14,
                border:
                  "1px solid #252e4a",
                borderRadius: 8,
              }}
            >
              <Mail
                size={17}
                color="#4a9eff"
              />

              <div>
                <div
                  style={{
                    fontSize: 13,
                    color:
                      "#c8d0e8",
                    fontWeight: 600,
                  }}
                >
                  Original Email
                </div>

                <div
                  style={{
                    fontSize: 11,
                    color:
                      "#5a6a88",
                    marginTop: 3,
                  }}
                >
                  {email.subject ||
                    "Email evidence"}
                </div>
              </div>
            </div>

            <div
              style={{
                display: "flex",
                alignItems:
                  "center",
                gap: 12,
                padding: 14,
                border:
                  "1px solid #252e4a",
                borderRadius: 8,
              }}
            >
              <Globe
                size={17}
                color="#9b6fff"
              />

              <div>
                <div
                  style={{
                    fontSize: 13,
                    color:
                      "#c8d0e8",
                    fontWeight: 600,
                  }}
                >
                  Origin Infrastructure
                </div>

                <div
                  className="mono"
                  style={{
                    fontSize: 11,
                    color:
                      "#5a6a88",
                    marginTop: 3,
                  }}
                >
                  {originIP}
                </div>
              </div>
            </div>

            <div
              style={{
                display: "flex",
                alignItems:
                  "center",
                gap: 12,
                padding: 14,
                border:
                  "1px solid #252e4a",
                borderRadius: 8,
              }}
            >
              <LinkIcon
                size={17}
                color="#ff3b5c"
              />

              <div>
                <div
                  style={{
                    fontSize: 13,
                    color:
                      "#c8d0e8",
                    fontWeight: 600,
                  }}
                >
                  URL Evidence
                </div>

                <div
                  style={{
                    fontSize: 11,
                    color:
                      "#5a6a88",
                    marginTop: 3,
                  }}
                >
                  {urls.length} URL(s)
                  {" · "}
                  {suspiciousUrls.length} suspicious
                </div>
              </div>
            </div>

            <div
              style={{
                display: "flex",
                alignItems:
                  "center",
                gap: 12,
                padding: 14,
                border:
                  "1px solid #252e4a",
                borderRadius: 8,
              }}
            >
              <FileText
                size={17}
                color="#f5a623"
              />

              <div>
                <div
                  style={{
                    fontSize: 13,
                    color:
                      "#c8d0e8",
                    fontWeight: 600,
                  }}
                >
                  Attachments
                </div>

                <div
                  style={{
                    fontSize: 11,
                    color:
                      "#5a6a88",
                    marginTop: 3,
                  }}
                >
                  {attachments.length} attachment(s)
                  {" detected"}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}