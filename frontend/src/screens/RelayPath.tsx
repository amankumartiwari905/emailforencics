import {
  ArrowLeft,
  ArrowDown,
} from "lucide-react";

import type { Screen } from "../App";
import type { AnalysisResponse } from "../services/api";

interface Props {
  navigate: (s: Screen) => void;
  analysis: AnalysisResponse;
}

export default function RelayPath({
  navigate,
  analysis,
}: Props) {
  const chain =
    Array.isArray(
      analysis.relay_chain
    )
      ? analysis.relay_chain
      : [];

  const earliest =
    analysis.earliest_reliable_ip ||
    {};

  const comparison =
    analysis.trace_comparison ||
    {};

  const locations =
    analysis.ip_locations || {};

  const intelligence =
    Array.isArray(
      analysis.ip_intelligence
    )
      ? analysis.ip_intelligence
      : [];

  const getIntel = (ip: string) =>
    intelligence.find(
      (item: any) =>
        item.ip === ip
    );

  const getLocation = (
    ip: string
  ) => locations[ip] || {};

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

      <p
        style={{
          fontSize: 14,
          color: "#5a6a88",
          margin: "0 0 28px",
        }}
      >
        Email transmission path reconstructed from
        the actual Received headers returned by the
        backend.
      </p>

      {/* Relay chain */}
      <div
        style={{
          display: "flex",
          flexDirection:
            "column",
          alignItems: "center",
          marginBottom: 28,
        }}
      >
        {chain.map(
          (node: any, i: number) => {
            const ip =
              node.ip || "Unknown";

            const intel =
              getIntel(ip);

            const loc =
              getLocation(ip);

            const isOrigin =
              ip === earliest.ip;

            const isPrivate =
              intel?.status ===
              "private_ip";

            const color =
              isOrigin
                ? "#ff3b5c"
                : isPrivate
                ? "#f5a623"
                : "#4a9eff";

            return (
              <div
                key={i}
                style={{
                  width: "100%",
                  maxWidth: 720,
                }}
              >
                <div
                  className="card"
                  style={{
                    padding: 20,
                    borderColor:
                      `${color}40`,
                    background:
                      isOrigin
                        ? "rgba(255,59,92,0.04)"
                        : "#1a2035",
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
                      flexWrap:
                        "wrap",
                      gap: 12,
                    }}
                  >
                    <div
                      style={{
                        display:
                          "flex",
                        alignItems:
                          "center",
                        gap: 14,
                      }}
                    >
                      <div
                        style={{
                          width: 10,
                          height: 10,
                          borderRadius:
                            "50%",
                          background:
                            color,
                          boxShadow:
                            `0 0 8px ${color}60`,
                        }}
                      />

                      <div>
                        <div
                          style={{
                            fontSize: 11,
                            fontWeight: 700,
                            color:
                              "#5a6a88",
                          }}
                        >
                          HOP{" "}
                          {node.hop_index}
                        </div>

                        <div
                          className="mono"
                          style={{
                            fontSize: 14,
                            fontWeight: 600,
                            color:
                              "#e8eaf6",
                            marginTop: 2,
                          }}
                        >
                          {ip}
                        </div>

                        {isOrigin && (
                          <div
                            style={{
                              fontSize: 10,
                              color:
                                "#ff3b5c",
                              fontWeight: 700,
                              marginTop: 4,
                            }}
                          >
                            EARLIEST RELIABLE
                            SENDING NODE
                          </div>
                        )}
                      </div>
                    </div>

                    <div
                      style={{
                        display:
                          "flex",
                        gap: 24,
                        flexWrap:
                          "wrap",
                      }}
                    >
                      <div>
                        <div
                          style={{
                            fontSize: 10,
                            color:
                              "#5a6a88",
                          }}
                        >
                          LOCATION
                        </div>

                        <div
                          style={{
                            fontSize: 12,
                            color:
                              "#8b96b8",
                            marginTop: 2,
                          }}
                        >
                          {loc.city ||
                            intel?.city ||
                            "Unknown"}
                          {", "}
                          {loc.country_code ||
                            intel?.country_code ||
                            ""}
                        </div>
                      </div>

                      <div>
                        <div
                          style={{
                            fontSize: 10,
                            color:
                              "#5a6a88",
                          }}
                        >
                          STATUS
                        </div>

                        <div
                          className="mono"
                          style={{
                            fontSize: 12,
                            color,
                            marginTop: 2,
                          }}
                        >
                          {intel?.status ||
                            "Analyzed"}
                        </div>
                      </div>

                      <div>
                        <span
                          style={{
                            fontSize: 11,
                            fontWeight: 700,
                            padding:
                              "3px 10px",
                            borderRadius: 4,
                            background:
                              `${color}15`,
                            border:
                              `1px solid ${color}35`,
                            color,
                          }}
                        >
                          {isOrigin
                            ? "ORIGIN"
                            : isPrivate
                            ? "PRIVATE"
                            : "RELAY"}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div
                    style={{
                      fontSize: 12,
                      color:
                        "#5a6a88",
                      marginTop: 10,
                      paddingTop: 10,
                      borderTop:
                        "1px solid #252e4a",
                    }}
                  >
                    {node.all_ips
                      ? `IPs at this hop: ${node.all_ips.join(", ")}`
                      : `IP: ${ip}`}
                  </div>
                </div>

                {i <
                  chain.length -
                    1 && (
                  <div
                    style={{
                      display:
                        "flex",
                      justifyContent:
                        "center",
                      padding:
                        "8px 0",
                    }}
                  >
                    <ArrowDown
                      size={16}
                      color="#94a3b8"
                    />
                  </div>
                )}
              </div>
            );
          }
        )}
      </div>

      {/* Earliest reliable node */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "1fr 320px",
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
              marginBottom: 16,
            }}
          >
            Earliest Reliable Sending Node
          </div>

          <div
            style={{
              padding:
                "16px 20px",
              background:
                "rgba(255,59,92,0.06)",
              borderRadius: 8,
              border:
                "1px solid rgba(255,59,92,0.25)",
            }}
          >
            <div
              className="mono"
              style={{
                fontSize: 18,
                fontWeight: 700,
                color: "#ff7a4a",
              }}
            >
              {earliest.ip ||
                "Unknown"}
            </div>

            <div
              className="mono"
              style={{
                fontSize: 13,
                color: "#8b96b8",
                marginTop: 4,
              }}
            >
              {earliest.header ||
                "No header available"}
            </div>

            <div
              style={{
                fontSize: 12,
                color: "#5a6a88",
                marginTop: 8,
              }}
            >
              Confidence:{" "}
              <strong>
                {earliest.confidence ||
                  "Unknown"}
              </strong>
            </div>
          </div>
        </div>

        {/* Trace comparison */}
        <div
          className="card"
          style={{
            padding: 24,
          }}
        >
          <div
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: "#e8eaf6",
              marginBottom: 16,
            }}
          >
            Trace Comparison
          </div>

          <div
            style={{
              marginBottom: 12,
            }}
          >
            <div
              style={{
                fontSize: 10,
                color: "#5a6a88",
              }}
            >
              NAIVE TRACE
            </div>

            <div
              className="mono"
              style={{
                fontSize: 12,
                color: "#8b96b8",
                marginTop: 4,
              }}
            >
              {comparison.naive_trace
                ?.ip ||
                "Unknown"}
            </div>
          </div>

          <div
            style={{
              marginBottom: 12,
            }}
          >
            <div
              style={{
                fontSize: 10,
                color: "#5a6a88",
              }}
            >
              REASONED TRACE
            </div>

            <div
              className="mono"
              style={{
                fontSize: 12,
                color: "#4a9eff",
                marginTop: 4,
              }}
            >
              {comparison.reasoned_trace
                ?.ip ||
                "Unknown"}
            </div>
          </div>

          <div
            style={{
              padding:
                "10px 12px",
              borderRadius: 6,
              background:
                comparison.mismatch_detected
                  ? "rgba(255,59,92,0.08)"
                  : "rgba(45,199,122,0.08)",
              color:
                comparison.mismatch_detected
                  ? "#ff3b5c"
                  : "#2dc77a",
              fontSize: 11,
              fontWeight: 700,
            }}
          >
            {comparison.mismatch_detected
              ? "TRACE MISMATCH DETECTED"
              : "TRACE METHODS AGREE"}
          </div>
        </div>
      </div>
    </div>
  );
}