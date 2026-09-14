import {
  ShieldAlert,
  Globe,
  Network,
  Link as LinkIcon,
  AlertTriangle,
  CheckCircle,
} from "lucide-react";

import type { Screen } from "../App";
import type { AnalysisResponse } from "../services/api";

interface Props {
  navigate: (s: Screen) => void;
  analysis: AnalysisResponse | null;
}

function getSenderDomain(
  email: any
) {
  const from =
    email?.from || "";

  const match =
    String(from).match(
      /@([^>\s]+)/i
    );

  return match?.[1] || "Unknown";
}

export default function ThreatIntelligence({
  navigate,
  analysis,
}: Props) {
  if (!analysis) {
    return (
      <div
        className="card"
        style={{ padding: 30 }}
      >
        <ShieldAlert
          size={28}
          color="#5a6a88"
        />

        <h3
          style={{
            color: "#e8eaf6",
            marginTop: 15,
          }}
        >
          No Threat Intelligence Available
        </h3>

        <p
          style={{
            color: "#64748b",
            fontSize: 13,
          }}
        >
          Analyze an email first to populate
          live threat intelligence.
        </p>

        <button
          className="btn-primary"
          onClick={() =>
            navigate("analyze")
          }
        >
          Analyze Email
        </button>
      </div>
    );
  }

  const email =
    analysis.email || {};

  const domainAnalysis =
    analysis.domain_analysis || {};

  const threat =
    analysis.threat_analysis || {};

  const originIP =
    analysis.earliest_reliable_ip
      ?.ip || "Unknown";

  const domain =
    domainAnalysis.domain ||
    domainAnalysis.sender_domain ||
    getSenderDomain(email);

  const ips = Array.isArray(
    analysis.ip_intelligence
  )
    ? analysis.ip_intelligence
    : [];

  const urls = Array.isArray(
    analysis.url_analysis
  )
    ? analysis.url_analysis
    : [];

  const relay = Array.isArray(
    analysis.relay_chain
  )
    ? analysis.relay_chain
    : [];

  const lookalikes =
    Array.isArray(
      analysis.lookalike_analysis
    )
      ? analysis.lookalike_analysis
      : [];

  const indicators = [
    ...(originIP !== "Unknown"
      ? [
          {
            type: "IP",
            value: originIP,
            status: "Observed",
            icon: Network,
          },
        ]
      : []),

    {
      type: "DOMAIN",
      value: domain,
      status:
        domain !== "Unknown"
          ? "Observed"
          : "Unknown",
      icon: Globe,
    },

    ...urls.map(
      (item: any) => ({
        type: "URL",
        value:
          item.url ||
          item.value ||
          "Unknown",
        status:
          item.suspicious === true
            ? "Malicious / Suspicious"
            : "Observed",
        icon: LinkIcon,
      })
    ),

    ...ips.map(
      (item: any) => ({
        type: "IP",
        value:
          item.ip ||
          "Unknown",
        status:
          item.malicious === true
            ? "Malicious"
            : item.suspicious === true
              ? "Suspicious"
              : "Observed",
        icon: Network,
      })
    ),
  ];

  const uniqueIndicators =
    indicators.filter(
      (item, index, array) =>
        array.findIndex(
          (x) =>
            x.type === item.type &&
            x.value === item.value
        ) === index
    );

  return (
    <div>
      <div
        style={{
          marginBottom: 24,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <ShieldAlert
            size={22}
            color="#ff3b5c"
          />

          <h2
            style={{
              margin: 0,
              color: "#e8eaf6",
            }}
          >
            Threat Intelligence
          </h2>
        </div>

        <p
          style={{
            color: "#5a6a88",
            fontSize: 13,
            marginTop: 7,
          }}
        >
          Live indicators extracted from the
          latest email analysis.
        </p>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "repeat(4, 1fr)",
          gap: 12,
          marginBottom: 18,
        }}
      >
        <Summary
          label="Threat Score"
          value={`${threat.fraud_score ?? 0}/100`}
          danger
        />

        <Summary
          label="IP Indicators"
          value={String(
            ips.length +
              (originIP !== "Unknown"
                ? 1
                : 0)
          )}
        />

        <Summary
          label="URLs"
          value={String(urls.length)}
          danger={urls.some(
            (u: any) =>
              u.suspicious === true
          )}
        />

        <Summary
          label="Relay Hops"
          value={String(
            relay.length
          )}
        />
      </div>

      <div
        className="card"
        style={{
          padding: 20,
          marginBottom: 18,
        }}
      >
        <div
          style={{
            fontSize: 14,
            fontWeight: 600,
            color: "#e8eaf6",
            marginBottom: 16,
          }}
        >
          Live Indicators
        </div>

        {uniqueIndicators.length ===
        0 ? (
          <div
            style={{
              color: "#64748b",
              fontSize: 13,
            }}
          >
            No indicators detected.
          </div>
        ) : (
          uniqueIndicators.map(
            (item, index) => {
              const Icon = item.icon;

              const lowerStatus =
                item.status.toLowerCase();

              const dangerous =
                lowerStatus.includes(
                  "malicious"
                ) ||
                lowerStatus.includes(
                  "suspicious"
                );

              return (
                <div
                  key={`${item.type}-${index}`}
                  style={{
                    display: "flex",
                    alignItems:
                      "center",
                    gap: 14,
                    padding:
                      "13px 0",
                    borderBottom:
                      "1px solid #252e4a",
                  }}
                >
                  <Icon
                    size={16}
                    color={
                      dangerous
                        ? "#ff3b5c"
                        : "#4a9eff"
                    }
                  />

                  <div
                    style={{
                      width: 80,
                      fontSize: 10,
                      fontWeight: 700,
                      color: "#5a6a88",
                    }}
                  >
                    {item.type}
                  </div>

                  <div
                    className="mono"
                    style={{
                      flex: 1,
                      fontSize: 12,
                      color: "#c8d0e8",
                      wordBreak:
                        "break-all",
                    }}
                  >
                    {item.value}
                  </div>

                  <div
                    style={{
                      display: "flex",
                      alignItems:
                        "center",
                      gap: 5,
                      fontSize: 11,
                      color: dangerous
                        ? "#ff3b5c"
                        : item.status ===
                            "Unknown"
                          ? "#64748b"
                          : "#2dc77a",
                    }}
                  >
                    {dangerous ? (
                      <AlertTriangle
                        size={12}
                      />
                    ) : (
                      <CheckCircle
                        size={12}
                      />
                    )}

                    {item.status}
                  </div>
                </div>
              );
            }
          )
        )}
      </div>

      {lookalikes.length > 0 && (
        <div
          className="card"
          style={{
            padding: 20,
            marginBottom: 18,
          }}
        >
          <div
            style={{
              display: "flex",
              gap: 8,
              alignItems: "center",
              color: "#e8eaf6",
              fontSize: 14,
              fontWeight: 600,
              marginBottom: 15,
            }}
          >
            <AlertTriangle
              size={15}
              color="#f5a623"
            />

            Domain Lookalikes
          </div>

          {lookalikes.map(
            (item: any, index) => (
              <div
                key={index}
                className="mono"
                style={{
                  padding: 10,
                  background:
                    "#151c2f",
                  borderRadius: 6,
                  marginBottom: 7,
                  fontSize: 12,
                  color: "#f5a623",
                }}
              >
                {item.domain ||
                  item.value ||
                  JSON.stringify(item)}
              </div>
            )
          )}
        </div>
      )}

      <div
        className="card"
        style={{
          padding: 20,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            color: "#e8eaf6",
            fontSize: 14,
            fontWeight: 600,
            marginBottom: 16,
          }}
        >
          <Network
            size={15}
            color="#9b6fff"
          />

          Observed Relay Infrastructure
        </div>

        {relay.length === 0 ? (
          <div
            style={{
              color: "#64748b",
              fontSize: 12,
            }}
          >
            No relay infrastructure
            returned.
          </div>
        ) : (
          relay.map(
            (hop: any, index) => (
              <div
                key={index}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  padding: 10,
                  borderBottom:
                    "1px solid #252e4a",
                }}
              >
                <span
                  style={{
                    width: 24,
                    height: 24,
                    borderRadius:
                      "50%",
                    background:
                      "rgba(155,111,255,0.1)",
                    display: "flex",
                    alignItems:
                      "center",
                    justifyContent:
                      "center",
                    color: "#9b6fff",
                    fontSize: 11,
                  }}
                >
                  {index + 1}
                </span>

                <span
                  className="mono"
                  style={{
                    fontSize: 12,
                    color: "#c8d0e8",
                  }}
                >
                  {hop.ip ||
                    hop.host ||
                    hop.server ||
                    "Unknown"}
                </span>
              </div>
            )
          )
        )}
      </div>
    </div>
  );
}

function Summary({
  label,
  value,
  danger = false,
}: {
  label: string;
  value: string;
  danger?: boolean;
}) {
  return (
    <div
      className="card"
      style={{
        padding: 18,
      }}
    >
      <div
        style={{
          fontSize: 10,
          color: "#5a6a88",
          marginBottom: 7,
        }}
      >
        {label.toUpperCase()}
      </div>

      <div
        style={{
          fontSize: 20,
          fontWeight: 800,
          color: danger
            ? "#ff3b5c"
            : "#e8eaf6",
        }}
      >
        {value}
      </div>
    </div>
  );
}