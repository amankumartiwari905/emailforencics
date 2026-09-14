import {
  ArrowLeft,
  MapPin,
  AlertTriangle,
  Info,
} from "lucide-react";

import type { Screen } from "../App";
import type { AnalysisResponse } from "../services/api";

interface Props {
  navigate: (s: Screen) => void;
  analysis: AnalysisResponse;
}

export default function IpGeolocation({
  navigate,
  analysis,
}: Props) {
  const earliest =
    analysis.earliest_reliable_ip ||
    {};

  const originIP =
    earliest.ip || "Unknown";

  const locations =
    analysis.ip_locations || {};

  const location =
    locations[originIP] || {};

  const intel =
    Array.isArray(
      analysis.ip_intelligence
    )
      ? analysis.ip_intelligence.find(
          (item: any) =>
            item.ip === originIP
        )
      : null;

  const relayChain =
    Array.isArray(
      analysis.relay_chain
    )
      ? analysis.relay_chain
      : [];

  const country =
    location.country ||
    intel?.country ||
    "Unknown";

  const city =
    location.city ||
    intel?.city ||
    "Unknown";

  const countryCode =
    location.country_code ||
    intel?.country_code ||
    "";

  const provider =
    intel?.provider ||
    "Unknown";

  const organization =
    intel?.organization ||
    "Unknown";

  const asn =
    intel?.asn ||
    "Unknown";

  const isPrivate =
    intel?.status ===
    "private_ip";

  const risk =
    intel?.risk_score;

  const confidence =
    earliest.confidence ||
    "Unknown";

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

      {/* IP summary */}
      <div
        className="card threat-fail"
        style={{
          padding: 24,
          marginBottom: 20,
        }}
      >
        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              "auto 1fr auto",
            gap: 24,
            alignItems: "center",
          }}
        >
          <div
            style={{
              textAlign: "center",
            }}
          >
            <div
              style={{
                fontSize: 11,
                color: "#5a6a88",
                marginBottom: 8,
              }}
            >
              EARLIEST RELIABLE IP
            </div>

            <span
              className="mono"
              style={{
                fontSize: 22,
                fontWeight: 700,
                color: "#4a9eff",
              }}
            >
              {originIP}
            </span>
          </div>

          <div
            style={{
              display: "grid",
              gridTemplateColumns:
                "repeat(3, 1fr)",
              gap: 20,
            }}
          >
            {[
              {
                label: "Status",
                value:
                  intel?.status ||
                  "Unknown",
                color:
                  isPrivate
                    ? "#f5a623"
                    : "#2dc77a",
              },
              {
                label: "Country",
                value:
                  `${country}${
                    countryCode
                      ? ` (${countryCode})`
                      : ""
                  }`,
                color:
                  "#e8eaf6",
              },
              {
                label: "City",
                value: city,
                color:
                  "#8b96b8",
              },
              {
                label: "Provider",
                value: provider,
                color:
                  "#8b96b8",
              },
              {
                label: "Organization",
                value:
                  organization,
                color:
                  "#8b96b8",
              },
              {
                label: "ASN",
                value: String(asn),
                color:
                  "#4a9eff",
              },
            ].map((item) => (
              <div
                key={item.label}
              >
                <div
                  style={{
                    fontSize: 11,
                    color:
                      "#5a6a88",
                    marginBottom: 4,
                  }}
                >
                  {item.label}
                </div>

                <div
                  className="mono"
                  style={{
                    fontSize: 13,
                    fontWeight: 600,
                    color:
                      item.color,
                  }}
                >
                  {item.value}
                </div>
              </div>
            ))}
          </div>

          <span
            style={{
              padding:
                "4px 12px",
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 700,
              color:
                isPrivate
                  ? "#f5a623"
                  : "#2dc77a",
              background:
                isPrivate
                  ? "rgba(245,166,35,0.1)"
                  : "rgba(45,199,122,0.1)",
            }}
          >
            {isPrivate
              ? "PRIVATE IP"
              : "PUBLIC IP"}
          </span>
        </div>
      </div>

      {/* Main */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "1fr 320px",
          gap: 16,
          marginBottom: 20,
        }}
      >
        {/* Location */}
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
            Geographic Origin
          </div>

          <div
            style={{
              position: "relative",
              height: 240,
              background:
                "#151c2f",
              borderRadius: 10,
              overflow: "hidden",
              border:
                "1px solid #252e4a",
            }}
          >
            <svg
              viewBox="0 0 800 400"
              style={{
                width: "100%",
                height: "100%",
                opacity: 0.4,
              }}
            >
              <path
                d="M80,120 Q120,100 160,110 Q180,140 160,170 Q140,190 100,180 Q70,160 80,120Z"
                fill="none"
                stroke="#b4bdd4"
                strokeWidth="1.5"
              />

              <path
                d="M200,80 Q280,60 360,80 Q400,100 410,140 Q380,180 320,190 Q260,185 230,160 Q200,130 200,80Z"
                fill="none"
                stroke="#b4bdd4"
                strokeWidth="1.5"
              />

              <path
                d="M440,100 Q500,80 560,90 Q600,110 620,150 Q610,190 570,200 Q510,205 470,180 Q440,155 440,100Z"
                fill="none"
                stroke="#b4bdd4"
                strokeWidth="1.5"
              />

              <path
                d="M440,210 Q500,200 560,215 Q600,240 590,280 Q550,310 490,310 Q450,290 435,260 Q430,235 440,210Z"
                fill="none"
                stroke="#b4bdd4"
                strokeWidth="1.5"
              />

              {[100, 200, 300].map(
                (y) => (
                  <line
                    key={y}
                    x1="0"
                    y1={y}
                    x2="800"
                    y2={y}
                    stroke="#252e4a"
                    strokeWidth="0.5"
                  />
                )
              )}

              {[100, 200, 300, 400, 500, 600, 700].map(
                (x) => (
                  <line
                    key={x}
                    x1={x}
                    y1="0"
                    x2={x}
                    y2="400"
                    stroke="#252e4a"
                    strokeWidth="0.5"
                  />
                )
              )}
            </svg>

            {/* Origin marker */}
            <div
              style={{
                position:
                  "absolute",
                left: "68%",
                top: "42%",
                transform:
                  "translate(-50%,-50%)",
              }}
            >
              <div
                style={{
                  width: 14,
                  height: 14,
                  borderRadius:
                    "50%",
                  background:
                    "#ff3b5c",
                  boxShadow:
                    "0 0 12px rgba(255,59,92,0.6)",
                  border:
                    "2px solid white",
                }}
              />

              <div
                style={{
                  position:
                    "absolute",
                  top: "100%",
                  left: "50%",
                  transform:
                    "translateX(-50%)",
                  marginTop: 6,
                  whiteSpace:
                    "nowrap",
                }}
              >
                <div
                  className="mono"
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    color:
                      "#ff3b5c",
                    textAlign:
                      "center",
                  }}
                >
                  {originIP}
                </div>

                <div
                  style={{
                    fontSize: 10,
                    color:
                      "#5a6a88",
                    textAlign:
                      "center",
                  }}
                >
                  {city}, {country}
                </div>
              </div>
            </div>
          </div>

          <div
            style={{
              marginTop: 16,
              padding:
                "12px 14px",
              background:
                "#151c2f",
              borderRadius: 8,
              border:
                "1px solid #252e4a",
            }}
          >
            <div
              style={{
                fontSize: 11,
                color: "#5a6a88",
                marginBottom: 6,
              }}
            >
              GEOLOCATION
            </div>

            <div
              style={{
                fontSize: 15,
                fontWeight: 600,
                color: "#e8eaf6",
              }}
            >
              {city}, {country}
            </div>

            <div
              className="mono"
              style={{
                fontSize: 11,
                color: "#5a6a88",
                marginTop: 4,
              }}
            >
              Latitude:{" "}
              {location.latitude ??
                "Unknown"}{" "}
              · Longitude:{" "}
              {location.longitude ??
                "Unknown"}
            </div>
          </div>

          <div
            style={{
              marginTop: 12,
              padding:
                "10px 14px",
              background:
                "rgba(74,124,255,0.06)",
              border:
                "1px solid rgba(74,124,255,0.15)",
              borderRadius: 8,
              display: "flex",
              gap: 10,
            }}
          >
            <Info
              size={14}
              color="#4a9eff"
            />

            <p
              style={{
                fontSize: 12,
                color: "#5a6a88",
                margin: 0,
                lineHeight: 1.6,
              }}
            >
              Geolocation estimates the network
              location of an IP. It does not establish
              the physical identity of the sender.
            </p>
          </div>
        </div>

        {/* IP intelligence */}
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
              marginBottom: 20,
            }}
          >
            IP Intelligence
          </div>

          {[
            [
              "VPN",
              intel?.vpn,
            ],
            [
              "Proxy",
              intel?.proxy,
            ],
            [
              "TOR",
              intel?.tor,
            ],
            [
              "Hosting",
              intel?.hosting,
            ],
            [
              "Anonymous",
              intel?.anonymous,
            ],
            [
              "Compromised",
              intel?.compromised,
            ],
          ].map(
            ([label, value]) => (
              <div
                key={String(label)}
                style={{
                  display:
                    "flex",
                  justifyContent:
                    "space-between",
                  padding:
                    "11px 0",
                  borderBottom:
                    "1px solid #252e4a",
                }}
              >
                <span
                  style={{
                    fontSize: 12,
                    color:
                      "#5a6a88",
                  }}
                >
                  {label}
                </span>

                <span
                  style={{
                    fontSize: 12,
                    fontWeight: 700,
                    color:
                      value === true
                        ? "#ff3b5c"
                        : value === false
                        ? "#2dc77a"
                        : "#8b96b8",
                  }}
                >
                  {value === true
                    ? "YES"
                    : value === false
                    ? "NO"
                    : "N/A"}
                </span>
              </div>
            )
          )}

          <div
            style={{
              marginTop: 20,
              padding:
                "14px 16px",
              background:
                "rgba(74,124,255,0.06)",
              borderRadius: 8,
            }}
          >
            <div
              style={{
                fontSize: 11,
                color: "#5a6a88",
              }}
            >
              TRACE CONFIDENCE
            </div>

            <div
              style={{
                fontSize: 18,
                fontWeight: 700,
                color: "#4a9eff",
                marginTop: 4,
              }}
            >
              {confidence}
            </div>

            {risk != null && (
              <div
                style={{
                  marginTop: 8,
                  fontSize: 12,
                  color: "#8b96b8",
                }}
              >
                Risk score: {risk}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Relay IPs */}
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
          IPs Found in Relay Chain
        </div>

        {relayChain.map(
          (node: any, i: number) => (
            <div
              key={i}
              style={{
                display:
                  "flex",
                alignItems:
                  "center",
                gap: 12,
                padding:
                  "12px 0",
                borderBottom:
                  i <
                  relayChain.length -
                    1
                    ? "1px solid #252e4a"
                    : "none",
              }}
            >
              <MapPin
                size={15}
                color={
                  node.ip ===
                  originIP
                    ? "#ff3b5c"
                    : "#4a9eff"
                }
              />

              <span
                style={{
                  fontSize: 11,
                  color:
                    "#5a6a88",
                  width: 70,
                }}
              >
                HOP{" "}
                {node.hop_index}
              </span>

              <span
                className="mono"
                style={{
                  fontSize: 13,
                  color:
                    "#c8d0e8",
                }}
              >
                {node.ip}
              </span>

              {node.ip ===
                originIP && (
                <span
                  style={{
                    fontSize: 10,
                    color:
                      "#ff3b5c",
                    fontWeight: 700,
                  }}
                >
                  EARLIEST RELIABLE
                </span>
              )}
            </div>
          )
        )}
      </div>
    </div>
  );
}