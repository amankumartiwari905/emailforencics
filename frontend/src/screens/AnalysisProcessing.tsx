import {
  CheckCircle,
  Circle,
  Loader,
} from "lucide-react";

const steps = [
  "Email parsed",
  "Headers extracted",
  "Authentication analyzed",
  "Threat detection running",
  "URL intelligence",
  "IP geolocation",
  "Threat intelligence correlation",
];

export default function AnalysisProcessing() {
  return (
    <div
      style={{
        maxWidth: 720,
        margin: "0 auto",
        paddingTop: 40,
      }}
    >
      {/* Header */}
      <div
        style={{
          textAlign: "center",
          marginBottom: 40,
        }}
      >
        <div
          style={{
            width: 60,
            height: 60,
            borderRadius: "50%",
            background:
              "rgba(74,124,255,0.1)",
            border:
              "1px solid rgba(74,124,255,0.2)",
            margin: "0 auto 16px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Loader
            size={24}
            color="#4a7cff"
            style={{
              animation:
                "spin 1s linear infinite",
            }}
          />
        </div>

        <h2
          style={{
            fontSize: 22,
            fontWeight: 700,
            color: "#e8eaf6",
            margin: "0 0 8px",
          }}
        >
          Analyzing Email
        </h2>

        <p
          style={{
            fontSize: 14,
            color: "#5a6a88",
            margin: 0,
          }}
        >
          Running the MailTrace AI threat detection
          pipeline...
        </p>
      </div>

      {/* Progress */}
      <div style={{ marginBottom: 36 }}>
        <div
          style={{
            display: "flex",
            justifyContent:
              "space-between",
            marginBottom: 8,
          }}
        >
          <span
            style={{
              fontSize: 12,
              color: "#5a6a88",
            }}
          >
            Backend analysis in progress
          </span>

          <span
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: "#4a7cff",
            }}
          >
            ANALYZING
          </span>
        </div>

        <div
          style={{
            height: 6,
            background: "#252e4a",
            borderRadius: 3,
            overflow: "hidden",
          }}
        >
          <div
            style={{
              height: "100%",
              width: "65%",
              background:
                "linear-gradient(90deg, #4a7cff, #7a5cff)",
              borderRadius: 3,
              animation:
                "progress 1.5s ease-in-out infinite",
            }}
          />
        </div>
      </div>

      {/* Pipeline */}
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
            color: "#8b96b8",
            letterSpacing: "0.05em",
            marginBottom: 18,
          }}
        >
          ANALYSIS PIPELINE
        </div>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 16,
          }}
        >
          {steps.map((step, index) => {
            const active =
              index === 3;

            const done =
              index < 3;

            return (
              <div
                key={step}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                }}
              >
                {done ? (
                  <CheckCircle
                    size={17}
                    color="#2dc77a"
                  />
                ) : active ? (
                  <Loader
                    size={17}
                    color="#4a7cff"
                    style={{
                      animation:
                        "spin 1s linear infinite",
                    }}
                  />
                ) : (
                  <Circle
                    size={17}
                    color="#64748b"
                  />
                )}

                <span
                  style={{
                    fontSize: 13,
                    color: done
                      ? "#64748b"
                      : active
                      ? "#e8eaf6"
                      : "#4a5a78",
                  }}
                >
                  {step}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      <div
        style={{
          textAlign: "center",
          marginTop: 24,
          fontSize: 12,
          color: "#4a5a78",
        }}
      >
        Please wait while the backend analyzes the
        email...
      </div>

      <style>{`
        @keyframes spin {
          to {
            transform: rotate(360deg);
          }
        }

        @keyframes progress {
          0% {
            transform: translateX(-80%);
          }

          50% {
            transform: translateX(20%);
          }

          100% {
            transform: translateX(100%);
          }
        }
      `}</style>
    </div>
  );
}