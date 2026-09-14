import { useState, useRef } from "react";
import {
  Upload,
  Mail,
  FileText,
  X,
  CheckSquare,
  Square,
  AlertTriangle,
} from "lucide-react";

interface Props {
  onAnalyze: (file: File) => void;
  error?: string | null;
}

const placeholder = `From: support@paypa1-secure.com
Reply-To: security-alert@paypa1-secure.com
Return-Path: <mailer@mx.paypa1-secure.com>
Subject: Urgent: Verify Your Account
Date: Sun, 31 Aug 2026 09:14:22 +0000
Message-ID: <CA+xyz123@mail.paypa1-secure.com>
MIME-Version: 1.0
Received: from mail.paypa1-secure.com (185.220.101.47) by mx.organization.com
Authentication-Results: mx.organization.com;
  spf=fail smtp.mailfrom=paypa1-secure.com;
  dkim=fail header.d=paypa1-secure.com;
  dmarc=fail

Dear Customer,

We have detected unusual activity on your account. Please verify immediately.

Click here: http://paypa1-secure.com/verify?token=abc123`;

const initialOptions = [
  {
    key: "threat",
    label: "Threat Detection",
    checked: true,
  },
  {
    key: "headers",
    label: "Header Forensics",
    checked: true,
  },
  {
    key: "url",
    label: "URL Analysis",
    checked: true,
  },
  {
    key: "domain",
    label: "Domain Intelligence",
    checked: true,
  },
  {
    key: "geo",
    label: "IP Geolocation",
    checked: true,
  },
  {
    key: "intel",
    label: "Threat Intelligence Correlation",
    checked: false,
    advanced: true,
  },
];

export default function AnalyzeEmail({
  onAnalyze,
  error,
}: Props) {
  const [tab, setTab] =
    useState<"upload" | "paste">("upload");

  const [dragging, setDragging] =
    useState(false);

  const [file, setFile] =
    useState<File | null>(null);

  const [text, setText] = useState("");

  const [opts, setOpts] =
    useState(initialOptions);

  const fileRef =
    useRef<HTMLInputElement>(null);

  const toggleOpt = (key: string) => {
    setOpts(
      opts.map((o) =>
        o.key === key
          ? {
              ...o,
              checked: !o.checked,
            }
          : o
      )
    );
  };

  const canAnalyze =
    tab === "upload"
      ? !!file
      : text.trim().length > 20;

  const startAnalysis = () => {
    if (tab === "upload") {
      if (file) {
        onAnalyze(file);
      }

      return;
    }

    if (text.trim().length > 20) {
      const pastedFile = new File(
        [text],
        "pasted-email.eml",
        {
          type: "message/rfc822",
        }
      );

      onAnalyze(pastedFile);
    }
  };

  const clearAll = () => {
    setFile(null);
    setText("");

    if (fileRef.current) {
      fileRef.current.value = "";
    }
  };

  return (
    <div style={{ maxWidth: 900 }}>
      <p
        style={{
          margin: "0 0 24px",
          fontSize: 14,
          color: "#5a6a88",
          marginTop: -8,
        }}
      >
        Upload or paste an email for comprehensive
        threat and forensic analysis.
      </p>

      {/* Error */}
      {error && (
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: 10,
            padding: "14px 16px",
            marginBottom: 20,
            borderRadius: 8,
            background: "rgba(255,59,92,0.08)",
            border:
              "1px solid rgba(255,59,92,0.25)",
            color: "#ff6b81",
            fontSize: 13,
          }}
        >
          <AlertTriangle
            size={16}
            style={{ flexShrink: 0 }}
          />

          <div>
            <div
              style={{
                fontWeight: 700,
                marginBottom: 4,
              }}
            >
              Analysis failed
            </div>

            <div>{error}</div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div
        style={{
          display: "flex",
          gap: 2,
          marginBottom: 24,
          background: "#151c2f",
          padding: 4,
          borderRadius: 10,
          width: "fit-content",
          border: "1px solid #252e4a",
        }}
      >
        {(["upload", "paste"] as const).map(
          (t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              style={{
                padding: "8px 20px",
                borderRadius: 8,
                border: "none",
                cursor: "pointer",
                fontSize: 13,
                fontWeight: 600,
                transition: "all 0.15s",
                background:
                  tab === t
                    ? "#1e2640"
                    : "transparent",
                color:
                  tab === t
                    ? "#ffffff"
                    : "#64748b",
              }}
            >
              {t === "upload"
                ? "Upload Email"
                : "Paste Email"}
            </button>
          )
        )}
      </div>

      {/* Upload */}
      {tab === "upload" ? (
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() =>
            setDragging(false)
          }
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);

            const droppedFile =
              e.dataTransfer.files[0];

            if (droppedFile) {
              setFile(droppedFile);
            }
          }}
          onClick={() =>
            fileRef.current?.click()
          }
          style={{
            border: `2px dashed ${
              dragging
                ? "#4a7cff"
                : file
                ? "#2dc77a"
                : "#252e4a"
            }`,
            borderRadius: 12,
            padding: "56px 40px",
            textAlign: "center",
            cursor: "pointer",
            background: dragging
              ? "rgba(74,124,255,0.04)"
              : file
              ? "rgba(45,199,122,0.04)"
              : "#d6daea",
            transition: "all 0.15s",
            marginBottom: 24,
          }}
        >
          <input
            ref={fileRef}
            type="file"
            accept=".eml,.msg,.txt"
            style={{ display: "none" }}
            onChange={(e) => {
              const selectedFile =
                e.target.files?.[0];

              if (selectedFile) {
                setFile(selectedFile);
              }
            }}
          />

          {file ? (
            <div>
              <div
                style={{
                  width: 48,
                  height: 48,
                  borderRadius: 10,
                  background:
                    "rgba(45,199,122,0.1)",
                  margin: "0 auto 16px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <FileText
                  size={24}
                  color="#2dc77a"
                />
              </div>

              <div
                style={{
                  fontSize: 15,
                  fontWeight: 600,
                  color: "#2dc77a",
                  marginBottom: 6,
                }}
              >
                {file.name}
              </div>

              <div
                style={{
                  fontSize: 13,
                  color: "#5a6a88",
                  marginBottom: 12,
                }}
              >
                {(file.size / 1024).toFixed(1)} KB
              </div>

              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setFile(null);

                  if (fileRef.current) {
                    fileRef.current.value = "";
                  }
                }}
                style={{
                  background:
                    "rgba(255,59,92,0.1)",
                  border:
                    "1px solid rgba(255,59,92,0.25)",
                  borderRadius: 6,
                  padding: "4px 12px",
                  color: "#ff3b5c",
                  fontSize: 12,
                  cursor: "pointer",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <X size={12} />
                Remove
              </button>
            </div>
          ) : (
            <div>
              <div
                style={{
                  width: 52,
                  height: 52,
                  borderRadius: 12,
                  background:
                    "rgba(74,124,255,0.1)",
                  border:
                    "1px solid rgba(74,124,255,0.2)",
                  margin: "0 auto 20px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Upload
                  size={22}
                  color="#4a7cff"
                />
              </div>

              <div
                style={{
                  fontSize: 16,
                  fontWeight: 600,
                  color: "#e8eaf6",
                  marginBottom: 8,
                }}
              >
                Drop .eml file here
              </div>

              <div
                style={{
                  fontSize: 14,
                  color: "#5a6a88",
                  marginBottom: 4,
                }}
              >
                or{" "}
                <span
                  style={{ color: "#4a7cff" }}
                >
                  browse from your computer
                </span>
              </div>

              <div
                style={{
                  fontSize: 12,
                  color: "#4a5a78",
                  marginTop: 12,
                }}
              >
                Supported formats: EML, MSG, TXT ·
                Maximum 25 MB
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Paste */
        <div style={{ marginBottom: 24 }}>
          <textarea
            value={text}
            onChange={(e) =>
              setText(e.target.value)
            }
            placeholder={placeholder}
            style={{
              width: "100%",
              height: 340,
              padding: 16,
              fontSize: 12,
              fontFamily:
                "'JetBrains Mono', monospace",
              lineHeight: 1.7,
              resize: "vertical",
              borderRadius: 10,
            }}
          />

          <div
            style={{
              fontSize: 12,
              color: "#4a5a78",
              marginTop: 6,
              display: "flex",
              justifyContent: "flex-end",
            }}
          >
            {text.length > 0 && (
              <span>
                {text.length.toLocaleString()}{" "}
                characters
              </span>
            )}
          </div>
        </div>
      )}

      {/* Analysis Options */}
      <div
        className="card"
        style={{
          padding: 24,
          marginBottom: 24,
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
          Analysis Options
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns:
              "1fr 1fr",
            gap: 12,
          }}
        >
          {opts
            .filter((o) => !o.advanced)
            .map((opt) => (
              <label
                key={opt.key}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  cursor: "pointer",
                }}
              >
                <div
                  onClick={() =>
                    toggleOpt(opt.key)
                  }
                  style={{
                    color: opt.checked
                      ? "#4a7cff"
                      : "#94a3b8",
                    cursor: "pointer",
                  }}
                >
                  {opt.checked ? (
                    <CheckSquare size={18} />
                  ) : (
                    <Square size={18} />
                  )}
                </div>

                <span
                  style={{
                    fontSize: 13,
                    color: "#8b96b8",
                  }}
                >
                  {opt.label}
                </span>
              </label>
            ))}
        </div>

        <div
          style={{
            borderTop:
              "1px solid #252e4a",
            marginTop: 16,
            paddingTop: 14,
          }}
        >
          <div
            style={{
              fontSize: 12,
              fontWeight: 600,
              color: "#5a6a88",
              letterSpacing: "0.05em",
              marginBottom: 10,
            }}
          >
            ADVANCED
          </div>

          {opts
            .filter((o) => o.advanced)
            .map((opt) => (
              <label
                key={opt.key}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  cursor: "pointer",
                }}
              >
                <div
                  onClick={() =>
                    toggleOpt(opt.key)
                  }
                  style={{
                    color: opt.checked
                      ? "#4a7cff"
                      : "#94a3b8",
                    cursor: "pointer",
                  }}
                >
                  {opt.checked ? (
                    <CheckSquare size={18} />
                  ) : (
                    <Square size={18} />
                  )}
                </div>

                <span
                  style={{
                    fontSize: 13,
                    color: "#8b96b8",
                  }}
                >
                  {opt.label}
                </span>
              </label>
            ))}
        </div>
      </div>

      {/* Buttons */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
        }}
      >
        <button
          className="btn-primary"
          disabled={!canAnalyze}
          onClick={startAnalysis}
          style={{
            padding: "11px 28px",
            fontSize: 14,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Mail size={15} />
          Analyze Email
        </button>

        <button
          className="btn-secondary"
          onClick={clearAll}
        >
          Clear
        </button>

        <span
          style={{
            fontSize: 13,
            color: "#4a5a78",
            marginLeft: 8,
          }}
        >
          Analysis typically takes 2–5 seconds
        </span>
      </div>
    </div>
  );
}