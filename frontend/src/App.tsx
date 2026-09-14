import { useState } from "react";

import Login from "./screens/Login";
import Dashboard from "./screens/Dashboard";
import AnalyzeEmail from "./screens/AnalyzeEmail";
import AnalysisProcessing from "./screens/AnalysisProcessing";
import AnalysisResult from "./screens/AnalysisResult";
import HeaderForensics from "./screens/HeaderForensics";
import UrlDomainIntelligence from "./screens/UrlDomainIntelligence";
import IpGeolocation from "./screens/IpGeolocation";
import RelayPath from "./screens/RelayPath";
import ThreatIntelligence from "./screens/ThreatIntelligence";
import Cases from "./screens/Cases";
import CaseDetails from "./screens/CaseDetails";
import ForensicReport from "./screens/ForensicReport";
import Alerts from "./screens/Alerts";
import AnalysisHistory from "./screens/AnalysisHistory";
import Settings from "./screens/Settings";
import SpamTracker from "./screens/SpamTracker";
import ServerTrace from "./screens/ServerTrace";

import AppShell from "./components/AppShell";

import { analyzeEmail } from "./services/api";
import type { AnalysisResponse } from "./services/api";

export type Screen =
  | "login"
  | "dashboard"
  | "analyze"
  | "processing"
  | "result"
  | "header-forensics"
  | "url-domain"
  | "ip-geo"
  | "relay-path"
  | "threat-intel"
  | "cases"
  | "case-details"
  | "forensic-report"
  | "alerts"
  | "history"
  | "settings"
  | "spam-tracker"
  | "server-trace";

export interface CaseRecord {
  id: string;
  title: string;
  severity: string;
  type: string;
  indicators: number;
  analyst: string;
  created: string;
  status: string;
  score: number;
  classification: string;
  analysis: AnalysisResponse;
}

function createCaseId() {
  const year = new Date().getFullYear();
  const random = Math.floor(
    100000 + Math.random() * 900000
  );

  return `CASE-${year}-${random}`;
}

function loadStoredCase(): CaseRecord | null {
  try {
    const saved =
      localStorage.getItem(
        "activeThreatCase"
      );

    if (!saved) return null;

    return JSON.parse(saved);
  } catch {
    return null;
  }
}

export default function App() {
  const [screen, setScreen] =
    useState<Screen>("login");

  const [sidebarCollapsed, setSidebarCollapsed] =
    useState(false);

  const [analysis, setAnalysis] =
    useState<AnalysisResponse | null>(null);

  const [analysisError, setAnalysisError] =
    useState<string | null>(null);

  const [analyzedFile, setAnalyzedFile] =
    useState<File | null>(null);

  const [activeCase, setActiveCase] =
    useState<CaseRecord | null>(
      loadStoredCase
    );

  const handleAnalyze = async (
    file: File
  ) => {
    setAnalysisError(null);
    setAnalyzedFile(file);
    setScreen("processing");

    try {
      const result =
        await analyzeEmail(file);

      setAnalysis(result);
      setScreen("result");
    } catch (error) {
      console.error(error);

      setAnalysisError(
        error instanceof Error
          ? error.message
          : "Email analysis failed"
      );

      setScreen("analyze");
    }
  };

  const handleCreateCase = () => {
    if (!analysis) {
      alert(
        "Please analyze an email first."
      );
      return;
    }

    const threat =
      analysis.threat_analysis || {};

    const email =
      analysis.email || {};

    const score = Number(
      threat.fraud_score ?? 0
    );

    const classification =
      String(
        threat.classification ??
          "UNKNOWN"
      );

    const subject =
      email.subject ||
      "Email Threat Investigation";

    const caseId = createCaseId();

    const analysisText = `
      ${classification}
      ${subject}
      ${JSON.stringify(threat)}
      ${JSON.stringify(analysis.nlp_analysis || {})}
    `.toLowerCase();

    let type = "Suspicious Email";

    if (
      analysisText.includes("phish") ||
      analysisText.includes(
        "credential_harvesting"
      ) ||
      analysisText.includes(
        "suspicious url"
      )
    ) {
      type = "Phishing";
    } else if (
      analysisText.includes("bec") ||
      analysisText.includes("fraud") ||
      analysisText.includes("invoice") ||
      analysisText.includes("payment") ||
      analysisText.includes("wire")
    ) {
      type = "BEC";
    } else if (
      analysisText.includes("malware")
    ) {
      type = "Malware";
    } else if (
      analysisText.includes("spoof") ||
      analysisText.includes("imperson")
    ) {
      type = "Spoofing";
    }

    let severity = "low";

    if (score >= 80) {
      severity = "critical";
    } else if (score >= 60) {
      severity = "high";
    } else if (score >= 30) {
      severity = "medium";
    }

    const urls = Array.isArray(
      analysis.url_analysis
    )
      ? analysis.url_analysis
      : [];

    const suspiciousUrls =
      urls.filter(
        (item: any) =>
          item.suspicious === true
      ).length;

    const relayCount = Array.isArray(
      analysis.relay_chain
    )
      ? analysis.relay_chain.length
      : 0;

    const attachmentCount =
      Array.isArray(
        analysis.attachment_analysis
      )
        ? analysis.attachment_analysis
            .length
        : 0;

    const ipCount = Array.isArray(
      analysis.ip_intelligence
    )
      ? analysis.ip_intelligence.length
      : 0;

    const indicators =
      suspiciousUrls +
      relayCount +
      attachmentCount +
      ipCount +
      2;

    const newCase: CaseRecord = {
      id: caseId,
      title: subject,
      severity,
      type,
      indicators,
      analyst: "Analyst 01",
      created: "Just now",
      status: "Investigating",
      score,
      classification,
      analysis,
    };

    setActiveCase(newCase);

    localStorage.setItem(
      "activeThreatCase",
      JSON.stringify(newCase)
    );

    setScreen("case-details");
  };

  const screenMap: Record<
    Screen,
    React.ReactNode
  > = {
    login: null,

    processing: null,

    dashboard: (
      <Dashboard
        navigate={setScreen}
      />
    ),

    analyze: (
      <AnalyzeEmail
        onAnalyze={handleAnalyze}
        error={analysisError}
      />
    ),

    result: analysis ? (
      <AnalysisResult
        navigate={setScreen}
        analysis={analysis}
        analyzedFile={analyzedFile}
        onCreateCase={
          handleCreateCase
        }
        activeCaseId={
          activeCase?.id
        }
      />
    ) : (
      <Dashboard
        navigate={setScreen}
      />
    ),

    "header-forensics": analysis ? (
      <HeaderForensics
        navigate={setScreen}
        analysis={analysis}
      />
    ) : (
      <Dashboard
        navigate={setScreen}
      />
    ),

    "url-domain": analysis ? (
      <UrlDomainIntelligence
        navigate={setScreen}
        analysis={analysis}
      />
    ) : (
      <Dashboard
        navigate={setScreen}
      />
    ),

    "ip-geo": analysis ? (
      <IpGeolocation
        navigate={setScreen}
        analysis={analysis}
      />
    ) : (
      <Dashboard
        navigate={setScreen}
      />
    ),

    "relay-path": analysis ? (
      <RelayPath
        navigate={setScreen}
        analysis={analysis}
      />
    ) : (
      <Dashboard
        navigate={setScreen}
      />
    ),

    "threat-intel": (
      <ThreatIntelligence
        navigate={setScreen}
        analysis={analysis}
      />
    ),

    cases: (
      <Cases
        navigate={setScreen}
        activeCase={activeCase}
      />
    ),

    "case-details": activeCase ? (
      <CaseDetails
        navigate={setScreen}
        activeCase={activeCase}
      />
    ) : (
      <Cases
        navigate={setScreen}
        activeCase={activeCase}
      />
    ),

    "forensic-report": (
      <ForensicReport
        navigate={setScreen}
      />
    ),

    alerts: (
      <Alerts
        navigate={setScreen}
      />
    ),

    history: (
      <AnalysisHistory
        navigate={setScreen}
      />
    ),

    settings: <Settings />,

    "spam-tracker": (
      <SpamTracker
        navigate={setScreen}
      />
    ),

    "server-trace": (
      <ServerTrace
        navigate={setScreen}
      />
    ),
  };

  if (screen === "login") {
    return (
      <Login
        onLogin={() =>
          setScreen("dashboard")
        }
      />
    );
  }

  if (screen === "processing") {
    return <AnalysisProcessing />;
  }

  return (
    <AppShell
      screen={screen}
      navigate={setScreen}
      collapsed={sidebarCollapsed}
      setCollapsed={
        setSidebarCollapsed
      }
    >
      {screenMap[screen]}
    </AppShell>
  );
}