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

export default function App() {
  const [screen, setScreen] = useState<Screen>("login");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  if (screen === "login") {
    return <Login onLogin={() => setScreen("dashboard")} />;
  }

  if (screen === "processing") {
    return (
      <AnalysisProcessing
        onComplete={() => setScreen("result")}
      />
    );
  }

  const screenMap: Record<Screen, React.ReactNode> = {
    login: null,
    processing: null,

    dashboard: (
      <Dashboard navigate={setScreen} />
    ),

    analyze: (
      <AnalyzeEmail
        onAnalyze={() => setScreen("processing")}
      />
    ),

    result: (
      <AnalysisResult navigate={setScreen} />
    ),

    "header-forensics": (
      <HeaderForensics navigate={setScreen} />
    ),

    "url-domain": (
      <UrlDomainIntelligence navigate={setScreen} />
    ),

    "ip-geo": (
      <IpGeolocation navigate={setScreen} />
    ),

    "relay-path": (
      <RelayPath navigate={setScreen} />
    ),

    "threat-intel": (
      <ThreatIntelligence navigate={setScreen} />
    ),

    cases: (
      <Cases navigate={setScreen} />
    ),

    "case-details": (
      <CaseDetails navigate={setScreen} />
    ),

    "forensic-report": (
      <ForensicReport navigate={setScreen} />
    ),

    alerts: (
      <Alerts navigate={setScreen} />
    ),

    history: (
      <AnalysisHistory navigate={setScreen} />
    ),

    settings: (
      <Settings />
    ),

    "spam-tracker": (
      <SpamTracker navigate={setScreen} />
    ),

    "server-trace": (
      <ServerTrace navigate={setScreen} />
    ),
  };

  return (
    <AppShell
      screen={screen}
      navigate={setScreen}
      collapsed={sidebarCollapsed}
      setCollapsed={setSidebarCollapsed}
    >
      {screenMap[screen]}
    </AppShell>
  );
}