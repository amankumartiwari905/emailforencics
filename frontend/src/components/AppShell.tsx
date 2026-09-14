import { useState } from "react";
import {
  Shield, Mail, LayoutDashboard, Search, Bell, HelpCircle,
  ChevronLeft, ChevronRight, Settings, User, FileText,
  AlertTriangle, Database, Globe, MapPin, GitBranch,
  FolderOpen, History, ChevronDown, Activity, CheckCircle,
  BarChart2, Network
} from "lucide-react";
import type { Screen } from "../../src/App";

interface Props {
  screen: Screen;
  navigate: (s: Screen) => void;
  collapsed: boolean;
  setCollapsed: (v: boolean) => void;
  children: React.ReactNode;
}

const navGroups = [
  {
    label: "OVERVIEW",
    items: [
      { id: "dashboard" as Screen, icon: LayoutDashboard, label: "Dashboard" },
    ],
  },
  {
    label: "EMAIL SECURITY",
    items: [
      { id: "analyze" as Screen, icon: Mail, label: "Analyze Email" },
      { id: "spam-tracker" as Screen, icon: BarChart2, label: "Spam Tracker" },
      { id: "history" as Screen, icon: History, label: "Analysis History" },
      { id: "alerts" as Screen, icon: AlertTriangle, label: "Alerts" },
    ],
  },
  {
    label: "INVESTIGATION",
    items: [
      { id: "cases" as Screen, icon: FolderOpen, label: "Cases" },
      { id: "threat-intel" as Screen, icon: Database, label: "Threat Intelligence" },
      { id: "relay-path" as Screen, icon: GitBranch, label: "Infrastructure" },
      { id: "server-trace" as Screen, icon: Network, label: "Server Trace" },
      { id: "ip-geo" as Screen, icon: MapPin, label: "Geo Investigation" },
    ],
  },
  {
    label: "REPORTS",
    items: [
      { id: "forensic-report" as Screen, icon: FileText, label: "Forensic Reports" },
    ],
  },
  {
    label: "SYSTEM",
    items: [
      { id: "settings" as Screen, icon: Settings, label: "Settings" },
    ],
  },
];

const breadcrumbs: Record<Screen, string[]> = {
  login: [],
  processing: ["Email Security", "Analyze Email"],
  dashboard: ["Overview"],
  analyze: ["Email Security", "Analyze Email"],
  result: ["Email Security", "Analyze Email", "Analysis Result"],
  "header-forensics": ["Email Security", "Analyze Email", "Header Forensics"],
  "url-domain": ["Investigation", "URL & Domain Intelligence"],
  "ip-geo": ["Investigation", "Geo Investigation"],
  "relay-path": ["Investigation", "Infrastructure"],
  "threat-intel": ["Investigation", "Threat Intelligence"],
  cases: ["Investigation", "Cases"],
  "case-details": ["Investigation", "Cases", "Case Details"],
  "forensic-report": ["Reports", "Forensic Reports"],
  alerts: ["Email Security", "Alerts"],
  history: ["Email Security", "Analysis History"],
  settings: ["System", "Settings"],
  "spam-tracker": ["Email Security", "Spam Tracker"],
  "server-trace": ["Investigation", "Server Trace"],
};

const pageTitles: Record<Screen, string> = {
  login: "",
  processing: "Analyzing Email",
  dashboard: "Security Overview",
  analyze: "Analyze Email",
  result: "Email Threat Analysis",
  "header-forensics": "Header Forensics",
  "url-domain": "URL & Domain Intelligence",
  "ip-geo": "Origin & GeoLocation",
  "relay-path": "Email Transmission Trace",
  "threat-intel": "Threat Intelligence",
  cases: "Investigation Cases",
  "case-details": "Case Details",
  "forensic-report": "Forensic Report",
  alerts: "Security Alerts",
  history: "Analysis History",
  settings: "Settings",
  "spam-tracker": "Spam Tracker",
  "server-trace": "Server Trace",
};

export default function AppShell({ screen, navigate, collapsed, setCollapsed, children }: Props) {
  const [searchVal, setSearchVal] = useState("");
  const crumbs = breadcrumbs[screen] || [];

  return (
    <div className="flex h-full" style={{ background: "#111627" }}>
      {/* Sidebar */}
      <aside
        style={{
          width: collapsed ? 64 : 240,
          minWidth: collapsed ? 64 : 240,
          background: "#161c2d",
          borderRight: "1px solid #1e2848",
          display: "flex",
          flexDirection: "column",
          transition: "width 0.2s ease, min-width 0.2s ease",
          overflow: "hidden",
        }}
      >
        {/* Logo */}
        <div style={{ padding: "20px 16px 16px", borderBottom: "1px solid #1e2848", flexShrink: 0 }}>
          <div className="flex items-center gap-3">
            <div style={{
              width: 32, height: 32, borderRadius: 8, flexShrink: 0,
              background: "linear-gradient(135deg, #4a7cff 0%, #7a5cff 100%)",
              display: "flex", alignItems: "center", justifyContent: "center"
            }}>
              <Shield size={16} color="#fff" />
            </div>
            {!collapsed && (
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: "#dde2f0", lineHeight: 1.2 }}>MailTrace AI</div>
                <div style={{ fontSize: 10, color: "#4a5a78", letterSpacing: "0.08em" }}>THREAT INTELLIGENCE</div>
              </div>
            )}
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, overflowY: "auto", padding: "12px 8px" }}>
          {navGroups.map((group) => (
            <div key={group.label} style={{ marginBottom: 8 }}>
              {!collapsed && (
                <div style={{ fontSize: 10, fontWeight: 600, color: "#3a4a68", letterSpacing: "0.1em", padding: "8px 8px 4px" }}>
                  {group.label}
                </div>
              )}
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = screen === item.id;
                return (
                  <div
                    key={item.id}
                    title={collapsed ? item.label : undefined}
                    onClick={() => navigate(item.id)}
                    className="nav-item"
                    style={{
                      background: isActive ? "rgba(74,124,255,0.15)" : undefined,
                      color: isActive ? "#7aabff" : undefined,
                      justifyContent: collapsed ? "center" : undefined,
                      padding: collapsed ? "9px" : undefined,
                    }}
                  >
                    <Icon size={16} style={{ flexShrink: 0 }} />
                    {!collapsed && <span>{item.label}</span>}
                  </div>
                );
              })}
              {collapsed && <div style={{ height: 4 }} />}
            </div>
          ))}
        </nav>

        {/* Bottom */}
        <div style={{ borderTop: "1px solid #3a4460", padding: "12px 8px", flexShrink: 0 }}>
          {!collapsed && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 8px", marginBottom: 8 }}>
              <div style={{
                width: 32, height: 32, borderRadius: "50%", flexShrink: 0,
                background: "linear-gradient(135deg, #4a7cff, #7a5cff)",
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 13, fontWeight: 600, color: "#fff"
              }}>A1</div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: "#eef0f6", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>Analyst 01</div>
                <div style={{ fontSize: 11, color: "#6b7694" }}>SOC Analyst</div>
              </div>
              <Settings size={14} color="#6b7694" style={{ cursor: "pointer" }} onClick={() => navigate("settings")} />
            </div>
          )}
          <button
            onClick={() => setCollapsed(!collapsed)}
            style={{
              width: "100%", display: "flex", alignItems: "center", justifyContent: collapsed ? "center" : "flex-start",
              gap: 8, padding: "7px 8px", background: "transparent", border: "none",
              borderRadius: 8, color: "#6b7694", cursor: "pointer", fontSize: 12, fontWeight: 500,
              transition: "all 0.15s"
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = "#2c3550"; (e.currentTarget as HTMLButtonElement).style.color = "#9aa3be"; }}
            onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = "transparent"; (e.currentTarget as HTMLButtonElement).style.color = "#6b7694"; }}
          >
            {collapsed ? <ChevronRight size={14} /> : <><ChevronLeft size={14} /><span>Collapse</span></>}
          </button>
        </div>
      </aside>

      {/* Main */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, overflow: "hidden" }}>
        {/* Top Nav */}
        <header style={{
          height: 56, borderBottom: "1px solid #1e2848", background: "#141829",
          display: "flex", alignItems: "center", padding: "0 24px", gap: 16, flexShrink: 0
        }}>
          {/* Breadcrumb */}
          <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
            {crumbs.map((crumb, i) => (
              <span key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                {i > 0 && <ChevronDown size={12} color="#2a3a58" style={{ transform: "rotate(-90deg)" }} />}
                <span style={{ fontSize: 12, color: i === crumbs.length - 1 ? "#4a7cff" : "#5a6a88", whiteSpace: "nowrap" }}>{crumb}</span>
              </span>
            ))}
          </div>

          <div style={{ flex: 1 }} />

          {/* Search */}
          <div style={{ position: "relative", width: 280 }}>
            <Search size={14} color="#3d4d68" style={{ position: "absolute", left: 10, top: "50%", transform: "translateY(-50%)" }} />
            <input
              value={searchVal}
              onChange={e => setSearchVal(e.target.value)}
              placeholder="Search IPs, domains, cases..."
              style={{ width: "100%", paddingLeft: 32, paddingRight: 12, height: 34, fontSize: 13, background: "#0e1323", border: "1px solid #1e2848", color: "#8b96b8" }}
            />
          </div>

          {/* Status + Actions */}
          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 10px", background: "rgba(45,199,122,0.10)", border: "1px solid rgba(45,199,122,0.25)", borderRadius: 20, marginRight: 4 }}>
              <CheckCircle size={12} color="#2dc77a" />
              <span style={{ fontSize: 11, color: "#2dc77a", fontWeight: 500, whiteSpace: "nowrap" }}>All Systems Operational</span>
            </div>
            <button className="btn-ghost" style={{ padding: "7px", position: "relative" }}>
              <Bell size={16} />
              <span style={{ position: "absolute", top: 5, right: 5, width: 7, height: 7, background: "#e8284a", borderRadius: "50%", border: "1.5px solid #e4e7f2" }} />
            </button>
            <button className="btn-ghost" style={{ padding: "7px" }}><HelpCircle size={16} /></button>
            <div style={{ width: 32, height: 32, borderRadius: "50%", background: "linear-gradient(135deg,#4a7cff,#7a5cff)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700, color: "#fff", cursor: "pointer", marginLeft: 4 }}>A1</div>
          </div>
        </header>

        {/* Page */}
        <main style={{ flex: 1, overflowY: "auto", overflowX: "hidden", padding: "28px 32px", background: "#111627" }}>
          {/* Page title row */}
          <div style={{ marginBottom: 24 }}>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: "#e8eaf6", margin: 0, fontFamily: "'Plus Jakarta Sans', 'Inter', sans-serif", letterSpacing: "-0.02em" }}>{pageTitles[screen]}</h1>
          </div>
          {children}
        </main>
      </div>
    </div>
  );
}
