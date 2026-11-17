import {
  BrainCircuit,
  CircleUserRound,
  History,
  LayoutDashboard,
  LogOut,
  ScanSearch,
  Search,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react";
import { useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { clearToken } from "../api";


const PRIMARY_NAV = [
  { to: "/", label: "总览", english: "Overview", icon: LayoutDashboard, end: true },
  { to: "/scan", label: "新建扫描", english: "New scan", icon: ScanSearch },
  { to: "/history", label: "历史与资产", english: "History", icon: History },
];

const SYSTEM_NAV = [
  { to: "/settings/ai", label: "AI 研判设置", english: "AI settings", icon: BrainCircuit },
];


export default function AppShell({ children }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");

  function logout() {
    clearToken();
    navigate("/login", { replace: true });
  }

  function search(event) {
    event.preventDefault();
    const value = query.trim();
    if (value) navigate(`/history?q=${encodeURIComponent(value)}`);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link to="/" className="sidebar-brand">
          <span className="brand-mark" aria-hidden="true" />
          <span className="min-w-0">
            <span className="flex items-center gap-2">
              <span className="brand-name">Surface</span>
              <span className="brand-badge">Local</span>
            </span>
            <span className="brand-subtitle">Security Control Plane</span>
          </span>
        </Link>

        <form className="sidebar-search" onSubmit={search}>
          <Search size={14} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜索资产"
            aria-label="搜索资产"
          />
          <span>↵</span>
        </form>

        <div className="sidebar-section-label">Operations</div>
        <nav className="sidebar-nav" aria-label="主导航">
          {PRIMARY_NAV.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) => `sidebar-link${isActive ? " active" : ""}`}
              >
                <Icon size={16} strokeWidth={1.8} />
                <span>{item.label}</span>
                <span className="sidebar-link-en">{item.english}</span>
              </NavLink>
            );
          })}
        </nav>

        <div className="sidebar-section-label">System</div>
        <nav className="sidebar-nav" aria-label="系统设置">
          {SYSTEM_NAV.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) => `sidebar-link${isActive ? " active" : ""}`}
              >
                <Icon size={16} strokeWidth={1.8} />
                <span>{item.label}</span>
                <span className="sidebar-link-en">{item.english}</span>
              </NavLink>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <div className="environment-card">
            <div className="environment-row">
              <span className="environment-title">Local runtime</span>
              <span className="environment-status">
                <span className="status-dot" />
                Online
              </span>
            </div>
            <div className="mt-3 flex items-center gap-2 text-[9px] text-[#71717a]">
              <ShieldCheck size={12} />
              JWT secured · Docker isolated
            </div>
            <div className="mt-2 flex items-center gap-2 text-[9px] text-[#71717a]">
              <TerminalSquare size={12} />
              Multi-engine · 19 nodes
            </div>
          </div>
          <div className="operator-card">
            <CircleUserRound size={28} />
            <div className="min-w-0">
              <strong>Administrator</strong>
              <span>Local operator</span>
            </div>
            <button type="button" onClick={logout} aria-label="退出当前会话">
              <LogOut size={14} />
            </button>
          </div>
        </div>
      </aside>
      <div className="app-main">{children}</div>
    </div>
  );
}
