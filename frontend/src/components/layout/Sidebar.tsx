import { NavLink, useLocation } from "react-router-dom";
import {
  BarChart3,
  Bug,
  FileText,
  History,
  Network,
  ScanLine,
  Settings,
  ShieldCheck,
  Sparkles,
  Wrench,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { ROUTES } from "@/lib/constants";
import { useAuthStore } from "@/store/authStore";

interface SidebarProps {
  collapsed: boolean;
  mobileOpen: boolean;
  onClose: () => void;
}

const NAV_ITEMS = [
  { to: ROUTES.dashboard, label: "Overview", icon: BarChart3, section: "Workspace", roles: ["admin", "analyst", "viewer"] },
  { to: ROUTES.assets, label: "Assets", icon: Network, section: "Workspace", roles: ["admin", "analyst", "viewer"] },
  { to: ROUTES.networkDiscovery, label: "Network Discovery", icon: Network, section: "Workspace", roles: ["admin", "analyst"] },
  { to: ROUTES.scans, label: "Vulnerability Scanner", icon: ScanLine, section: "Workspace", roles: ["admin", "analyst"] },
  { to: ROUTES.findings, label: "Security Findings", icon: Bug, section: "Workspace", roles: ["admin", "analyst", "viewer"] },
  { to: "/#security-intelligence", label: "AI Security Insights", icon: Sparkles, section: "Manage", hash: "#security-intelligence", roles: ["admin", "analyst"] },
  { to: ROUTES.remediation, label: "Remediation Center", icon: Wrench, section: "Manage", roles: ["admin", "analyst"] },
  { to: ROUTES.baseline, label: "Security Baselines", icon: ShieldCheck, section: "Manage", roles: ["admin", "analyst"] },
  { to: ROUTES.scanHistory, label: "Scan History", icon: History, section: "Manage", roles: ["admin", "analyst", "viewer"] },
  { to: ROUTES.reports, label: "Reports", icon: FileText, section: "Manage", roles: ["admin", "analyst", "viewer"] },
  { to: ROUTES.settings, label: "Admin Control Center", icon: Settings, section: "System", roles: ["admin"] },
];

export function Sidebar({ collapsed, mobileOpen, onClose }: SidebarProps) {
  const location = useLocation();
  const user = useAuthStore((s) => s.user);
  const isLegacyNetworkView =
    location.pathname === ROUTES.assets &&
    new URLSearchParams(location.search).get("view") === "network";
  const initials = (user?.full_name || user?.username || "U")
    .split(" ")
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  let lastSection = "";

  return (
    <>
      {mobileOpen && (
        <button
          type="button"
          aria-label="Close navigation"
          className="fixed inset-0 z-30 bg-black/60 md:hidden"
          onClick={onClose}
        />
      )}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex h-full flex-col border-r border-border bg-[hsl(var(--sidebar))] transition-[width,transform] duration-200 md:relative md:z-auto md:translate-x-0",
          collapsed ? "w-[76px]" : "w-[258px]",
          mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        )}
      >
        <div className={cn("flex h-[72px] shrink-0 items-center border-b border-border", collapsed ? "justify-center px-2" : "gap-3 px-5")}>
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-primary/25 bg-primary/10 text-primary">
            <ShieldCheck className="h-5 w-5" />
          </div>
          {!collapsed && (
            <div className="min-w-0">
              <p className="truncate text-[15px] font-bold tracking-[0.12em] text-foreground">VULNEXIS</p>
              <p className="mt-0.5 truncate text-[10px] tracking-wide text-muted-foreground">Discover. Analyze. Defend.</p>
            </div>
          )}
        </div>

        <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-5">
          {NAV_ITEMS.filter((item) => !!user && item.roles.includes(user.role)).map((item) => {
            const Icon = item.icon;
            const showSection = !collapsed && lastSection !== item.section;
            lastSection = item.section;
            return (
              <div key={`${item.label}-${item.to}`}>
                {showSection && (
                  <p className={cn("eyebrow px-3 pb-2 pt-4 first:pt-0")}>{item.section}</p>
                )}
                <NavLink
                  to={item.to}
                  end={item.hash !== undefined || item.to === ROUTES.dashboard ||
                    item.to === ROUTES.networkDiscovery ||
                    item.to === ROUTES.scanHistory}
                  title={collapsed ? item.label : undefined}
                  onClick={onClose}
                  className={({ isActive }) => {
                    const active = item.hash
                      ? location.pathname === item.to.split("#")[0] && location.hash === item.hash
                      : item.to === ROUTES.dashboard
                        ? location.pathname === ROUTES.dashboard && !location.hash
                        : item.to === ROUTES.networkDiscovery
                          ? isActive || isLegacyNetworkView
                          : item.to === ROUTES.assets
                            ? isActive && !isLegacyNetworkView
                            : isActive;
                    return cn(
                    "group relative flex min-h-10 items-center rounded-lg text-[13px] font-medium transition-colors duration-150",
                    collapsed ? "justify-center px-2" : "gap-3 px-3",
                    active
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-accent/70 hover:text-foreground"
                    );
                  }}
                >
                  {({ isActive }) => {
                    const active = item.hash
                      ? location.pathname === item.to.split("#")[0] && location.hash === item.hash
                      : item.to === ROUTES.dashboard
                        ? location.pathname === ROUTES.dashboard && !location.hash
                        : item.to === ROUTES.networkDiscovery
                          ? isActive || isLegacyNetworkView
                          : item.to === ROUTES.assets
                            ? isActive && !isLegacyNetworkView
                            : isActive;
                    return (
                      <>
                        {active && <span className="absolute bottom-2 left-0 top-2 w-0.5 rounded-r bg-primary" />}
                        <Icon className={cn("h-[17px] w-[17px] shrink-0", active && "text-primary")} />
                        {!collapsed && <span className="truncate">{item.label}</span>}
                      </>
                    );
                  }}
                </NavLink>
              </div>
            );
          })}
        </nav>

        <div className={cn("border-t border-border p-3", collapsed && "px-2")}>
          <div className={cn("flex items-center rounded-lg bg-card/70 p-2", collapsed ? "justify-center" : "gap-3")}>
            <div
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border border-primary/20 bg-primary/10 text-xs font-semibold text-primary"
              title={collapsed ? user?.full_name || user?.username || "Account" : undefined}
            >
              {initials}
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <p className="truncate text-xs font-medium text-foreground">{user?.full_name || user?.username}</p>
                <p className="mt-0.5 truncate text-[11px] capitalize text-muted-foreground">{user?.role}</p>
              </div>
            )}
          </div>
          {!collapsed && (
            <p className="px-2 pt-3 text-[10px] text-muted-foreground">
              Agent-less Security Intelligence
            </p>
          )}
        </div>
      </aside>
    </>
  );
}
