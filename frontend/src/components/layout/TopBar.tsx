import { useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Bell,
  ChevronDown,
  CircleHelp,
  LogOut,
  Menu,
  Search,
  Shield,
  User as UserIcon,
} from "lucide-react";

import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/hooks/useAuth";
import { useDemoStore } from "@/store/demoStore";

interface TopBarProps {
  onMenuClick: () => void;
}

const PAGE_TITLES: Record<string, string> = {
  "/": "Security Overview",
  "/assets": "Asset Inventory",
  "/scans": "Vulnerability Scanner",
  "/scan-history": "Scan History",
  "/network-discovery": "Network Discovery",
  "/findings": "Security Findings",
  "/vulnerabilities": "Vulnerability Intelligence",
  "/remediation": "Remediation Center",
  "/baseline": "Security Baselines",
  "/changes": "Change Detection",
  "/reports": "Reports",
  "/settings": "Settings",
};

export function TopBar({ onMenuClick }: TopBarProps) {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const configuredDemoMode = useDemoStore((state) => state.isDemoMode);
  const isDemoMode = configuredDemoMode || user?.id.startsWith("demo-") === true;
  const [search, setSearch] = useState("");

  const initials = (user?.full_name || user?.username || "U")
    .split(" ")
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
  const pageTitle =
    location.pathname.startsWith("/scans/") ? "Scan Details" :
    location.pathname.startsWith("/assets/") ? "Asset Details" :
    PAGE_TITLES[location.pathname] ?? "VULNEXIS";

  function submitSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const query = search.trim();
    if (query) navigate(`/findings?search=${encodeURIComponent(query)}`);
  }

  return (
    <header className="sticky top-0 z-20 flex h-[68px] shrink-0 items-center justify-between gap-4 border-b border-border bg-background/90 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
      <div className="flex min-w-0 items-center gap-3">
        <Button
          variant="ghost"
          size="icon"
          className="shrink-0 text-muted-foreground"
          onClick={onMenuClick}
          aria-label="Toggle navigation"
          title="Toggle navigation"
        >
          <Menu className="h-5 w-5" />
        </Button>
        <p className="max-w-[40vw] truncate text-sm font-semibold md:hidden">{pageTitle}</p>
        <div className="hidden min-w-0 md:block">
          <p className="truncate text-sm font-semibold tracking-wide text-foreground">{pageTitle}</p>
          <p className="mt-0.5 truncate text-[11px] text-muted-foreground">VULNEXIS / Security Intelligence</p>
        </div>
        <form onSubmit={submitSearch} className="relative hidden w-[min(34vw,360px)] sm:block">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search findings…"
            aria-label="Search findings"
            className="h-9 border-border/80 bg-card/70 pl-9 pr-14 text-xs placeholder:text-muted-foreground/70"
          />
          <kbd className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground">
            Enter
          </kbd>
        </form>
      </div>

      <div className="flex shrink-0 items-center gap-1.5 sm:gap-3">
        <Button
          variant="ghost"
          size="icon"
          className="text-muted-foreground sm:hidden"
          aria-label="Search findings"
          onClick={() => navigate("/findings")}
        >
          <Search className="h-[18px] w-[18px]" />
        </Button>
        <span
          className="hidden items-center gap-1.5 rounded-full border border-border bg-card/70 px-2.5 py-1.5 text-[10px] font-medium text-muted-foreground sm:inline-flex"
          title={isDemoMode ? "Using the configured demo environment" : "Connected to the live application environment"}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${isDemoMode ? "bg-amber-400" : "bg-emerald-400"}`} />
          {isDemoMode ? "DEMO ENVIRONMENT" : "LIVE ENVIRONMENT"}
        </span>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" aria-label="Notifications" className="text-muted-foreground">
              <Bell className="h-[18px] w-[18px]" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-72">
            <DropdownMenuLabel>Security alert center</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <p className="px-2 py-2 text-xs leading-5 text-muted-foreground">
              Alerts are represented by open findings in the security queue.
            </p>
            <DropdownMenuItem onClick={() => navigate("/findings")}>
              <Shield className="mr-2 h-4 w-4 text-primary" />
              Review findings
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="h-9 gap-2 rounded-full px-1.5 sm:px-2">
              <Avatar className="h-7 w-7 border border-border">
                <AvatarFallback className="bg-primary/10 text-[10px] font-semibold text-primary">{initials}</AvatarFallback>
              </Avatar>
              <span className="hidden max-w-28 truncate text-xs font-medium sm:block">
                {user?.full_name || user?.username}
              </span>
              <ChevronDown className="hidden h-3.5 w-3.5 text-muted-foreground sm:block" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel className="font-normal">
              <p className="text-sm font-medium">{user?.full_name || user?.username}</p>
              <p className="mt-1 truncate text-xs text-muted-foreground">{user?.email}</p>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => navigate("/settings")}>
              <UserIcon className="mr-2 h-4 w-4" /> Account settings
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => navigate("/findings")}>
              <CircleHelp className="mr-2 h-4 w-4" /> Help & security findings
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={async () => {
                await signOut();
                navigate("/login");
              }}
            >
              <LogOut className="mr-2 h-4 w-4" /> Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
