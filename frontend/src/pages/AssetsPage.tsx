import { useState } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { ArrowLeft, ArrowRight, ArrowUpRight, Monitor, Network, Plus, Search } from "lucide-react";
import { Link } from "react-router-dom";
import { NetworkMapView } from "@/components/assets/NetworkMapView";
import { PageHeader } from "@/components/layout/PageHeader";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { TargetCreateDialog } from "@/components/targets/TargetCreateDialog";
import { EmptyState } from "@/components/common/EmptyState";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useListAssets } from "@/hooks/useAssets";
import { useDebounce } from "@/hooks/useDebounce";
import type { BusinessCriticality } from "@/types";
import { useAuthStore } from "@/store/authStore";

const PAGE_SIZE = 10;

export function AssetsPage() {
  const role = useAuthStore((state) => state.user?.role);
  const [searchParams] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();
  const scanJobId = searchParams.get("scan_job_id") ?? undefined;
  const view =
    location.pathname === "/network-discovery"
    || searchParams.get("view") === "network"
      ? "network"
      : "inventory";

  const [search, setSearch] = useState("");
  const [criticality, setCriticality] = useState<string>("all");
  const [windowsOnly, setWindowsOnly] = useState(false);
  const [showTargetForm, setShowTargetForm] = useState(false);
  const [sortBy, setSortBy] = useState<"risk" | "hostname" | "ip">("risk");
  const [page, setPage] = useState(1);

  const debouncedSearch = useDebounce(search, 300);

  const params: Record<string, unknown> = {};
  if (scanJobId) params.scan_job_id = scanJobId;
  if (windowsOnly) params.is_windows = true;
  if (criticality !== "all") params.business_criticality = criticality;

  const assetsQuery = useListAssets(params);
  const { data: assets = [], isLoading } = assetsQuery;

  const filtered = debouncedSearch
    ? assets.filter((a) =>
        `${a.ip_address} ${a.hostname ?? ""} ${a.os_name ?? ""}`
          .toLowerCase()
          .includes(debouncedSearch.toLowerCase())
      )
    : assets;
  const sorted = [...filtered].sort((a, b) => {
    if (sortBy === "hostname") {
      return (a.hostname ?? a.ip_address).localeCompare(b.hostname ?? b.ip_address);
    }
    if (sortBy === "ip") return a.ip_address.localeCompare(b.ip_address);
    return (b.risk_score ?? -1) - (a.risk_score ?? -1);
  });
  const pageCount = Math.max(1, Math.ceil(sorted.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount);
  const pagedAssets = sorted.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  function changeView(nextView: string) {
    if (nextView === "network") {
      navigate({
        pathname: "/network-discovery",
        search: searchParams.toString(),
      });
      return;
    }

    const nextParams = new URLSearchParams(searchParams);
    nextParams.delete("view");
    navigate({
      pathname: "/assets",
      search: nextParams.toString(),
    });
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={view === "network" ? "Network Discovery" : "Asset Inventory"}
        subtitle={
          scanJobId
            ? `Assets from scan ${scanJobId.slice(0, 8)}…`
            : view === "network"
              ? "Explore discovered hosts by observed risk and open ports. Connections between hosts are not inferred."
              : "Discovered hosts, operating systems, and exposed services."
        }
        action={
          view === "inventory" && role === "admin" ? (
            <Button className="gap-2" onClick={() => setShowTargetForm(true)}>
              <Plus className="h-4 w-4" /> Add Asset
            </Button>
          ) : undefined
        }
      />

      <Tabs value={view} onValueChange={changeView}>
        <TabsList className="h-10 border border-border bg-card/60">
          <TabsTrigger value="inventory" className="gap-2 px-4">
            <Monitor className="h-4 w-4" /> Inventory
          </TabsTrigger>
          <TabsTrigger value="network" className="gap-2 px-4">
            <Network className="h-4 w-4" /> Network Discovery
          </TabsTrigger>
        </TabsList>
      </Tabs>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-border bg-card/60 p-3">
        <div className="relative min-w-[220px] flex-1 sm:max-w-sm">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search IP, host, or operating system"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="pl-9"
          />
        </div>
        <Select value={criticality} onValueChange={(value) => { setCriticality(value); setPage(1); }}>
          <SelectTrigger className="w-full sm:w-44">
            <SelectValue placeholder="Criticality" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All criticalities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <label className="flex min-h-9 items-center gap-2 rounded-md border border-border px-3 text-sm text-muted-foreground cursor-pointer select-none">
          <input
            type="checkbox"
            checked={windowsOnly}
            onChange={(e) => {
              setWindowsOnly(e.target.checked);
              setPage(1);
            }}
            className="rounded border-border accent-cyan-400"
          />
          Windows only
        </label>
      </div>

      {isLoading && (
        <div className="rounded-xl border border-border bg-card/50 px-5 py-10 text-center text-sm text-muted-foreground">
          Loading asset inventory…
        </div>
      )}

      {assetsQuery.isError && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm">
          <span className="text-destructive">Asset inventory could not be loaded.</span>
          <button className="font-medium text-foreground underline-offset-4 hover:underline" onClick={() => void assetsQuery.refetch()}>
            Try again
          </button>
        </div>
      )}

      {!isLoading && !assetsQuery.isError && !filtered.length && (
        <EmptyState icon={Monitor} title="No assets found" description="Run a scan to discover assets." />
      )}

      {!isLoading && filtered.length > 0 && view === "network" && (
        <NetworkMapView assets={filtered} />
      )}

      {!isLoading && filtered.length > 0 && view === "inventory" && (
        <>
          <section className="surface-panel overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3.5 sm:px-5">
              <div>
                <h2 className="text-sm font-semibold">Discovered assets</h2>
                <p className="mt-1 text-xs text-muted-foreground">{filtered.length} hosts in current view</p>
              </div>
              <Select value={sortBy} onValueChange={(value) => setSortBy(value as typeof sortBy)}>
                <SelectTrigger className="w-full sm:w-44" aria-label="Sort assets">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="risk">Sort by risk</SelectItem>
                  <SelectItem value="hostname">Sort by hostname</SelectItem>
                  <SelectItem value="ip">Sort by IP address</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] text-left text-sm">
                <thead className="border-b border-border bg-muted/40 text-[11px] uppercase tracking-wide text-muted-foreground">
                  <tr>
                    <th className="px-5 py-3 font-medium">Asset</th>
                    <th className="px-4 py-3 font-medium">IP address</th>
                    <th className="px-4 py-3 font-medium">Operating system</th>
                    <th className="px-4 py-3 font-medium">Type</th>
                    <th className="px-4 py-3 text-right font-medium">Risk / 10</th>
                    <th className="px-4 py-3 text-right font-medium">Open ports</th>
                    <th className="px-5 py-3 text-right font-medium">Last observed</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/70">
                  {pagedAssets.map((asset) => (
                    <tr key={asset.id} className="transition-colors hover:bg-accent/30">
                      <td className="px-5 py-3.5">
                        <Link to={`/assets/${asset.id}`} className="font-medium text-foreground hover:text-primary">
                          {asset.hostname || asset.ip_address}
                        </Link>
                      </td>
                      <td className="px-4 py-3.5 font-mono text-xs text-muted-foreground">{asset.ip_address}</td>
                      <td className="px-4 py-3.5 text-xs text-muted-foreground">
                        {asset.os_name ? `${asset.os_name}${asset.os_version ? ` ${asset.os_version}` : ""}` : "Unknown"}
                      </td>
                      <td className="px-4 py-3.5">
                        <span className="rounded-full border border-border bg-muted/70 px-2 py-1 text-[10px] capitalize text-muted-foreground">
                          {asset.is_windows ? "Windows" : asset.asset_type.replace("_", " ")}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 text-right font-mono text-xs font-medium">
                        {asset.risk_score === null ? <span className="text-muted-foreground">—</span> : (
                          <span className={asset.risk_score >= 7 ? "text-rose-400" : asset.risk_score >= 4 ? "text-amber-300" : "text-emerald-400"}>
                            {asset.risk_score.toFixed(1)}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3.5 text-right text-xs text-muted-foreground">{asset.open_ports?.length ?? "—"}</td>
                      <td className="px-5 py-3.5 text-right">
                        <span className="mr-3 text-xs text-muted-foreground">{new Date(asset.last_seen_at).toLocaleDateString()}</span>
                        <Link to={`/assets/${asset.id}`} aria-label={`View ${asset.hostname || asset.ip_address}`} className="inline-flex text-muted-foreground hover:text-primary">
                          <ArrowUpRight className="h-4 w-4" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t border-border px-4 py-3 sm:px-5">
              <p className="text-xs text-muted-foreground">
                Page {currentPage} of {pageCount}
              </p>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={currentPage <= 1}
                  onClick={() => setPage(currentPage - 1)}
                  aria-label="Previous page"
                >
                  <ArrowLeft className="h-3.5 w-3.5" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={currentPage >= pageCount}
                  onClick={() => setPage(currentPage + 1)}
                  aria-label="Next page"
                >
                  <ArrowRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          </section>
        </>
      )}
      <TargetCreateDialog open={showTargetForm} onOpenChange={setShowTargetForm} />
    </div>
  );
}
