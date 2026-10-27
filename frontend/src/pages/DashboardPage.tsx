import { useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowUpRight,
  Bug,
  CircleAlert,
  FileText,
  Network,
  Plus,
  ScanLine,
  ShieldCheck,
  Workflow,
} from "lucide-react";

import { PageHeader } from "@/components/layout/PageHeader";
import { StatCard } from "@/components/dashboard/StatCard";
import { RiskGauge } from "@/components/dashboard/RiskGauge";
import { SeverityDonut } from "@/components/dashboard/SeverityDonut";
import { TrendChart } from "@/components/dashboard/TrendChart";
import { TopAssetsTable } from "@/components/dashboard/TopAssetsTable";
import { RecentScansWidget } from "@/components/dashboard/RecentScansWidget";
import { AIInsightsPanel } from "@/components/dashboard/AIInsightsPanel";
import { ScanForm } from "@/components/scans/ScanForm";
import { ScanProgressDrawer } from "@/components/scans/ScanProgressDrawer";
import { TargetCreateDialog } from "@/components/targets/TargetCreateDialog";
import { Button } from "@/components/ui/button";
import { useCreateScan, useListScans } from "@/hooks/useScans";
import { useDashboardSummary, useTrends, useInsights } from "@/hooks/useDashboard";
import { useListAssets } from "@/hooks/useAssets";
import { useListTargets } from "@/hooks/useTargets";
import { toast } from "@/components/ui/use-toast";
import type { ScanJobCreate } from "@/types";
import { useAuthStore } from "@/store/authStore";

export function DashboardPage() {
  const role = useAuthStore((state) => state.user?.role);
  const canStartScans = role === "admin" || role === "analyst";
  const canManageAssets = role === "admin";
  const [showScanForm, setShowScanForm] = useState(false);
  const [showTargetForm, setShowTargetForm] = useState(false);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const summary = useDashboardSummary();
  const trends = useTrends();
  const insights = useInsights();
  const scans = useListScans();
  const assets = useListAssets();
  const targets = useListTargets();
  const createScan = useCreateScan();

  const summaryData = summary.data;
  const assetData = assets.data ?? [];
  const scanData = scans.data ?? [];
  const totalServices = assets.data
    ? new Set(
        assetData.flatMap((asset) =>
          (asset.open_ports ?? []).map(
            (port) => `${asset.ip_address}:${port.protocol}:${port.port}`
          )
        )
      ).size
    : null;
  const remediationPercent =
    summaryData && summaryData.open_findings + summaryData.remediated_findings > 0
      ? Math.round(
          (summaryData.remediated_findings /
            (summaryData.open_findings + summaryData.remediated_findings)) *
            100
        )
      : summaryData
        ? 0
        : null;

  async function launchScan(data: ScanJobCreate) {
    try {
      const scan = await createScan.mutateAsync(data);
      setActiveScanId(scan.id);
      toast({
        title: "Scan queued",
        description: "You can follow live progress from the Vulnerability Scanner.",
      });
    } catch (error) {
      toast({
        title: "Unable to start scan",
        description: error instanceof Error ? error.message : "Please try again.",
        variant: "destructive",
      });
      throw error;
    }
  }

  return (
    <div className="space-y-7">
      <PageHeader
        title="Security Overview"
        subtitle="Monitor your infrastructure, identify vulnerabilities, and improve your security posture."
        action={
          <div className="flex flex-wrap items-center gap-2">
            {canManageAssets && <Button variant="outline" className="h-9 gap-2" onClick={() => setShowTargetForm(true)}>
              <Plus className="h-4 w-4" />
              <span className="hidden sm:inline">Add Asset</span>
              <span className="sm:hidden">Add</span>
            </Button>}
            {canStartScans && <Button onClick={() => setShowScanForm(true)} className="h-9 gap-2 shadow-sm shadow-primary/10">
              <ScanLine className="h-4 w-4" />
              Start Scan
            </Button>}
            <Button asChild variant="ghost" className="h-9 gap-2">
              <Link to="/reports">
                <FileText className="h-4 w-4" />
                <span className="hidden lg:inline">Generate Report</span>
                <span className="lg:hidden">Report</span>
              </Link>
            </Button>
          </div>
        }
      />

      {summary.isError && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm">
          <div className="flex items-center gap-2 text-destructive">
            <CircleAlert className="h-4 w-4 shrink-0" />
            <span>Security summary could not be loaded. Metrics are shown as unavailable.</span>
          </div>
          <Button size="sm" variant="outline" onClick={() => void summary.refetch()}>Retry</Button>
        </div>
      )}

      <section aria-label="Security metrics" className="grid grid-cols-2 gap-3 lg:grid-cols-3 2xl:grid-cols-6">
        <StatCard
          icon={Network}
          label="Total Assets"
          value={summaryData?.total_assets ?? "—"}
          hint="Discovered hosts"
          iconClassName="text-primary"
        />
        <StatCard
          icon={ShieldCheck}
          label="Windows Systems"
          value={summaryData?.windows_assets ?? "—"}
          hint="Windows endpoints"
          iconClassName="text-sky-400"
        />
        <StatCard
          icon={Bug}
          label="Confirmed Findings"
          value={summaryData?.total_vulnerabilities ?? "—"}
          hint="Confirmed vulnerabilities"
          iconClassName="text-rose-400"
        />
        <StatCard
          icon={CircleAlert}
          label="Critical Findings"
          value={summaryData?.findings_by_severity.critical ?? "—"}
          hint="Open · requires attention"
          iconClassName="text-red-400"
        />
        <StatCard
          icon={Workflow}
          label="Exposed Services"
          value={totalServices ?? "—"}
          hint={assets.isError ? "Inventory unavailable" : "Open ports in inventory"}
          iconClassName="text-amber-400"
        />
        <StatCard
          icon={ShieldCheck}
          label="Remediation Progress"
          value={remediationPercent === null ? "—" : `${remediationPercent}%`}
          hint={
            summaryData
              ? `${summaryData.remediated_findings} remediated findings`
              : "Unavailable"
          }
          iconClassName="text-emerald-400"
        />
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.65fr)_minmax(320px,0.9fr)]">
        <TrendChart
          data={trends.data?.data_points ?? []}
          periodDays={trends.data?.period_days}
          isError={trends.isError}
        />
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-1">
          <RiskGauge score={summaryData?.overall_posture_score ?? 0} unavailable={!summaryData} />
          <SeverityDonut counts={summaryData?.findings_by_severity ?? {}} />
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(360px,1fr)]">
        {role !== "viewer" && <div id="security-intelligence">
          <AIInsightsPanel
            insights={insights.data ?? []}
            isError={insights.isError}
            onRetry={() => void insights.refetch()}
          />
        </div>}
        <RecentScansWidget
          scans={scanData}
          isLoading={scans.isLoading}
          isError={scans.isError}
          onRetry={() => void scans.refetch()}
        />
      </section>

      <section className="space-y-3">
        <div className="flex items-end justify-between gap-3">
          <div>
            <p className="eyebrow">Risk prioritization</p>
            <h2 className="mt-1 text-lg font-semibold">Highest-risk assets</h2>
          </div>
          <Button asChild variant="ghost" size="sm" className="gap-1.5 text-muted-foreground">
            <Link to="/assets">View inventory <ArrowUpRight className="h-3.5 w-3.5" /></Link>
          </Button>
        </div>
        <TopAssetsTable
          assets={assetData}
          isLoading={assets.isLoading}
          isError={assets.isError}
          onRetry={() => void assets.refetch()}
        />
      </section>

      {canStartScans && <ScanForm
        open={showScanForm}
        onOpenChange={setShowScanForm}
        targets={targets.data ?? []}
        onSubmit={launchScan}
        isPending={createScan.isPending}
      />}
      {canManageAssets && (
        <TargetCreateDialog
          open={showTargetForm}
          onOpenChange={setShowTargetForm}
        />
      )}
      {canStartScans && (
        <ScanProgressDrawer
          scanJobId={activeScanId}
          onClose={() => setActiveScanId(null)}
        />
      )}
    </div>
  );
}
