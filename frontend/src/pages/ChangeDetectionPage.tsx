import { useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { EmptyState } from "@/components/common/EmptyState";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { ArrowRight, GitCompare } from "lucide-react";
import { useListScans } from "@/hooks/useScans";
import { useQuery } from "@tanstack/react-query";
import { compareScans } from "@/api/scans";
import type { ChangeDetectionReport } from "@/types";

export function ChangeDetectionPage() {
  const { data: scans = [] } = useListScans();
  const [newId, setNewId] = useState("");
  const [prevId, setPrevId] = useState("");

  const completedScans = scans.filter((s) => s.status === "completed");

  const {
    data: report,
    isLoading,
    refetch,
    isFetching,
  } = useQuery<ChangeDetectionReport>({
    queryKey: ["change-detection", newId, prevId],
    queryFn: () => compareScans(newId, prevId),
    enabled: false,
  });

  const canCompare = !!newId && !!prevId && newId !== prevId;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Change Detection"
        subtitle="Compare two scans to see what changed."
      />

      {/* Scan selector */}
      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">Previous scan</p>
          <Select value={prevId} onValueChange={setPrevId}>
            <SelectTrigger className="w-56">
              <SelectValue placeholder="Select scan…" />
            </SelectTrigger>
            <SelectContent>
              {completedScans.map((s) => (
                <SelectItem key={s.id} value={s.id}>
                  {s.id.slice(0, 8)}… · {s.scan_type} · {s.completed_at ? new Date(s.completed_at).toLocaleDateString() : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <ArrowRight className="h-5 w-5 text-muted-foreground mb-2" />

        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">Newer scan</p>
          <Select value={newId} onValueChange={setNewId}>
            <SelectTrigger className="w-56">
              <SelectValue placeholder="Select scan…" />
            </SelectTrigger>
            <SelectContent>
              {completedScans.map((s) => (
                <SelectItem key={s.id} value={s.id}>
                  {s.id.slice(0, 8)}… · {s.scan_type} · {s.completed_at ? new Date(s.completed_at).toLocaleDateString() : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <Button onClick={() => refetch()} disabled={!canCompare || isFetching} className="gap-2">
          <GitCompare className="h-4 w-4" />
          {isFetching ? "Comparing…" : "Compare"}
        </Button>
      </div>

      {isLoading && <LoadingSpinner label="Comparing scans…" />}

      {!report && !isLoading && canCompare && (
        <EmptyState icon={GitCompare} title="Click Compare" description="Select two scans and click Compare to see the diff." />
      )}

      {report && (
        <div className="space-y-4">
          {/* Risk delta */}
          <div className="rounded border p-4 text-sm">
            <span className="font-medium">Risk delta: </span>
            <span className={report.risk_delta > 0 ? "text-red-600 font-semibold" : report.risk_delta < 0 ? "text-green-600 font-semibold" : "text-muted-foreground"}>
              {report.risk_delta > 0 ? "+" : ""}{report.risk_delta.toFixed(1)}
            </span>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <DiffSection
              title={`New Findings (${report.new_findings.length})`}
              items={report.new_findings.map((f) => ({ id: f.id, label: f.title, severity: f.severity }))}
              emptyMsg="No new findings"
              accent="red"
            />
            <DiffSection
              title={`Resolved Findings (${report.resolved_findings.length})`}
              items={report.resolved_findings.map((f) => ({ id: f.id, label: f.title, severity: f.severity }))}
              emptyMsg="No resolved findings"
              accent="green"
            />
            <DiffSection
              title={`New Assets (${report.new_assets.length})`}
              items={report.new_assets.map((a) => ({ id: a.id, label: a.hostname ?? a.ip_address }))}
              emptyMsg="No new assets"
              accent="blue"
            />
            <DiffSection
              title={`Removed Assets (${report.removed_assets.length})`}
              items={report.removed_assets.map((a) => ({ id: a.id, label: a.hostname ?? a.ip_address }))}
              emptyMsg="No removed assets"
              accent="gray"
            />
          </div>
        </div>
      )}
    </div>
  );
}

function DiffSection({
  title,
  items,
  emptyMsg,
  accent,
}: {
  title: string;
  items: { id: string; label: string; severity?: string }[];
  emptyMsg: string;
  accent: "red" | "green" | "blue" | "gray";
}) {
  const border = {
    red: "border-red-200",
    green: "border-green-200",
    blue: "border-blue-200",
    gray: "border-gray-200",
  }[accent];

  return (
    <Card className={`border ${border}`}>
      <CardHeader className="pb-2 text-sm font-medium">{title}</CardHeader>
      <CardContent>
        {!items.length ? (
          <p className="text-xs text-muted-foreground">{emptyMsg}</p>
        ) : (
          <ul className="space-y-1">
            {items.map((item) => (
              <li key={item.id} className="flex items-center gap-2 text-sm">
                {item.severity && <SeverityBadge severity={item.severity as never} />}
                <span className="truncate">{item.label}</span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
