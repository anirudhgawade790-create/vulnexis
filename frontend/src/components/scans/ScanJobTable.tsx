import { Link } from "react-router-dom";
import { XCircle, Eye } from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/common/EmptyState";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { SCAN_STATUS_LABELS } from "@/lib/constants";
import { cn } from "@/lib/utils";
import type { ScanJob, ScanStatus } from "@/types";

const STATUS_STYLES: Record<ScanStatus, string> = {
  queued: "bg-gray-100 text-gray-700 dark:bg-slate-500/10 dark:text-slate-300",
  running: "bg-blue-100 text-blue-700 dark:bg-cyan-500/10 dark:text-cyan-300",
  completed: "bg-green-100 text-green-700 dark:bg-emerald-500/10 dark:text-emerald-300",
  failed: "bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-300",
  cancelled: "bg-gray-100 text-gray-500 dark:bg-slate-500/10 dark:text-slate-400",
};

interface ScanJobTableProps {
  scans: ScanJob[];
  isLoading?: boolean;
  onCancel?: (id: string) => void;
}

function duration(scan: ScanJob): string {
  if (!scan.started_at) return "—";
  const end = scan.completed_at ? new Date(scan.completed_at) : new Date();
  const secs = Math.floor((end.getTime() - new Date(scan.started_at).getTime()) / 1000);
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs / 60)}m ${secs % 60}s`;
}

export function ScanJobTable({ scans, isLoading, onCancel }: ScanJobTableProps) {
  if (isLoading) return <LoadingSpinner label="Loading scans…" />;
  if (!scans.length) return <EmptyState icon={Eye} title="No scans yet" description="Launch a scan to get started." />;

  return (
    <Card id="scan-history" className="scroll-mt-24">
      <CardHeader className="pb-2 text-sm font-medium">Scan Jobs ({scans.length})</CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/40 text-xs text-muted-foreground">
              <tr>
                <th className="px-4 py-3 text-left">ID</th>
                <th className="px-4 py-3 text-left">Type</th>
                <th className="px-4 py-3 text-left">Status</th>
                <th className="px-4 py-3 text-left">Progress</th>
                <th className="px-4 py-3 text-left">Started</th>
                <th className="px-4 py-3 text-left">Duration</th>
                <th className="px-4 py-3 text-left">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {scans.map((s) => (
                <tr key={s.id} className="hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{s.id.slice(0, 8)}…</td>
                  <td className="px-4 py-3 capitalize">{s.scan_type}</td>
                  <td className="px-4 py-3">
                    <span className={cn("text-xs rounded px-1.5 py-0.5 font-medium", STATUS_STYLES[s.status])}>
                      {SCAN_STATUS_LABELS[s.status]}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-20 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full bg-primary transition-all"
                          style={{ width: `${s.progress}%` }}
                        />
                      </div>
                      <span className="text-xs text-muted-foreground">{s.progress}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {s.started_at ? new Date(s.started_at).toLocaleString() : "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{duration(s)}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <Link to={`/scans/${s.id}`}>
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0">
                          <Eye className="h-3.5 w-3.5" />
                        </Button>
                      </Link>
                      {(s.status === "queued" || s.status === "running") && onCancel && (
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 w-7 p-0 text-red-500 hover:text-red-700"
                          onClick={() => onCancel(s.id)}
                        >
                          <XCircle className="h-3.5 w-3.5" />
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
