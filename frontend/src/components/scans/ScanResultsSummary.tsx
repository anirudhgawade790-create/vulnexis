import { Monitor, Globe, Bug, Clock } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import type { ScanResultsSummary as ScanResultsSummaryType, Severity } from "@/types";

interface ScanResultsSummaryProps {
  summary: ScanResultsSummaryType;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function ScanResultsSummary({ summary }: ScanResultsSummaryProps) {
  const durationStr = summary.scan_duration_seconds
    ? summary.scan_duration_seconds < 60
      ? `${summary.scan_duration_seconds}s`
      : `${Math.floor(summary.scan_duration_seconds / 60)}m ${summary.scan_duration_seconds % 60}s`
    : "—";

  return (
    <div className="space-y-4">
      {/* Top stats */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Monitor className="h-5 w-5 text-primary shrink-0" />
            <div>
              <p className="text-2xl font-semibold">{summary.assets_found}</p>
              <p className="text-xs text-muted-foreground">Assets found</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Monitor className="h-5 w-5 text-blue-500 shrink-0" />
            <div>
              <p className="text-2xl font-semibold">{summary.windows_assets}</p>
              <p className="text-xs text-muted-foreground">Windows assets</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Globe className="h-5 w-5 text-orange-500 shrink-0" />
            <div>
              <p className="text-2xl font-semibold">{summary.total_open_ports}</p>
              <p className="text-xs text-muted-foreground">Open ports</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <Clock className="h-5 w-5 text-muted-foreground shrink-0" />
            <div>
              <p className="text-2xl font-semibold">{durationStr}</p>
              <p className="text-xs text-muted-foreground">Duration</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Findings by severity */}
      {Object.keys(summary.findings_by_severity).length > 0 && (
        <div className="rounded-md border p-4">
          <p className="text-sm font-medium mb-3 flex items-center gap-2">
            <Bug className="h-4 w-4" /> Findings by Severity
          </p>
          <div className="flex flex-wrap gap-3">
            {SEVERITIES.map((sev) => {
              const count = summary.findings_by_severity[sev] ?? 0;
              if (!count) return null;
              return (
                <div key={sev} className="flex items-center gap-1.5">
                  <SeverityBadge severity={sev} />
                  <span className="text-sm font-semibold">{count}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Errors */}
      {summary.errors.length > 0 && (
        <div className="rounded border border-red-200 bg-red-50 p-3 text-xs text-red-700 space-y-1">
          <p className="font-semibold">Scan errors ({summary.errors.length})</p>
          {summary.errors.map((e, i) => <p key={i}>{e}</p>)}
        </div>
      )}
    </div>
  );
}
