import { Link } from "react-router-dom";
import { CheckCircle2, Clock, XCircle, ArrowUpRight } from "lucide-react";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { formatRelative } from "@/lib/utils";
import type { ScanJob } from "@/types";

function statusBadge(status: ScanJob["status"]) {
  switch (status) {
    case "completed":
      return (
        <Badge variant="outline" className="border-green-600 text-green-500">
          <CheckCircle2 className="mr-1 h-3 w-3" />
          Completed
        </Badge>
      );
    case "running":
      return (
        <Badge variant="outline" className="border-blue-600 text-blue-500">
          <Clock className="mr-1 h-3 w-3 animate-spin" />
          Running
        </Badge>
      );
    case "failed":
      return (
        <Badge variant="destructive">
          <XCircle className="mr-1 h-3 w-3" />
          Failed
        </Badge>
      );
    default:
      return (
        <Badge variant="secondary">
          <Clock className="mr-1 h-3 w-3" />
          {status}
        </Badge>
      );
  }
}

/**
 * Compact widget listing the latest 5 scans with status, type, and quick link.
 */
interface RecentScansWidgetProps {
  scans: ScanJob[];
  isLoading?: boolean;
  isError?: boolean;
  onRetry?: () => void;
}

export function RecentScansWidget({
  scans,
  isLoading = false,
  isError = false,
  onRetry,
}: RecentScansWidgetProps) {
  const recent = [...scans]
    .sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""))
    .slice(0, 5);

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>
            <span className="eyebrow block">Assessment activity</span>
            <span className="mt-1 block">Recent scans</span>
          </span>
          <Link
            to="/scans"
            className="text-xs font-normal text-muted-foreground hover:text-foreground"
          >
            View all
          </Link>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="py-8 text-center text-sm text-muted-foreground">Loading recent assessments…</div>
        ) : isError ? (
          <div className="py-6 text-center text-sm text-destructive">
            <p>Scan activity could not be loaded.</p>
            {onRetry && <button type="button" onClick={onRetry} className="mt-2 text-xs text-foreground underline-offset-4 hover:underline">Try again</button>}
          </div>
        ) : recent.length === 0 ? (
          <div className="py-8 text-center text-sm text-muted-foreground">
            No scans performed yet.
          </div>
        ) : (
          <div className="divide-y divide-border/70">
            {recent.map((scan) => (
              <div
                key={scan.id}
                className="flex flex-wrap items-center justify-between gap-2 py-3 first:pt-0 last:pb-0"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-medium uppercase">
                      {scan.scan_type}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {formatRelative(scan.created_at)}
                    </span>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Target: {scan.target_id.slice(0, 8)}…
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {statusBadge(scan.status)}
                  <Link
                    to={`/scans/${scan.id}`}
                    className="text-muted-foreground hover:text-foreground"
                    aria-label={`View scan ${scan.id}`}
                  >
                    <ArrowUpRight className="h-4 w-4" />
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}