import { Link } from "react-router-dom";
import { ArrowUpRight, Monitor } from "lucide-react";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import type { Asset } from "@/types";

function riskTone(score: number | null) {
  if (score === null) return "text-muted-foreground";
  if (score >= 9) return "text-red-500";
  if (score >= 7) return "text-orange-500";
  if (score >= 4) return "text-yellow-500";
  return "text-green-500";
}

/**
 * Ranks assets by risk score. Renders a compact, sortable-looking table with
 * a link to each asset's detail page. Empty state when there are no assets.
 */
interface TopAssetsTableProps {
  assets: Asset[];
  isLoading?: boolean;
  isError?: boolean;
  onRetry?: () => void;
}

export function TopAssetsTable({
  assets,
  isLoading = false,
  isError = false,
  onRetry,
}: TopAssetsTableProps) {
  const ranked = [...assets]
    .sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0))
    .slice(0, 10);

  if (isLoading) {
    return (
      <div className="surface-panel px-6 py-10 text-center text-sm text-muted-foreground">
        Loading asset risk ranking…
      </div>
    );
  }

  if (isError) {
    return (
      <div className="surface-panel px-6 py-8 text-center">
        <p className="text-sm text-destructive">Asset risk ranking could not be loaded.</p>
        {onRetry && (
          <button type="button" onClick={onRetry} className="mt-2 text-xs font-medium text-foreground underline-offset-4 hover:underline">
            Try again
          </button>
        )}
      </div>
    );
  }

  if (ranked.length === 0) {
    return (
      <div className="surface-panel flex flex-col items-center justify-center px-6 py-10 text-center">
        <Monitor className="h-6 w-6 text-muted-foreground" />
        <p className="mt-3 text-sm font-medium text-foreground">No assets discovered yet</p>
        <p className="mt-1 text-xs text-muted-foreground">Add an authorized target and run a scan to populate inventory.</p>
      </div>
    );
  }

  return (
    <div className="surface-panel overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Host</TableHead>
            <TableHead>IP</TableHead>
            <TableHead>OS</TableHead>
            <TableHead className="text-right">Risk</TableHead>
            <TableHead className="w-12" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {ranked.map((asset) => (
            <TableRow key={asset.id} className="transition-colors hover:bg-accent/40">
              <TableCell className="font-medium">
                {asset.hostname || "—"}
              </TableCell>
              <TableCell className="font-mono text-xs">
                {asset.ip_address}
              </TableCell>
              <TableCell className="text-muted-foreground">
                {asset.os_name || "Unknown"}
              </TableCell>
              <TableCell className={cn("text-right font-mono", riskTone(asset.risk_score))}>
                {asset.risk_score?.toFixed(1) ?? "—"}
              </TableCell>
              <TableCell>
                <Link
                  to={`/assets/${asset.id}`}
                  className="text-muted-foreground hover:text-foreground"
                  aria-label={`View ${asset.ip_address}`}
                >
                  <ArrowUpRight className="h-4 w-4" />
                </Link>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}