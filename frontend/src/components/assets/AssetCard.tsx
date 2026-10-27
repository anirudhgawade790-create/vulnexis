import { Monitor, Server, Router, HelpCircle, Globe } from "lucide-react";
import { Link } from "react-router-dom";
import { Card, CardContent } from "@/components/ui/card";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { cn } from "@/lib/utils";
import type { Asset, AssetType, Severity } from "@/types";

const ASSET_ICONS: Record<AssetType, React.ComponentType<{ className?: string }>> = {
  server: Server,
  workstation: Monitor,
  network_device: Router,
  unknown: HelpCircle,
};

function riskToSeverity(score: number | null): Severity {
  if (!score) return "info";
  if (score >= 8) return "critical";
  if (score >= 6) return "high";
  if (score >= 4) return "medium";
  if (score >= 2) return "low";
  return "info";
}

interface AssetCardProps {
  asset: Asset;
}

export function AssetCard({ asset }: AssetCardProps) {
  const Icon = ASSET_ICONS[asset.asset_type] ?? HelpCircle;
  const portCount = asset.open_ports?.length ?? 0;

  return (
    <Link to={`/assets/${asset.id}`} className="block">
      <Card className="transition-colors hover:border-primary/50">
        <CardContent className="p-4 space-y-3">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <div className="rounded bg-muted p-2 shrink-0">
                <Icon className="h-4 w-4 text-muted-foreground" />
              </div>
              <div className="min-w-0">
                <p className="font-mono text-sm font-semibold truncate">{asset.ip_address}</p>
                {asset.hostname && (
                  <p className="text-xs text-muted-foreground truncate">{asset.hostname}</p>
                )}
              </div>
            </div>
            {asset.risk_score !== null && (
              <SeverityBadge severity={riskToSeverity(asset.risk_score)} />
            )}
          </div>

          <div className="space-y-1 text-xs text-muted-foreground">
            {asset.os_name && (
              <p className="truncate">
                <span className="font-medium text-foreground">OS: </span>
                {asset.os_name} {asset.os_version}
              </p>
            )}
            <div className="flex items-center justify-between">
              <span>
                <Globe className="inline h-3 w-3 mr-1" />
                {portCount} open port{portCount !== 1 ? "s" : ""}
              </span>
              {asset.risk_score !== null && (
                <span className={cn("font-semibold", asset.risk_score >= 7 ? "text-red-600" : "text-foreground")}>
                  Risk: {asset.risk_score.toFixed(1)}
                </span>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
