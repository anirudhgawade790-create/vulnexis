import { ArrowDown, ArrowUp, Minus } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

interface StatCardProps {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: React.ReactNode;
  delta?: number;
  hint?: string;
  iconClassName?: string;
}

export function StatCard({ icon: Icon, label, value, delta, hint, iconClassName }: StatCardProps) {
  const trendUp = delta !== undefined && delta > 0;
  const trendDown = delta !== undefined && delta < 0;
  const TrendIcon = trendUp ? ArrowUp : trendDown ? ArrowDown : Minus;

  return (
    <Card className="group transition-colors duration-150 hover:border-primary/25">
      <CardContent className="flex min-h-[132px] items-start justify-between gap-2 p-4 sm:p-5">
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">{label}</p>
          <p className="pt-1 text-[26px] font-semibold leading-none tracking-tight tabular-nums">{value}</p>
          {hint && <p className="pt-1 text-[11px] leading-4 text-muted-foreground">{hint}</p>}
          {delta !== undefined && (
            <p
              className={cn(
                "flex items-center gap-1 text-[11px] font-medium",
                trendUp && "text-rose-400",
                trendDown && "text-emerald-400",
                !trendUp && !trendDown && "text-muted-foreground"
              )}
            >
              <TrendIcon className="h-3 w-3" />
              {Math.abs(delta)}% vs prev
            </p>
          )}
        </div>
        <div className={cn("rounded-lg border border-border/70 bg-muted/70 p-2.5", iconClassName)}>
            <Icon className="h-[18px] w-[18px]" />
        </div>
      </CardContent>
    </Card>
  );
}
