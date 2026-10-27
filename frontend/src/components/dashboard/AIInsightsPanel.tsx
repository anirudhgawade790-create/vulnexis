import { Sparkles } from "lucide-react";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import type { InsightItem } from "@/types";

interface AIInsightsPanelProps {
  insights: InsightItem[];
  isError?: boolean;
  onRetry?: () => void;
}

export function AIInsightsPanel({ insights, isError = false, onRetry }: AIInsightsPanelProps) {
  return (
    <Card className="h-full">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-2 text-base">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-primary/20 bg-primary/10">
            <Sparkles className="h-4 w-4 text-primary" />
          </span>
          <span>
            <span className="eyebrow block">Evidence-based recommendations</span>
            <span className="mt-1 block">Security Intelligence</span>
          </span>
          <Badge variant="outline" className="ml-auto border-primary/20 text-[10px] text-primary">
            {isError ? "Unavailable" : `${insights.length} insights`}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isError ? (
          <div className="rounded-lg border border-destructive/25 bg-destructive/5 px-4 py-6 text-center">
            <p className="text-sm font-medium text-destructive">Security intelligence could not be loaded.</p>
            {onRetry && (
              <button type="button" onClick={onRetry} className="mt-2 text-xs font-medium text-foreground underline-offset-4 hover:underline">
                Try again
              </button>
            )}
          </div>
        ) : insights.length === 0 ? (
          <div className="rounded-lg border border-dashed border-border px-4 py-8 text-center">
            <p className="text-sm font-medium">No security insights available</p>
            <p className="mt-1 text-xs text-muted-foreground">Run an assessment to generate evidence-based recommendations.</p>
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {insights.map((item) => (
              <div
                key={item.id}
                className="rounded-lg border border-border/80 bg-background/50 p-3.5 transition-colors hover:border-primary/30"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={item.severity} />
                      <span className="text-xs uppercase tracking-wider text-muted-foreground">
                        {item.category}
                      </span>
                    </div>
                    <p className="text-sm font-semibold leading-5 text-foreground">
                      {item.title}
                    </p>
                    <p className="text-xs leading-5 text-muted-foreground">
                      {item.detail}
                    </p>
                  </div>
                </div>
                {item.evidence_tags.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {item.evidence_tags.map((tag) => (
                      <span
                        key={tag}
                        className="rounded-md border border-border bg-muted/60 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}