import { SeverityBadge } from "@/components/common/SeverityBadge";
import { ConfidenceBadge } from "@/components/common/ConfidenceBadge";
import { FindingTypeBadge } from "./FindingTypeBadge";
import { EmptyState } from "@/components/common/EmptyState";
import { Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Finding, FindingStatus, Severity } from "@/types";

const STATUS_STYLES: Record<FindingStatus, string> = {
  open: "border border-red-200 bg-red-100 text-red-700 dark:border-red-500/25 dark:bg-red-500/10 dark:text-red-300",
  acknowledged: "border border-amber-200 bg-amber-100 text-amber-800 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-300",
  remediated: "border border-emerald-200 bg-emerald-100 text-emerald-700 dark:border-emerald-500/25 dark:bg-emerald-500/10 dark:text-emerald-300",
  false_positive: "border border-border bg-muted text-muted-foreground",
  wont_fix: "border border-border bg-muted text-muted-foreground",
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

interface FindingsListProps {
  findings: Finding[];
  onSelect?: (f: Finding) => void;
}

export function FindingsList({ findings, onSelect }: FindingsListProps) {
  if (!findings.length) {
    return <EmptyState icon={Shield} title="No findings" description="Run a scan to discover findings." />;
  }

  const grouped = findings.reduce<Record<Severity, Finding[]>>((acc, f) => {
    if (!acc[f.severity]) acc[f.severity] = [];
    acc[f.severity].push(f);
    return acc;
  }, {} as Record<Severity, Finding[]>);

  const severities = (Object.keys(grouped) as Severity[]).sort(
    (a, b) => SEVERITY_ORDER[a] - SEVERITY_ORDER[b]
  );

  return (
    <div className="space-y-6">
      {severities.map((sev) => (
        <div key={sev}>
          <div className="flex items-center gap-2 mb-2">
            <SeverityBadge severity={sev} />
            <span className="text-xs text-muted-foreground">{grouped[sev].length} finding{grouped[sev].length !== 1 ? "s" : ""}</span>
          </div>
          <div className="surface-panel divide-y divide-border/70 overflow-hidden">
            {grouped[sev].map((f) => (
              <div
                key={f.id}
                onClick={() => onSelect?.(f)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onSelect?.(f);
                  }
                }}
                role={onSelect ? "button" : undefined}
                tabIndex={onSelect ? 0 : undefined}
                className="flex cursor-pointer items-center gap-3 px-4 py-3 transition-colors hover:bg-accent/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring"
              >
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium truncate">{f.title}</p>
                  <div className="flex flex-wrap items-center gap-1.5 mt-1">
                    <FindingTypeBadge type={f.finding_type} />
                    <ConfidenceBadge confidence={f.confidence} />
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <span className={cn("text-xs rounded px-1.5 py-0.5 font-medium capitalize", STATUS_STYLES[f.status])}>
                    {f.status.replace("_", " ")}
                  </span>
                  <span className="text-xs font-semibold text-muted-foreground w-12 text-right">
                    {f.risk_score.toFixed(1)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
