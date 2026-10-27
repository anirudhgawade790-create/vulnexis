import { cn } from "@/lib/utils";
import type { Effort } from "@/types";

const EFFORT_STYLES: Record<Effort, string> = {
  low: "bg-green-100 text-green-800 border-green-200",
  medium: "bg-yellow-100 text-yellow-800 border-yellow-200",
  high: "bg-orange-100 text-orange-800 border-orange-200",
  critical: "bg-red-100 text-red-800 border-red-200",
};

const EFFORT_LABELS: Record<Effort, string> = {
  low: "Low Effort",
  medium: "Medium Effort",
  high: "High Effort",
  critical: "Critical Effort",
};

export function EffortBadge({ effort, className }: { effort: Effort; className?: string }) {
  return (
    <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium", EFFORT_STYLES[effort], className)}>
      {EFFORT_LABELS[effort]}
    </span>
  );
}
