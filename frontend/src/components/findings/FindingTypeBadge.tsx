import { cn } from "@/lib/utils";
import { FINDING_TYPE_LABELS } from "@/lib/constants";
import type { FindingType } from "@/types";

const TYPE_STYLES: Record<FindingType, string> = {
  confirmed_vulnerability: "bg-red-100 text-red-800 border-red-200 dark:bg-red-500/10 dark:text-red-300 dark:border-red-500/25",
  potential_vulnerability: "bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-500/10 dark:text-orange-300 dark:border-orange-500/25",
  misconfiguration: "bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-amber-500/10 dark:text-amber-300 dark:border-amber-500/25",
  network_exposure: "bg-blue-100 text-blue-800 border-blue-200 dark:bg-cyan-500/10 dark:text-cyan-300 dark:border-cyan-500/25",
  informational: "bg-gray-100 text-gray-700 border-gray-200 dark:bg-slate-500/10 dark:text-slate-300 dark:border-slate-500/25",
};

export function FindingTypeBadge({ type, className }: { type: FindingType; className?: string }) {
  return (
    <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium", TYPE_STYLES[type], className)}>
      {FINDING_TYPE_LABELS[type] ?? type}
    </span>
  );
}
