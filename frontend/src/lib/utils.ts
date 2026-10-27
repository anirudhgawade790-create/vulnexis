import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { format, formatDistanceToNow, parseISO } from "date-fns";

import type { Severity } from "@/types";

/** Merge Tailwind classes with conditional support. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Format an ISO date string as a readable date. */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return format(parseISO(iso), "MMM d, yyyy HH:mm");
  } catch {
    return iso;
  }
}

/** Format an ISO date as a relative time ("2 days ago"). */
export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return formatDistanceToNow(parseISO(iso), { addSuffix: true });
  } catch {
    return iso;
  }
}

/** Format a CVSS score to one decimal place. */
export function formatCVSS(score: number | null | undefined): string {
  if (score === null || score === undefined) return "—";
  return score.toFixed(1);
}

/** Map a severity to a hex/text color token. */
export function severityColor(sev: Severity): string {
  switch (sev) {
    case "critical":
      return "#F87171";
    case "high":
      return "#FB923C";
    case "medium":
      return "#FBBF24";
    case "low":
      return "#34D399";
    case "info":
      return "#22D3EE";
    default:
      return "#64748b";
  }
}

/** Tailwind background classes per severity (for badges/chips). */
export function severityBgColor(sev: Severity): string {
  switch (sev) {
    case "critical":
      return "bg-red-100 text-red-800 border-red-200 dark:bg-red-500/10 dark:text-red-300 dark:border-red-500/25";
    case "high":
      return "bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-500/10 dark:text-orange-300 dark:border-orange-500/25";
    case "medium":
      return "bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-amber-500/10 dark:text-amber-300 dark:border-amber-500/25";
    case "low":
      return "bg-green-100 text-green-800 border-green-200 dark:bg-emerald-500/10 dark:text-emerald-300 dark:border-emerald-500/25";
    case "info":
      return "bg-blue-100 text-blue-800 border-blue-200 dark:bg-cyan-500/10 dark:text-cyan-300 dark:border-cyan-500/25";
    default:
      return "bg-slate-100 text-slate-800 border-slate-200";
  }
}

/** Map a CVSS score to a severity label. */
export function cvssToSeverity(score: number | null | undefined): Severity {
  if (score === null || score === undefined) return "info";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "info";
}

/** Truncate a UUID to a short display form. */
export function shortId(id: string | null | undefined): string {
  if (!id) return "—";
  return id.slice(0, 8);
}
