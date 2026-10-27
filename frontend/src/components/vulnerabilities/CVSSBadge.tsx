import { cn } from "@/lib/utils";

interface CVSSBadgeProps {
  score: number | null;
  className?: string;
}

function getCVSSColor(score: number): string {
  if (score >= 9.0) return "bg-red-100 text-red-800 border-red-200";
  if (score >= 7.0) return "bg-orange-100 text-orange-800 border-orange-200";
  if (score >= 4.0) return "bg-yellow-100 text-yellow-800 border-yellow-200";
  return "bg-green-100 text-green-800 border-green-200";
}

export function CVSSBadge({ score, className }: CVSSBadgeProps) {
  if (score === null || score === undefined) {
    return (
      <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium bg-muted text-muted-foreground", className)}>
        N/A
      </span>
    );
  }
  return (
    <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-mono font-semibold", getCVSSColor(score), className)}>
      {score.toFixed(1)}
    </span>
  );
}
