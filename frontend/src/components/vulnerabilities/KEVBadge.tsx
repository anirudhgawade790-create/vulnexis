import { ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";

interface KEVBadgeProps {
  isKev: boolean;
  className?: string;
}

export function KEVBadge({ isKev, className }: KEVBadgeProps) {
  if (!isKev) return null;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded border border-red-300 bg-red-100 px-1.5 py-0.5 text-xs font-semibold text-red-800", className)}>
      <ShieldAlert className="h-3 w-3" />
      KEV
    </span>
  );
}
