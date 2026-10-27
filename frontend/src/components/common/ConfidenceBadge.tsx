import { Badge } from "@/components/ui/badge";
import type { Confidence } from "@/types";

const CONFIDENCE_STYLE: Record<Confidence, string> = {
  confirmed: "bg-blue-100 text-blue-800 border-blue-200",
  high: "bg-sky-100 text-sky-800 border-sky-200",
  medium: "bg-slate-100 text-slate-800 border-slate-200",
  low: "bg-gray-100 text-gray-600 border-gray-200",
};

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  return (
    <Badge variant="outline" className={CONFIDENCE_STYLE[confidence]}>
      <span className="capitalize">{confidence}</span>
    </Badge>
  );
}
