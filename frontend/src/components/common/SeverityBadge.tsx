import { Badge } from "@/components/ui/badge";
import { SEVERITY_LABELS } from "@/lib/constants";
import type { Severity } from "@/types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant={severity as never} className="capitalize">
      {SEVERITY_LABELS[severity] ?? severity}
    </Badge>
  );
}
