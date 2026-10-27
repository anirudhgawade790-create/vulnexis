import { CheckCircle, XCircle, HelpCircle } from "lucide-react";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import type { ControlResult, BaselineControl } from "@/types";
import { cn } from "@/lib/utils";

type ControlRowData = ControlResult & Partial<Pick<BaselineControl, "title" | "severity" | "category">>;

interface ControlRowProps {
  control: ControlRowData;
}

const RESULT_ICONS = {
  pass: CheckCircle,
  fail: XCircle,
  unknown: HelpCircle,
};

const RESULT_COLORS = {
  pass: "text-green-700 dark:text-emerald-400",
  fail: "text-red-700 dark:text-red-400",
  unknown: "text-yellow-700 dark:text-amber-300",
};

export function ControlRow({ control }: ControlRowProps) {
  const Icon = RESULT_ICONS[control.result];
  return (
    <div className="flex items-start gap-3 px-4 py-3 border-b last:border-0">
      <Icon className={cn("h-4 w-4 mt-0.5 shrink-0", RESULT_COLORS[control.result])} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-xs text-muted-foreground">{control.control_id}</span>
          <span className="text-sm font-medium">{control.title ?? control.control_id}</span>
          {control.severity && <SeverityBadge severity={control.severity} />}
        </div>
        {control.evidence && (
          <p className="mt-1 text-xs text-muted-foreground truncate">{control.evidence}</p>
        )}
        {control.last_checked && (
          <p className="mt-0.5 text-xs text-muted-foreground">
            Checked: {new Date(control.last_checked).toLocaleDateString()}
          </p>
        )}
      </div>
      <span className={cn("text-xs font-semibold capitalize shrink-0", RESULT_COLORS[control.result])}>
        {control.result}
      </span>
    </div>
  );
}
