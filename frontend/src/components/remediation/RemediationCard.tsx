import { useState } from "react";
import { ChevronDown, ChevronUp, CheckCircle } from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { EffortBadge } from "./EffortBadge";
import { PowerShellBlock } from "./PowerShellBlock";
import type { Finding, RemediationDetail } from "@/types";

interface RemediationCardProps {
  finding: Finding;
  detail: RemediationDetail | null;
  onVerify?: (findingId: string) => void;
}

export function RemediationCard({ finding, detail, onVerify }: RemediationCardProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <p className="truncate font-medium">{finding.title}</p>
            <p className="mt-0.5 text-xs text-muted-foreground">{finding.check_name}</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            {detail && <EffortBadge effort={detail.estimated_effort} />}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {detail && (
          <p className="text-sm text-muted-foreground">{detail.plain_explanation}</p>
        )}

        {finding.business_impact && (
          <div className="rounded bg-muted px-3 py-2 text-xs text-muted-foreground">
            <span className="font-semibold text-foreground">Business impact: </span>
            {finding.business_impact}
          </div>
        )}

        {/* Steps accordion */}
        {finding.remediation_steps && finding.remediation_steps.length > 0 && (
          <div>
            <button
              onClick={() => setExpanded((p) => !p)}
              className="flex w-full items-center justify-between text-sm font-medium text-primary hover:underline"
            >
              Remediation steps ({finding.remediation_steps.length})
              {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>

            {expanded && (
              <ol className="mt-2 space-y-2 text-sm">
                {finding.remediation_steps.map((s, i) => (
                  <li key={i} className="space-y-1">
                    <p className="font-medium">{i + 1}. {s.step}</p>
                    {s.command && <PowerShellBlock code={s.command} />}
                  </li>
                ))}
              </ol>
            )}
          </div>
        )}

        {detail?.powershell_examples && detail.powershell_examples.length > 0 && expanded && (
          <div className="space-y-2">
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">PowerShell Examples</p>
            {detail.powershell_examples.map((cmd, i) => (
              <PowerShellBlock key={i} code={cmd} />
            ))}
          </div>
        )}

        <div className="flex justify-end pt-1">
          <Button
            size="sm"
            variant="outline"
            onClick={() => onVerify?.(finding.id)}
            className="gap-1.5"
          >
            <CheckCircle className="h-3.5 w-3.5" />
            Mark Verified
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
