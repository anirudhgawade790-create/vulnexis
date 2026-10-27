import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { ConfidenceBadge } from "@/components/common/ConfidenceBadge";
import { FindingTypeBadge } from "./FindingTypeBadge";
import { PowerShellBlock } from "@/components/remediation/PowerShellBlock";
import type { Finding } from "@/types";

interface FindingDetailPanelProps {
  finding: Finding | null;
  onClose: () => void;
}

export function FindingDetailPanel({ finding, onClose }: FindingDetailPanelProps) {
  if (!finding) return null;

  return (
    <Dialog open={!!finding} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-base leading-snug pr-8">{finding.title}</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          {/* Meta badges */}
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <FindingTypeBadge type={finding.finding_type} />
            <ConfidenceBadge confidence={finding.confidence} />
            <span className="text-xs text-muted-foreground">Risk: {finding.risk_score.toFixed(1)}</span>
          </div>

          {/* Evidence */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Evidence</p>
            <div className="rounded bg-muted px-3 py-2 text-sm font-mono whitespace-pre-wrap break-words">
              {finding.evidence}
            </div>
          </div>

          {/* Detection Method */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Detection Method</p>
            <p className="text-sm">{finding.detection_method}</p>
          </div>

          {/* Risk explanation */}
          {finding.risk_explanation && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Risk Explanation</p>
              <p className="text-sm">{finding.risk_explanation}</p>
            </div>
          )}

          {/* Business impact */}
          {finding.business_impact && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Business Impact</p>
              <p className="text-sm">{finding.business_impact}</p>
            </div>
          )}

          {/* Remediation steps */}
          {finding.remediation_steps && finding.remediation_steps.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">Remediation Steps</p>
              <ol className="space-y-3">
                {finding.remediation_steps.map((s, i) => (
                  <li key={i} className="space-y-1">
                    <p className="text-sm font-medium">{i + 1}. {s.step}</p>
                    {s.command && <PowerShellBlock code={s.command} />}
                  </li>
                ))}
              </ol>
            </div>
          )}

          {/* Recommended action */}
          {finding.recommended_action && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Recommended Action</p>
              <p className="text-sm">{finding.recommended_action}</p>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
