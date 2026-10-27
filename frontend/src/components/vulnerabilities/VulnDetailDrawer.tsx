import { ExternalLink, X } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { CVSSBadge } from "./CVSSBadge";
import { KEVBadge } from "./KEVBadge";
import type { Vulnerability } from "@/types";

interface VulnDetailDrawerProps {
  vuln: Vulnerability | null;
  onClose: () => void;
}

export function VulnDetailDrawer({ vuln, onClose }: VulnDetailDrawerProps) {
  if (!vuln) return null;

  const refs = (vuln.references ?? []) as { url?: string; source?: string }[];

  return (
    <Dialog open={!!vuln} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-start justify-between gap-2 pr-8">
            <div>
              {vuln.cve_id && (
                <p className="font-mono text-sm text-blue-600 mb-1">{vuln.cve_id}</p>
              )}
              <DialogTitle className="text-base leading-snug">{vuln.title}</DialogTitle>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-4">
          {/* Badges */}
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={vuln.severity} />
            <CVSSBadge score={vuln.cvss_v3_score} />
            <KEVBadge isKev={vuln.is_kev} />
            {vuln.patch_available && (
              <span className="text-xs font-medium text-green-700 bg-green-100 border border-green-200 px-1.5 py-0.5 rounded">
                Patch Available
              </span>
            )}
          </div>

          {/* Description */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">Description</p>
            <p className="text-sm leading-relaxed">{vuln.description}</p>
          </div>

          {/* CVSS Vector */}
          {vuln.cvss_v3_vector && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">CVSS v3 Vector</p>
              <code className="text-xs bg-muted px-2 py-1 rounded block break-all">{vuln.cvss_v3_vector}</code>
            </div>
          )}

          {/* KEV dates */}
          {vuln.is_kev && (
            <div className="rounded border border-red-200 bg-red-50 p-3 text-sm space-y-1">
              <p className="font-semibold text-red-800">CISA Known Exploited Vulnerability</p>
              {vuln.kev_date_added && <p className="text-xs text-red-700">Added: {vuln.kev_date_added}</p>}
              {vuln.kev_due_date && <p className="text-xs text-red-700">Remediation due: {vuln.kev_due_date}</p>}
            </div>
          )}

          {/* References */}
          {refs.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1">References</p>
              <ul className="space-y-1">
                {refs.slice(0, 8).map((r, i) => (
                  <li key={i} className="text-xs">
                    {r.url ? (
                      <a href={r.url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-blue-600 hover:underline break-all">
                        <ExternalLink className="h-3 w-3 shrink-0" />
                        {r.source ?? r.url}
                      </a>
                    ) : (
                      <span>{r.source}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <p className="text-xs text-muted-foreground">Source: {vuln.source} · Fetched: {new Date(vuln.fetched_at).toLocaleDateString()}</p>
        </div>
      </DialogContent>
    </Dialog>
  );
}
