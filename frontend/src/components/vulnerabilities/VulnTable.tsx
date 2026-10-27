import { useState } from "react";
import { ExternalLink } from "lucide-react";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { CVSSBadge } from "./CVSSBadge";
import { KEVBadge } from "./KEVBadge";
import { EmptyState } from "@/components/common/EmptyState";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import type { Vulnerability } from "@/types";

interface VulnTableProps {
  vulns: Vulnerability[];
  isLoading?: boolean;
  onSelect?: (vuln: Vulnerability) => void;
}

type SortKey = "cvss_v3_score" | "severity" | "cve_id";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function VulnTable({ vulns, isLoading, onSelect }: VulnTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>("cvss_v3_score");
  const [sortAsc, setSortAsc] = useState(false);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc((p) => !p);
    else { setSortKey(key); setSortAsc(false); }
  };

  const sorted = [...vulns].sort((a, b) => {
    let cmp = 0;
    if (sortKey === "cvss_v3_score") {
      cmp = (b.cvss_v3_score ?? 0) - (a.cvss_v3_score ?? 0);
    } else if (sortKey === "severity") {
      cmp = (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5);
    } else {
      cmp = (a.cve_id ?? "").localeCompare(b.cve_id ?? "");
    }
    return sortAsc ? -cmp : cmp;
  });

  if (isLoading) return <LoadingSpinner label="Loading vulnerabilities…" />;

  if (!vulns.length) return (
    <EmptyState icon={ExternalLink} title="No vulnerabilities" description="Sync the CVE database or run a scan." />
  );

  const SortBtn = ({ col, label }: { col: SortKey; label: string }) => (
    <button onClick={() => handleSort(col)} className="flex items-center gap-1 hover:text-foreground">
      {label}
      {sortKey === col && <span>{sortAsc ? "↑" : "↓"}</span>}
    </button>
  );

  return (
    <Card>
      <CardHeader className="pb-2 text-sm font-medium">Vulnerabilities ({vulns.length})</CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/40 text-xs text-muted-foreground">
              <tr>
                <th className="px-4 py-3 text-left"><SortBtn col="cve_id" label="CVE ID" /></th>
                <th className="px-4 py-3 text-left">Title</th>
                <th className="px-4 py-3 text-left"><SortBtn col="cvss_v3_score" label="CVSS" /></th>
                <th className="px-4 py-3 text-left"><SortBtn col="severity" label="Severity" /></th>
                <th className="px-4 py-3 text-left">KEV</th>
                <th className="px-4 py-3 text-left">Patch</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {sorted.map((v) => (
                <tr
                  key={v.id}
                  onClick={() => onSelect?.(v)}
                  className="cursor-pointer hover:bg-muted/30 transition-colors"
                >
                  <td className="px-4 py-3 font-mono text-xs text-blue-600">{v.cve_id ?? "—"}</td>
                  <td className="px-4 py-3 max-w-xs truncate">{v.title}</td>
                  <td className="px-4 py-3"><CVSSBadge score={v.cvss_v3_score} /></td>
                  <td className="px-4 py-3"><SeverityBadge severity={v.severity} /></td>
                  <td className="px-4 py-3"><KEVBadge isKev={v.is_kev} /></td>
                  <td className="px-4 py-3">
                    {v.patch_available ? (
                      <span className="text-xs text-green-700 font-medium">Available</span>
                    ) : (
                      <span className="text-xs text-muted-foreground">No</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
