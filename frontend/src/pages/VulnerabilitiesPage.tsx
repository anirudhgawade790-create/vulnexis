import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { VulnTable } from "@/components/vulnerabilities/VulnTable";
import { VulnDetailDrawer } from "@/components/vulnerabilities/VulnDetailDrawer";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useListVulnerabilities, useSyncVulnerabilities } from "@/hooks/useVulnerabilities";
import type { Severity, Vulnerability } from "@/types";

export function VulnerabilitiesPage() {
  const [selected, setSelected] = useState<Vulnerability | null>(null);
  const [severity, setSeverity] = useState<string>("all");
  const [kevOnly, setKevOnly] = useState(false);

  const params: Record<string, unknown> = {};
  if (severity !== "all") params.severity = severity;
  if (kevOnly) params.is_kev = true;

  const { data: vulns = [], isLoading } = useListVulnerabilities(params);
  const sync = useSyncVulnerabilities();

  return (
    <div className="space-y-6">
      <PageHeader
        title="Vulnerabilities"
        subtitle="CVE database with CVSS scores and CISA KEV indicators."
        action={
          <Button
            variant="outline"
            size="sm"
            onClick={() => sync.mutate()}
            disabled={sync.isPending}
            className="gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${sync.isPending ? "animate-spin" : ""}`} />
            Sync CVEs
          </Button>
        }
      />

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <label className="flex items-center gap-2 text-sm cursor-pointer select-none">
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={(e) => setKevOnly(e.target.checked)}
            className="rounded"
          />
          KEV only
        </label>
      </div>

      <VulnTable vulns={vulns} isLoading={isLoading} onSelect={setSelected} />

      <VulnDetailDrawer vuln={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
