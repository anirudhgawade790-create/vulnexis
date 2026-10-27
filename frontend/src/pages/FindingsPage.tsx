import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { PageHeader } from "@/components/layout/PageHeader";
import { FindingsList } from "@/components/findings/FindingsList";
import { FindingDetailPanel } from "@/components/findings/FindingDetailPanel";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { useListFindings } from "@/hooks/useFindings";
import { useDebounce } from "@/hooks/useDebounce";
import type { Finding, FindingStatus, FindingType, Severity } from "@/types";
import { Search } from "lucide-react";

export function FindingsPage() {
  const [searchParams] = useSearchParams();
  const scanJobId = searchParams.get("scan_job_id") ?? undefined;

  const [selected, setSelected] = useState<Finding | null>(null);
  const [severity, setSeverity] = useState<string>("all");
  const [status, setStatus] = useState<string>("all");
  const [type, setType] = useState<string>("all");
  const [search, setSearch] = useState(searchParams.get("search") ?? "");
  const debouncedSearch = useDebounce(search, 250);

  useEffect(() => {
    setSearch(searchParams.get("search") ?? "");
  }, [searchParams]);

  const params: Record<string, unknown> = {};
  if (scanJobId) params.scan_job_id = scanJobId;
  if (severity !== "all") params.severity = severity;
  if (status !== "all") params.status = status;
  if (type !== "all") params.finding_type = type;

  const findingsQuery = useListFindings(params);
  const { data: findings = [], isLoading } = findingsQuery;
  const filteredFindings = debouncedSearch
    ? findings.filter((finding) =>
        `${finding.title} ${finding.check_name} ${finding.asset_id} ${finding.vulnerability_id ?? ""} ${finding.evidence}`
          .toLowerCase()
          .includes(debouncedSearch.toLowerCase())
      )
    : findings;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Findings"
        subtitle={scanJobId ? `Findings from scan ${scanJobId.slice(0, 8)}…` : "All findings across scans."}
      />

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-border bg-card/60 p-3">
        <div className="relative min-w-[220px] flex-1 sm:max-w-sm">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search title, CVE, asset, or evidence"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            className="pl-9"
          />
        </div>
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger className="w-full sm:w-36">
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

        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger className="w-full sm:w-40">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="acknowledged">Acknowledged</SelectItem>
            <SelectItem value="remediated">Remediated</SelectItem>
            <SelectItem value="false_positive">False Positive</SelectItem>
            <SelectItem value="wont_fix">Won't Fix</SelectItem>
          </SelectContent>
        </Select>

        <Select value={type} onValueChange={setType}>
          <SelectTrigger className="w-full sm:w-44">
            <SelectValue placeholder="Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            <SelectItem value="confirmed_vulnerability">Confirmed Vuln</SelectItem>
            <SelectItem value="potential_vulnerability">Potential Vuln</SelectItem>
            <SelectItem value="misconfiguration">Misconfiguration</SelectItem>
            <SelectItem value="network_exposure">Network Exposure</SelectItem>
            <SelectItem value="informational">Informational</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {findingsQuery.isError ? (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm">
          <span className="text-destructive">Findings could not be loaded.</span>
          <button className="font-medium text-foreground underline-offset-4 hover:underline" onClick={() => void findingsQuery.refetch()}>
            Try again
          </button>
        </div>
      ) : isLoading ? (
        <div className="rounded-xl border border-border bg-card/50 px-5 py-10 text-center text-sm text-muted-foreground">
          Loading findings…
        </div>
      ) : (
        <FindingsList findings={filteredFindings} onSelect={setSelected} />
      )}

      <FindingDetailPanel finding={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
