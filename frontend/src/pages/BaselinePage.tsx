import { useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { BaselineComplianceChart } from "@/components/baseline/BaselineComplianceChart";
import { ControlRow } from "@/components/baseline/ControlRow";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { EmptyState } from "@/components/common/EmptyState";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { ShieldCheck } from "lucide-react";
import { useListPolicies, useBaselineResults } from "@/hooks/useBaseline";
import type { BaselineControl } from "@/types";

export function BaselinePage() {
  const { data: policies = [], isLoading: policiesLoading } = useListPolicies();
  const { data: results, isLoading: resultsLoading } = useBaselineResults();
  const [selectedPolicyId, setSelectedPolicyId] = useState<string>("");

  const isLoading = policiesLoading || resultsLoading;

  const selectedPolicy = policies.find((p) => p.id === selectedPolicyId) ?? policies[0];
  const controls: BaselineControl[] = (selectedPolicy?.controls ?? []) as BaselineControl[];

  // Merge control metadata with results
  const resultMap = Object.fromEntries(
    (results?.results ?? []).map((r) => [r.control_id, r])
  );
  const enriched = controls.map((c) => ({
    ...c,
    ...(resultMap[c.id] ?? {}),
    control_id: c.id,
  }));

  if (isLoading) return <LoadingSpinner label="Loading baseline…" />;

  if (!policies.length) {
    return (
      <>
        <PageHeader title="Baseline Compliance" subtitle="Check compliance against security frameworks." />
        <EmptyState icon={ShieldCheck} title="No policies configured" description="Create a baseline policy in Settings." />
      </>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Baseline Compliance"
        subtitle="Security configuration compliance checks."
      />

      {/* Policy selector */}
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium">Policy:</span>
        <Select value={selectedPolicy?.id ?? ""} onValueChange={setSelectedPolicyId}>
          <SelectTrigger className="w-56">
            <SelectValue placeholder="Select policy" />
          </SelectTrigger>
          <SelectContent>
            {policies.map((p) => (
              <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Summary bar */}
      {results && (
        <div className="grid grid-cols-3 gap-3 sm:grid-cols-5 text-center">
          {[
            { label: "Total", value: results.total_controls },
            { label: "Passed", value: results.passed, cls: "text-green-600" },
            { label: "Failed", value: results.failed, cls: "text-red-600" },
            { label: "Unknown", value: results.unknown, cls: "text-yellow-600" },
            { label: "Compliance", value: `${results.compliance_percentage.toFixed(0)}%` },
          ].map((s) => (
            <Card key={s.label}>
              <CardContent className="p-3 text-center">
                <p className={`text-2xl font-semibold ${s.cls ?? ""}`}>{s.value}</p>
                <p className="text-xs text-muted-foreground">{s.label}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Chart */}
      <BaselineComplianceChart controls={controls} />

      {/* Control rows */}
      <Card>
        <CardHeader className="pb-0 text-sm font-medium">Controls ({enriched.length})</CardHeader>
        <CardContent className="p-0">
          {enriched.map((c) => (
            <ControlRow key={c.control_id} control={c} />
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
