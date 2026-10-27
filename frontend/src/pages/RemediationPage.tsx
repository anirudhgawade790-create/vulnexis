import { PageHeader } from "@/components/layout/PageHeader";
import { RemediationCard } from "@/components/remediation/RemediationCard";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { EmptyState } from "@/components/common/EmptyState";
import { ShieldCheck } from "lucide-react";
import { useListFindings } from "@/hooks/useFindings";
import { useRemediationPlan, useVerifyRemediation } from "@/hooks/useRemediation";

export function RemediationPage() {
  const { data: plan = [], isLoading: planLoading } = useRemediationPlan();
  const { data: findings = [], isLoading: findingsLoading } = useListFindings({ status: "open" });
  const verify = useVerifyRemediation();

  const isLoading = planLoading || findingsLoading;

  // Match findings to remediation details by finding_id
  const findingMap = Object.fromEntries(findings.map((f) => [f.id, f]));

  if (isLoading) return <LoadingSpinner label="Loading remediation plan…" />;

  if (!plan.length) {
    return (
      <>
        <PageHeader title="Remediation" subtitle="Prioritized action plan for open findings." />
        <EmptyState
          icon={ShieldCheck}
          title="No open findings"
          description="All findings are resolved or no scans have been run."
        />
      </>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Remediation"
        subtitle={`${plan.length} prioritized action${plan.length !== 1 ? "s" : ""} — ordered by risk score.`}
      />

      <div className="space-y-4">
        {plan.map((detail) => {
          const finding = findingMap[detail.finding_id];
          if (!finding) return null;
          return (
            <RemediationCard
              key={detail.finding_id}
              finding={finding}
              detail={detail}
              onVerify={(id) => verify.mutate({ findingId: id })}
            />
          );
        })}
      </div>
    </div>
  );
}
