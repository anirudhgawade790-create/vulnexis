import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getFindingRemediation, getRemediationPlan, verifyRemediation } from "@/api/remediation";

export function useRemediationPlan() {
  return useQuery({
    queryKey: ["remediation", "plan"],
    queryFn: getRemediationPlan,
    staleTime: 60_000,
  });
}

export function useFindingRemediation(findingId: string | undefined) {
  return useQuery({
    queryKey: ["remediation", findingId],
    queryFn: () => getFindingRemediation(findingId as string),
    enabled: !!findingId,
  });
}

export function useVerifyRemediation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ findingId, notes }: { findingId: string; notes?: string }) =>
      verifyRemediation(findingId, notes),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["remediation"] });
    },
  });
}
