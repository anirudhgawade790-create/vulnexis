import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { assessBaseline, createPolicy, getBaselineResults, listPolicies } from "@/api/baseline";
import type { BaselinePolicyCreate } from "@/types";

export function useListPolicies() {
  return useQuery({
    queryKey: ["baseline", "policies"],
    queryFn: listPolicies,
    staleTime: 60_000,
  });
}

export function useBaselineResults() {
  return useQuery({
    queryKey: ["baseline", "results"],
    queryFn: getBaselineResults,
    staleTime: 60_000,
  });
}

export function useAssessBaseline() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanJobId: string) => assessBaseline(scanJobId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["baseline"] }),
  });
}

export function useCreatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: BaselinePolicyCreate) => createPolicy(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["baseline", "policies"] }),
  });
}
