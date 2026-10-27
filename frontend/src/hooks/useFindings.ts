import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { assignFinding, getFinding, listFindings, updateFindingStatus } from "@/api/findings";
import type { Finding, FindingStatusUpdate, ListParams } from "@/types";

export function useListFindings(params: ListParams = {}) {
  return useQuery({
    queryKey: ["findings", params],
    queryFn: () => listFindings(params),
    staleTime: 30_000,
  });
}

export function useFinding(id: string | undefined) {
  return useQuery({
    queryKey: ["findings", id],
    queryFn: () => getFinding(id as string),
    enabled: !!id,
  });
}

export function useUpdateFindingStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: FindingStatusUpdate }) =>
      updateFindingStatus(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });
}

export function useAssignFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, userId }: { id: string; userId: string }) =>
      assignFinding(id, userId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings"] }),
  });
}

export type { Finding };
