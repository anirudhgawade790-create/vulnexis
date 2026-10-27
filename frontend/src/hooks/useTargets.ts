import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createTarget, deleteTarget, listTargets, updateTarget } from "@/api/targets";
import type { TargetCreate, TargetUpdate } from "@/types";

export function useListTargets() {
  return useQuery({
    queryKey: ["targets"],
    queryFn: listTargets,
    staleTime: 60_000,
  });
}

export function useCreateTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: TargetCreate) => createTarget(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["targets"] }),
  });
}

export function useUpdateTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: TargetUpdate }) => updateTarget(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["targets"] }),
  });
}

export function useDeleteTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteTarget(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["targets"] }),
  });
}
