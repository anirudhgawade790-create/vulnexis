import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getVulnerability, listKev, listVulnerabilities, syncVulnerabilities } from "@/api/vulnerabilities";
import type { ListParams } from "@/types";

export function useListVulnerabilities(params: ListParams = {}) {
  return useQuery({
    queryKey: ["vulnerabilities", params],
    queryFn: () => listVulnerabilities(params),
    staleTime: 60_000,
  });
}

export function useVulnerability(id: string | undefined) {
  return useQuery({
    queryKey: ["vulnerabilities", id],
    queryFn: () => getVulnerability(id as string),
    enabled: !!id,
  });
}

export function useKevList() {
  return useQuery({
    queryKey: ["vulnerabilities", "kev"],
    queryFn: listKev,
    staleTime: 300_000,
  });
}

export function useSyncVulnerabilities() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: syncVulnerabilities,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["vulnerabilities"] }),
  });
}
