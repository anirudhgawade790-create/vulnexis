import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  cancelScan,
  createScan,
  getScan,
  getScanResults,
  listScans,
} from "@/api/scans";
import type { ScanJob, ScanJobCreate, ScanResultsSummary } from "@/types";

export function useListScans() {
  return useQuery({
    queryKey: ["scans"],
    queryFn: () => listScans(),
    staleTime: 30_000,
  });
}

export function useScan(id: string | undefined) {
  return useQuery({
    queryKey: ["scans", id],
    queryFn: () => getScan(id as string),
    enabled: !!id,
  });
}

export function useScanResults(id: string | undefined) {
  return useQuery({
    queryKey: ["scans", id, "results"],
    queryFn: () => getScanResults(id as string),
    enabled: !!id,
  });
}

export function useCreateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: ScanJobCreate) => createScan(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => cancelScan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

export function usePrefetchScan() {
  const qc = useQueryClient();
  return (id: string) =>
    qc.prefetchQuery({
      queryKey: ["scans", id],
      queryFn: () => getScan(id),
      staleTime: 30_000,
    });
}

export type { ScanJob, ScanResultsSummary };