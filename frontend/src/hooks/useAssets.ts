import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getAsset, getAssetFindings, getAssetHistory, listAssets, updateAsset } from "@/api/assets";
import type { Asset, AssetUpdate, ListParams } from "@/types";

export function useListAssets(params: ListParams = {}) {
  return useQuery({
    queryKey: ["assets", params],
    queryFn: () => listAssets(params),
    staleTime: 30_000,
  });
}

export function useAsset(id: string | undefined) {
  return useQuery({
    queryKey: ["assets", id],
    queryFn: () => getAsset(id as string),
    enabled: !!id,
  });
}

export function useAssetFindings(id: string | undefined) {
  return useQuery({
    queryKey: ["assets", id, "findings"],
    queryFn: () => getAssetFindings(id as string),
    enabled: !!id,
  });
}

export function useAssetHistory(id: string | undefined) {
  return useQuery({
    queryKey: ["assets", id, "history"],
    queryFn: () => getAssetHistory(id as string),
    enabled: !!id,
  });
}

export function useUpdateAsset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: AssetUpdate }) => updateAsset(id, data),
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: ["assets", id] });
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });
}

export type { Asset };
