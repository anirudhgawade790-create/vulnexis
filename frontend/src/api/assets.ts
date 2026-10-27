import { apiClient } from "./client";
import type { Asset, AssetUpdate, Finding, ListParams } from "@/types";

export async function listAssets(params: ListParams = {}): Promise<Asset[]> {
  const res = await apiClient.get<Asset[]>("/assets/", { params });
  return res.data;
}

export async function getAsset(id: string): Promise<Asset> {
  const res = await apiClient.get<Asset>(`/assets/${id}`);
  return res.data;
}

export async function updateAsset(
  id: string,
  data: AssetUpdate
): Promise<Asset> {
  const res = await apiClient.patch<Asset>(`/assets/${id}`, data);
  return res.data;
}

export async function getAssetFindings(id: string): Promise<Finding[]> {
  const res = await apiClient.get<Finding[]>(`/assets/${id}/findings`);
  return res.data;
}

export async function getAssetHistory(id: string): Promise<Asset[]> {
  const res = await apiClient.get<Asset[]>(`/assets/${id}/history`);
  return res.data;
}
