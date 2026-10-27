import { apiClient } from "./client";
import type { ListParams, VulnSyncResponse, Vulnerability } from "@/types";

export async function listVulnerabilities(
  params: ListParams = {}
): Promise<Vulnerability[]> {
  const res = await apiClient.get<Vulnerability[]>("/vulnerabilities/", { params });
  return res.data;
}

export async function getVulnerability(id: string): Promise<Vulnerability> {
  const res = await apiClient.get<Vulnerability>(`/vulnerabilities/${id}`);
  return res.data;
}

export async function listKev(): Promise<Vulnerability[]> {
  const res = await apiClient.get<Vulnerability[]>("/vulnerabilities/kev");
  return res.data;
}

export async function syncVulnerabilities(): Promise<VulnSyncResponse> {
  const res = await apiClient.post<VulnSyncResponse>("/vulnerabilities/sync");
  return res.data;
}
