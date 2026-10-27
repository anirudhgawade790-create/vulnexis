import { apiClient } from "./client";
import type { Finding, FindingStatusUpdate, ListParams } from "@/types";

export async function listFindings(params: ListParams = {}): Promise<Finding[]> {
  const res = await apiClient.get<Finding[]>("/findings/", { params });
  return res.data;
}

export async function getFinding(id: string): Promise<Finding> {
  const res = await apiClient.get<Finding>(`/findings/${id}`);
  return res.data;
}

export async function updateFindingStatus(
  id: string,
  data: FindingStatusUpdate
): Promise<Finding> {
  const res = await apiClient.patch<Finding>(`/findings/${id}/status`, data);
  return res.data;
}

export async function assignFinding(
  id: string,
  userId: string
): Promise<Finding> {
  const res = await apiClient.post<Finding>(`/findings/${id}/assign`, {
    user_id: userId,
  });
  return res.data;
}
