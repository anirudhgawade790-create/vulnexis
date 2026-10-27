import { apiClient } from "./client";
import type {
  BaselinePolicy,
  BaselinePolicyCreate,
  BaselinePolicyUpdate,
  BaselineResultSummary,
} from "@/types";

export async function listPolicies(): Promise<BaselinePolicy[]> {
  const res = await apiClient.get<BaselinePolicy[]>("/baseline/policies");
  return res.data;
}

export async function getPolicy(id: string): Promise<BaselinePolicy> {
  const res = await apiClient.get<BaselinePolicy>(`/baseline/policies/${id}`);
  return res.data;
}

export async function createPolicy(
  data: BaselinePolicyCreate
): Promise<BaselinePolicy> {
  const res = await apiClient.post<BaselinePolicy>("/baseline/policies", data);
  return res.data;
}

export async function updatePolicy(
  id: string,
  data: BaselinePolicyUpdate
): Promise<BaselinePolicy> {
  const res = await apiClient.put<BaselinePolicy>(
    `/baseline/policies/${id}`,
    data
  );
  return res.data;
}

export async function deletePolicy(id: string): Promise<void> {
  await apiClient.delete(`/baseline/policies/${id}`);
}

export async function getBaselineResults(): Promise<BaselineResultSummary> {
  const res = await apiClient.get<BaselineResultSummary>("/baseline/results");
  return res.data;
}

export async function assessBaseline(
  scanJobId: string
): Promise<BaselineResultSummary> {
  const res = await apiClient.post<BaselineResultSummary>(
    `/baseline/assess/${scanJobId}`
  );
  return res.data;
}
