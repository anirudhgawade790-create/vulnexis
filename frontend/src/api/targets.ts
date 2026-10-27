import { apiClient } from "./client";
import type { Target, TargetCreate, TargetUpdate } from "@/types";

export async function listTargets(): Promise<Target[]> {
  const res = await apiClient.get<Target[]>("/targets/");
  return res.data;
}

export async function getTarget(id: string): Promise<Target> {
  const res = await apiClient.get<Target>(`/targets/${id}`);
  return res.data;
}

export async function createTarget(data: TargetCreate): Promise<Target> {
  const res = await apiClient.post<Target>("/targets/", data);
  return res.data;
}

export async function updateTarget(id: string, data: TargetUpdate): Promise<Target> {
  const res = await apiClient.put<Target>(`/targets/${id}`, data);
  return res.data;
}

export async function deleteTarget(id: string): Promise<void> {
  await apiClient.delete(`/targets/${id}`);
}
