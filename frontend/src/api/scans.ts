import { apiClient } from "./client";
import type {
  ChangeDetectionReport,
  ListParams,
  ScanJob,
  ScanJobCreate,
  ScanResultsSummary,
} from "@/types";

export async function listScans(params: ListParams = {}): Promise<ScanJob[]> {
  const res = await apiClient.get<ScanJob[]>("/scans/", { params });
  return res.data;
}

export async function createScan(data: ScanJobCreate): Promise<ScanJob> {
  const res = await apiClient.post<ScanJob>("/scans/", data);
  return res.data;
}

export async function getScan(id: string): Promise<ScanJob> {
  const res = await apiClient.get<ScanJob>(`/scans/${id}`);
  return res.data;
}

export async function cancelScan(id: string): Promise<void> {
  await apiClient.delete(`/scans/${id}/cancel`);
}

export async function getScanResults(id: string): Promise<ScanResultsSummary> {
  const res = await apiClient.get<ScanResultsSummary>(`/scans/${id}/results`);
  return res.data;
}

export async function compareScans(
  id: string,
  prevId: string
): Promise<ChangeDetectionReport> {
  const res = await apiClient.get<ChangeDetectionReport>(
    `/scans/${id}/compare/${prevId}`
  );
  return res.data;
}

/**
 * Build the SSE EventSource URL for live scan progress.
 * Returns a string URL (not fetched via axios) to be opened with EventSource.
 */
export function getScanProgressUrl(id: string): string {
  return `${apiClient.defaults.baseURL ?? ""}/scans/${id}/progress`;
}
