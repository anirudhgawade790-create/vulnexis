import { apiClient } from "./client";
import type { RemediationDetail } from "@/types";

export async function getRemediationPlan(): Promise<RemediationDetail[]> {
  const res = await apiClient.get<RemediationDetail[]>("/remediation/plan");
  return res.data;
}

export async function getFindingRemediation(
  findingId: string
): Promise<RemediationDetail> {
  const res = await apiClient.get<RemediationDetail>(
    `/remediation/${findingId}`
  );
  return res.data;
}

export async function verifyRemediation(
  findingId: string,
  notes = ""
): Promise<{ status: string; finding_id: string; message: string }> {
  const res = await apiClient.post(`/remediation/${findingId}/verify`, {
    notes,
  });
  return res.data;
}
