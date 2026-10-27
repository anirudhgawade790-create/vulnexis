import { apiClient } from "./client";
import type {
  DashboardSummary,
  ExposureMapData,
  InsightItem,
  TopRiskItem,
  TrendData,
} from "@/types";

export async function getDashboardSummary(): Promise<DashboardSummary> {
  const res = await apiClient.get<DashboardSummary>("/dashboard/summary");
  return res.data;
}

export async function getTrends(): Promise<TrendData> {
  const res = await apiClient.get<TrendData>("/dashboard/trends");
  return res.data;
}

export async function getInsights(): Promise<InsightItem[]> {
  const res = await apiClient.get<InsightItem[]>("/dashboard/insights");
  return res.data;
}

export async function getTopRisks(): Promise<TopRiskItem[]> {
  const res = await apiClient.get<TopRiskItem[]>("/dashboard/top-risks");
  return res.data;
}

export async function getExposureMap(): Promise<ExposureMapData> {
  const res = await apiClient.get<ExposureMapData>("/dashboard/exposure-map");
  return res.data;
}
