import { useQuery } from "@tanstack/react-query";

import {
  getDashboardSummary,
  getExposureMap,
  getInsights,
  getTopRisks,
  getTrends,
} from "@/api/dashboard";

export function useDashboardSummary() {
  return useQuery({
    queryKey: ["dashboard", "summary"],
    queryFn: getDashboardSummary,
    staleTime: 30_000,
  });
}

export function useTrends() {
  return useQuery({
    queryKey: ["dashboard", "trends"],
    queryFn: getTrends,
    staleTime: 60_000,
  });
}

export function useInsights() {
  return useQuery({
    queryKey: ["dashboard", "insights"],
    queryFn: getInsights,
    staleTime: 30_000,
  });
}

export function useTopRisks() {
  return useQuery({
    queryKey: ["dashboard", "top-risks"],
    queryFn: getTopRisks,
    staleTime: 30_000,
  });
}

export function useExposureMap() {
  return useQuery({
    queryKey: ["dashboard", "exposure-map"],
    queryFn: getExposureMap,
    staleTime: 60_000,
  });
}
