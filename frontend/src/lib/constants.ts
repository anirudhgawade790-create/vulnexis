import type { FindingType, ScanStatus, Severity } from "@/types";

/** Base URL for the API. The Vite dev proxy forwards /api to the backend. */
export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

export const SEVERITY_LEVELS: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const FINDING_TYPES: FindingType[] = [
  "confirmed_vulnerability",
  "potential_vulnerability",
  "misconfiguration",
  "network_exposure",
  "informational",
];

export const FINDING_TYPE_LABELS: Record<FindingType, string> = {
  confirmed_vulnerability: "Confirmed Vuln",
  potential_vulnerability: "Potential Vuln",
  misconfiguration: "Misconfiguration",
  network_exposure: "Network Exposure",
  informational: "Informational",
};

export const SCAN_STATUS_LABELS: Record<ScanStatus, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

export const ROUTES = {
  login: "/login",
  dashboard: "/",
  scans: "/scans",
  scanHistory: "/scan-history",
  scanDetail: "/scans/:id",
  assets: "/assets",
  networkDiscovery: "/network-discovery",
  assetDetail: "/assets/:id",
  vulnerabilities: "/vulnerabilities",
  findings: "/findings",
  remediation: "/remediation",
  baseline: "/baseline",
  changes: "/changes",
  reports: "/reports",
  settings: "/settings",
} as const;
