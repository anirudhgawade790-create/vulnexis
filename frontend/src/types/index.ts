// TypeScript interfaces mirroring backend Pydantic schemas (app/schemas/*).
// Datetime/date fields arrive as ISO strings over JSON, so they are typed `string`.

export type ISODate = string;

export type UserRole = "admin" | "analyst" | "viewer";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingType =
  | "confirmed_vulnerability"
  | "potential_vulnerability"
  | "misconfiguration"
  | "network_exposure"
  | "informational";

export type FindingStatus =
  | "open"
  | "acknowledged"
  | "remediated"
  | "false_positive"
  | "wont_fix";

export type Confidence = "confirmed" | "high" | "medium" | "low";

export type ScanType = "network" | "windows" | "full";

export type ScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export type AssetType = "server" | "workstation" | "network_device" | "unknown";

export type BusinessCriticality = "critical" | "high" | "medium" | "low";

export type ScopeType = "ip" | "cidr" | "hostname" | "range";

export type BaselineFramework = "cis_windows" | "nist_csf" | "custom";

export type Effort = "low" | "medium" | "high" | "critical";

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  full_name: string | null;
  created_at: ISODate;
  updated_at: ISODate;
  last_login: ISODate | null;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: User;
}

export interface UserCreate {
  username: string;
  email: string;
  password: string;
  role: UserRole;
  full_name?: string;
}

export interface UserUpdate {
  email?: string;
  full_name?: string;
  role?: UserRole;
  is_active?: boolean;
}

export interface Target {
  id: string;
  name: string;
  description: string | null;
  scope_type: ScopeType;
  scope_value: string;
  is_active: boolean;
  business_criticality: BusinessCriticality;
  created_by: string | null;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface TargetCreate {
  name: string;
  description?: string;
  scope_type: ScopeType;
  scope_value: string;
  business_criticality: BusinessCriticality;
  is_active: boolean;
}

export interface TargetUpdate {
  name?: string;
  description?: string;
  scope_value?: string;
  business_criticality?: BusinessCriticality;
  is_active?: boolean;
}

export interface ScanJob {
  id: string;
  target_id: string;
  scan_type: ScanType;
  status: ScanStatus;
  progress: number;
  started_by: string;
  celery_task_id: string | null;
  options: Record<string, unknown> | null;
  error_message: string | null;
  started_at: ISODate | null;
  completed_at: ISODate | null;
  created_at: ISODate;
}

export interface ScanJobCreate {
  target_id: string;
  scan_type: ScanType;
  options?: Record<string, unknown>;
}

export interface ScanProgressEvent {
  scan_job_id: string;
  progress: number;
  phase: string;
  current_host: string | null;
  message: string;
  timestamp: ISODate;
}

export interface ScanResultsSummary {
  scan_job_id: string;
  assets_found: number;
  windows_assets: number;
  total_open_ports: number;
  findings_by_severity: Record<string, number>;
  findings_by_type: Record<string, number>;
  scan_duration_seconds: number | null;
  errors: string[];
}

export interface Port {
  port: number;
  protocol: string;
  service: string;
  version?: string;
}

export interface WindowsDetails {
  patch_count?: number;
  defender_status?: string;
  smb_version?: string;
  rdp_enabled?: boolean;
  is_supported_os?: boolean;
  firewall_enabled?: boolean;
  [key: string]: unknown;
}

export interface Asset {
  id: string;
  scan_job_id: string;
  target_id: string;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  os_name: string | null;
  os_version: string | null;
  os_build: string | null;
  os_arch: string | null;
  is_windows: boolean;
  is_supported_os: boolean | null;
  asset_type: AssetType;
  business_criticality: BusinessCriticality;
  open_ports: Port[] | null;
  windows_details: WindowsDetails | null;
  risk_score: number | null;
  last_seen_at: ISODate;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface AssetUpdate {
  business_criticality?: BusinessCriticality;
  asset_type?: AssetType;
}

export interface RemediationStep {
  step: string;
  command: string;
}

export interface Finding {
  id: string;
  scan_job_id: string;
  asset_id: string;
  vulnerability_id: string | null;
  title: string;
  finding_type: FindingType;
  severity: Severity;
  status: FindingStatus;
  check_name: string;
  evidence: string;
  detection_method: string;
  confidence: Confidence;
  risk_score: number;
  risk_explanation: string | null;
  business_impact: string | null;
  recommended_action: string | null;
  remediation_steps: RemediationStep[] | null;
  resolution_notes: string | null;
  first_seen_at: ISODate;
  last_seen_at: ISODate;
  resolved_at: ISODate | null;
  assigned_to: string | null;
}

export interface FindingStatusUpdate {
  status: FindingStatus;
  resolution_notes?: string;
}

export interface Vulnerability {
  id: string;
  cve_id: string | null;
  title: string;
  description: string;
  cvss_v3_score: number | null;
  cvss_v3_vector: string | null;
  cvss_v2_score: number | null;
  severity: Severity;
  cwe_id: string | null;
  affected_products: Record<string, unknown>[] | null;
  references: Record<string, unknown>[] | null;
  is_kev: boolean;
  kev_date_added: ISODate | null;
  kev_due_date: ISODate | null;
  patch_available: boolean;
  patch_urls: string[] | null;
  published_at: ISODate | null;
  last_modified: ISODate | null;
  source: string;
  fetched_at: ISODate;
}

export interface VulnSyncResponse {
  synced_count: number;
  kev_count: number;
  message: string;
}

export interface RemediationDetail {
  finding_id: string;
  title: string;
  plain_explanation: string;
  technical_explanation: string;
  potential_impact: string;
  recommended_fix: string;
  required_permissions: string;
  estimated_effort: Effort;
  verification_steps: string[];
  documentation_links: string[];
  rollback_considerations: string;
  powershell_examples: string[];
}

export interface BaselineControl {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  check_command: string;
  expected_result: string;
  result: "pass" | "fail" | "unknown";
  evidence?: string;
  last_checked?: ISODate;
}

export interface BaselinePolicy {
  id: string;
  name: string;
  description: string | null;
  framework: BaselineFramework;
  version: string;
  controls: BaselineControl[];
  is_active: boolean;
  created_by: string | null;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface BaselinePolicyCreate {
  name: string;
  description?: string;
  framework: BaselineFramework;
  version: string;
  controls: Record<string, unknown>[];
  is_active: boolean;
}

export interface BaselinePolicyUpdate {
  name?: string;
  description?: string;
  version?: string;
  controls?: Record<string, unknown>[];
  is_active?: boolean;
}

export interface ControlResult {
  control_id: string;
  title: string;
  result: "pass" | "fail" | "unknown";
  evidence: string | null;
  last_checked: ISODate;
}

export interface BaselineResultSummary {
  policy_id: string;
  policy_name: string;
  scan_job_id: string;
  total_controls: number;
  passed: number;
  failed: number;
  unknown: number;
  compliance_percentage: number;
  results: ControlResult[];
  assessed_at: ISODate;
}

export interface DashboardSummary {
  total_assets: number;
  windows_assets: number;
  total_vulnerabilities: number;
  findings_by_severity: Record<string, number>;
  overall_posture_score: number;
  unpatched_systems: number;
  critical_assets_at_risk: number;
  open_findings: number;
  remediated_findings: number;
  last_scan_at: ISODate | null;
}

export interface TrendDataPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface TrendData {
  period_days: number;
  data_points: TrendDataPoint[];
  posture_trend: Record<string, unknown>[];
}

export interface InsightItem {
  id: string;
  title: string;
  detail: string;
  severity: Severity;
  category: string;
  evidence_tags: string[];
  created_at: ISODate;
}

export interface ExposureNode {
  id: string;
  ip_address: string;
  hostname: string | null;
  risk_score: number;
  asset_type: AssetType;
  open_port_count: number;
  severity: Severity;
}

export interface ExposureMapData {
  nodes: ExposureNode[];
  total_exposed_ports: number;
  high_risk_count: number;
  generated_at: ISODate;
}

export interface TopRiskItem {
  id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  asset_id: string;
  finding_type: FindingType;
}

export interface ChangeFindingItem {
  id: string;
  title: string;
  check_name: string;
  asset_id: string;
  severity: Severity;
  status: FindingStatus;
  risk_score: number;
}

export interface ChangeAssetItem {
  id: string;
  ip_address: string;
  hostname: string | null;
  os_name: string | null;
  disappeared_inaccessible?: boolean;
}

export interface ChangeDetectionReport {
  scan_job_id: string;
  previous_scan_job_id: string;
  new_findings: ChangeFindingItem[];
  resolved_findings: ChangeFindingItem[];
  new_assets: ChangeAssetItem[];
  removed_assets: ChangeAssetItem[];
  new_open_ports: { ip: string; port: number }[];
  closed_ports: { ip: string; port: number }[];
  risk_delta: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
}

export interface ListParams {
  page?: number;
  size?: number;
  [key: string]: unknown;
}
