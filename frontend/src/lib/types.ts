// Mirrors backend/app/schemas/*.py exactly — kept hand-in-sync rather than
// codegenerated (e.g. via openapi-typescript) for this project's size.
// A larger version of this app would generate these from FastAPI's own
// OpenAPI schema instead of maintaining two hand-written sources of truth.

export type DetectionType = "sigma" | "correlation" | "yara" | "ml";
export type AlertSeverity = "informational" | "low" | "medium" | "high" | "critical";
export type AlertStatus = "new" | "acknowledged" | "closed";
export type UserRole = "admin" | "analyst";

export interface AlertOut {
  id: string;
  rule_id: string;
  rule_title: string;
  detection_type: DetectionType;
  severity: AlertSeverity;
  mitre_techniques: string[];
  source_event_id: string;
  summary: string;
  details: Record<string, unknown>;
  status: AlertStatus;
  created_at: string;
}

export interface UserOut {
  id: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface Token {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface DetectionRunResult {
  sigma_alerts_created: number;
  correlation_alerts_created: number;
  total_alerts_created: number;
}

export interface ModelMetrics {
  model: string;
  precision: number;
  recall: number;
  f1_score: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
}

export interface TrainResult {
  isolation_forest: ModelMetrics;
  random_forest: ModelMetrics;
  train_samples: number;
  test_samples: number;
  contamination_estimate: number;
}

export interface MLScoreResult {
  ips_scanned: number;
  alerts_created: number;
}

export interface IOCLookupResult {
  indicator: string;
  enrichable: boolean;
  combined_threat_score: number | null;
  abuseipdb_score: number | null;
  abuseipdb_total_reports: number | null;
  otx_pulse_count: number | null;
  otx_malware_families: string[];
}

export type CaseStatus = "open" | "investigating" | "closed";

export interface CaseOut {
  id: string;
  title: string;
  summary: string;
  status: CaseStatus;
  severity: AlertSeverity;
  tags: string[];
  alert_ids: string[];
  assigned_to_id: string | null;
  created_by_id: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

export interface CaseCommentOut {
  id: string;
  case_id: string;
  user_id: string;
  body: string;
  created_at: string;
}

export type PlaybookName = "auto_tag" | "simulated_ip_block" | "auto_case_notify";
export type PlaybookRunStatus = "success" | "skipped" | "failed";

export interface PlaybookRunOut {
  id: string;
  playbook_name: PlaybookName;
  alert_id: string;
  status: PlaybookRunStatus;
  result: Record<string, unknown>;
  created_at: string;
}

export interface SoarRunResult {
  alerts_processed: number;
  total_playbook_runs: number;
}

export interface BlockedIPOut {
  id: string;
  ip_address: string;
  reason: string;
  alert_id: string;
  blocked_at: string;
}
