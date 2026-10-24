export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ValidationStatus =
  | 'observed'
  | 'detected'
  | 'suspected'
  | 'confirmed_by_check'
  | 'validated_vulnerability'
  | 'potential_issue'
  | 'no_verified_cve_match';

export type WorkflowStatus =
  | 'new'
  | 'investigating'
  | 'confirmed'
  | 'false_positive'
  | 'accepted_risk'
  | 'resolved';

export interface ServiceScript {
  id: string;
  output?: string;
  elements?: Record<string, unknown>;
}

export interface ServiceItem {
  id: number;
  protocol: string;
  port: number;
  state: string;
  name?: string | null;
  product?: string | null;
  version?: string | null;
  detection_source?: string;
  scripts?: ServiceScript[];
}

export interface HostItem {
  id: number;
  ip: string;
  hostname?: string | null;
  mac?: string | null;
  state: string;
  os_guess?: string | null;
  os_accuracy?: number | null;
  os_label?: string | null;
  last_seen?: string | null;
  scan_id?: string | null;
  data_source: string;
  services: ServiceItem[];
  findings?: Array<{ id: string; title: string; validation_status: string }>;
}

export interface ScanJobItem {
  id: string;
  profile: string;
  targets: string;
  status: 'queued' | 'running' | 'completed' | 'error' | 'timeout' | 'cancelled' | 'dry_run' | 'preview';
  argv: string[];
  dry_run: boolean;
  progress_pct: number;
  error?: string | null;
  created_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  duration_seconds?: number | null;
  xml_path?: string | null;
  json_path?: string | null;
  data_source: string;
  ports_open: number;
  ports_closed: number;
  ports_filtered: number;
  hosts_up: number;
  hosts_down: number;
  nmap_version?: string | null;
}

export interface ScanProfileItem {
  id: string;
  label: string;
  flags: string[];
}

export interface FindingItem {
  id: string;
  host_ip: string;
  port?: number | null;
  protocol?: string | null;
  service_name?: string | null;
  product?: string | null;
  version?: string | null;
  title: string;
  cve?: string | null;
  cvss?: number | null;
  severity: Severity;
  evidence: Record<string, unknown>;
  detection_source: string;
  confidence?: number | null;
  validation_status: ValidationStatus;
  impact?: string | null;
  remediation?: string | null;
  reference_url?: string | null;
  first_observed?: string | null;
  last_observed?: string | null;
  workflow_status: WorkflowStatus;
  risk_score?: number | null;
  risk_breakdown?: {
    cvss_component?: number;
    exposure_component?: number;
    confidence_component?: number;
    ml_anomaly_signal?: number;
    freshness_factor?: number;
  };
  data_source: string;
}

export interface AlertNoteItem {
  id: number;
  author: string;
  body: string;
  created_at?: string | null;
}

export interface AlertItem {
  id: number;
  timestamp?: string | null;
  src_addr?: string | null;
  dst_addr?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string | null;
  detection_method: string;
  rule_or_model?: string | null;
  evidence_ref?: string | null;
  severity: Severity;
  confidence?: number | null;
  title: string;
  message: string;
  status: 'open' | 'acknowledged' | 'investigating' | 'resolved';
  data_source: string;
  extra?: Record<string, unknown>;
  notes: AlertNoteItem[];
}

export interface TrafficEventItem {
  id: number;
  timestamp?: string | null;
  adapter?: string;
  src_addr?: string | null;
  dst_addr?: string | null;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: string | null;
  packet_length?: number | null;
  feature_complete: boolean;
  ml_status: string;
  ml_label?: string | null;
  ml_confidence?: number | null;
  model_version?: string | null;
  signatures?: string[];
  features?: Record<string, unknown>;
  parse_error?: string | null;
  data_source: string;
}

export interface IngestionStatusItem {
  adapter: string;
  state: 'running' | 'idle' | 'stopped' | 'error';
  interface?: string | null;
  packets_processed: number;
  flows_processed: number;
  dropped_events: number;
  parse_errors: number;
  last_event_at?: string | null;
  last_error?: string | null;
  permission_ok: boolean;
  guidance: string;
}

export interface ClassMetrics {
  precision: number;
  recall: number;
  'f1-score': number;
  support: number;
}

export interface AlgorithmEvaluation {
  name: string;
  precision_macro: number;
  recall_macro: number;
  f1_macro: number;
  balanced_accuracy: number;
  confusion_matrix: number[][];
  labels: number[];
  classification_report: Record<string, ClassMetrics>;
}

export interface ReportItem {
  id: string;
  title: string;
  created_at: string;
  scope: Record<string, unknown>;
}

export interface AuthorizedTargetItem {
  id: number;
  cidr: string;
  label?: string;
}

export interface SettingsData {
  scanner_name?: string | null;
  scanner_ip?: string | null;
  target_name?: string | null;
  target_ip?: string | null;
  authorized_targets: AuthorizedTargetItem[];
  authorized_cidrs: string[];
  ingest_host: string;
  ingest_port: number;
  nmap: {
    installed: boolean;
    path: string;
    version?: string | null;
    guidance?: string;
  };
  model?: {
    version?: string | null;
    trained_at?: string | null;
    path?: string | null;
  };
  placeholders: {
    scanner: string;
    target: string;
  };
}

export interface DashboardSummary {
  hosts_total: number;
  hosts_up: number;
  ports_open: number;
  ports_closed: number;
  ports_filtered: number;
  services_observed: number;
  findings_by_severity: Record<string, number>;
  findings_by_validation: Record<string, number>;
  latest_scan?: {
    id: string;
    status: string;
    profile: string;
    created_at?: string | null;
    duration_seconds?: number | null;
    error?: string | null;
    data_source: string;
  } | null;
  model?: {
    version?: string | null;
    trained_at?: string | null;
    metrics?: AlgorithmEvaluation | null;
    disclaimer: string;
  } | null;
  traffic_ml_labels: Record<string, number>;
  recent_alerts: Array<{
    id: number;
    title: string;
    severity: Severity;
    timestamp?: string | null;
    detection_method: string;
    data_source: string;
  }>;
  scan_trend: Array<{
    id: string;
    created_at?: string | null;
    ports_open: number;
    status: string;
  }>;
  data_source_filter: string;
}

export interface TopologyNode {
  id: string;
  label: string;
  role: 'scanner' | 'observed_host';
  ip?: string | null;
  state?: string;
  os_guess?: string | null;
  provenance: string;
  data_source?: string;
}

export interface TopologyEdge {
  from: string;
  to: string;
  provenance: string;
  scan_id?: string | null;
}

export interface TopologyData {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  note: string;
}
