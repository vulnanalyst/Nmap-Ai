import type {
  AlertItem,
  DashboardSummary,
  FindingItem,
  HostItem,
  IngestionStatusItem,
  MLModelResponse,
  ReportItem,
  ScanJobItem,
  ScanProfileItem,
  SettingsData,
  TopologyData,
  TrafficEventItem,
  TrainingRunItem,
  WorkflowStatus,
} from '../types';

const BASE_URL = '/api/v1';

// Token management
const TOKEN_KEY = 'nmap_ai_auth_token';

export function getAuthToken(): string {
  return localStorage.getItem(TOKEN_KEY) || 'test-token';
}

export function setAuthToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function removeAuthToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

// Unified fetch wrapper
async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getAuthToken();
  const headers: Record<string, string> = {
    'X-API-Key': token,
    ...(options.headers as Record<string, string>),
  };

  // Only set Content-Type to JSON if not FormData
  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errorJson = await response.json();
      errorDetail = errorJson.detail || errorJson.error?.message || errorDetail;
    } catch {
      // fallback to statusText
    }
    throw new Error(errorDetail || `HTTP Error ${response.status}`);
  }

  return response.json();
}

// ----------------------------------------
// API Endpoints
// ----------------------------------------

export const api = {
  // Auth
  async login(password: string): Promise<{ token: string }> {
    const res = await request<{ token: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username: 'lab', password }),
    });
    setAuthToken(res.token);
    return res;
  },

  async checkHealth(): Promise<{ status: string }> {
    return request<{ status: string }>('/health');
  },

  // Dashboard
  async getDashboardSummary(includeDemo = false): Promise<DashboardSummary> {
    return request<DashboardSummary>(`/dashboard/summary?include_demo=${includeDemo}`);
  },

  // Hosts & Topology
  async getHosts(includeDemo = false): Promise<{ items: HostItem[]; count: number }> {
    return request<{ items: HostItem[]; count: number }>(`/hosts?include_demo=${includeDemo}`);
  },

  async getHost(hostId: number): Promise<HostItem> {
    return request<HostItem>(`/hosts/${hostId}`);
  },

  async getTopology(includeDemo = false): Promise<TopologyData> {
    return request<TopologyData>(`/topology?include_demo=${includeDemo}`);
  },

  async compareScans(leftScanId: string, rightScanId: string): Promise<Record<string, unknown>> {
    return request<Record<string, unknown>>(`/scans/compare?left=${leftScanId}&right=${rightScanId}`);
  },

  // Scans
  async getScanProfiles(): Promise<{
    profiles: ScanProfileItem[];
    nmap: { installed: boolean; path: string; version?: string | null; guidance?: string };
  }> {
    return request<{
      profiles: ScanProfileItem[];
      nmap: { installed: boolean; path: string; version?: string | null; guidance?: string };
    }>('/scans/profiles');
  },

  async previewScan(profile: string, target: string): Promise<{ argv: string[]; profile: string; target: string }> {
    return request<{ argv: string[]; profile: string; target: string }>('/scans/preview', {
      method: 'POST',
      body: JSON.stringify({
        profile,
        target,
        confirm_target: target,
        confirm_authorization: true,
        dry_run: true,
      }),
    });
  },

  async createScan(params: {
    profile: string;
    target: string;
    confirmTarget: string;
    confirmAuthorization: boolean;
    dryRun?: boolean;
  }): Promise<ScanJobItem> {
    return request<ScanJobItem>('/scans', {
      method: 'POST',
      body: JSON.stringify({
        profile: params.profile,
        target: params.target,
        confirm_target: params.confirmTarget,
        confirm_authorization: params.confirmAuthorization,
        dry_run: params.dryRun || false,
      }),
    });
  },

  async getScans(): Promise<{ items: ScanJobItem[] }> {
    return request<{ items: ScanJobItem[] }>('/scans');
  },

  async getScan(scanId: string): Promise<ScanJobItem> {
    return request<ScanJobItem>(`/scans/${scanId}`);
  },

  async cancelScan(scanId: string): Promise<ScanJobItem> {
    return request<ScanJobItem>(`/scans/${scanId}/cancel`, { method: 'POST' });
  },

  async importXml(file: File): Promise<{
    scan_id: string;
    hosts_up: number;
    ports_open: number;
    findings_created: number;
  }> {
    const formData = new FormData();
    formData.append('file', file, file.name);
    return request<{
      scan_id: string;
      hosts_up: number;
      ports_open: number;
      findings_created: number;
    }>('/scans/import', {
      method: 'POST',
      body: formData,
    });
  },

  // Vulnerability Findings
  async getFindings(params?: {
    severity?: string;
    validation_status?: string;
    q?: string;
    cve?: string;
    include_demo?: boolean;
  }): Promise<{ items: FindingItem[]; count: number }> {
    const query = new URLSearchParams();
    if (params?.severity) query.set('severity', params.severity);
    if (params?.validation_status) query.set('validation_status', params.validation_status);
    if (params?.q) query.set('q', params.q);
    if (params?.cve) query.set('cve', params.cve);
    if (params?.include_demo) query.set('include_demo', 'true');
    const qs = query.toString();
    return request<{ items: FindingItem[]; count: number }>(`/findings${qs ? `?${qs}` : ''}`);
  },

  async getFinding(findingId: string): Promise<FindingItem> {
    return request<FindingItem>(`/findings/${findingId}`);
  },

  async updateFindingStatus(findingId: string, status: WorkflowStatus): Promise<FindingItem> {
    return request<FindingItem>(`/findings/${findingId}`, {
      method: 'PATCH',
      body: JSON.stringify({ workflow_status: status }),
    });
  },

  // Alerts
  async getAlerts(params?: {
    status?: string;
    method?: string;
    include_demo?: boolean;
  }): Promise<{ items: AlertItem[]; count: number }> {
    const query = new URLSearchParams();
    if (params?.status) query.set('status', params.status);
    if (params?.method) query.set('method', params.method);
    if (params?.include_demo) query.set('include_demo', 'true');
    const qs = query.toString();
    return request<{ items: AlertItem[]; count: number }>(`/alerts${qs ? `?${qs}` : ''}`);
  },

  async updateAlert(alertId: number, update: { status?: string; note?: string }): Promise<AlertItem> {
    return request<AlertItem>(`/alerts/${alertId}`, {
      method: 'PATCH',
      body: JSON.stringify(update),
    });
  },

  // Traffic & Ingestion
  async getTrafficStatus(): Promise<IngestionStatusItem> {
    return request<IngestionStatusItem>('/traffic/status');
  },

  async getTrafficEvents(includeDemo = false): Promise<{ items: TrafficEventItem[] }> {
    return request<{ items: TrafficEventItem[] }>(`/traffic/events?include_demo=${includeDemo}`);
  },

  async ingestPacket(packet: {
    src_addr: string;
    dst_addr: string;
    src_port?: number;
    dst_port?: number;
    protocol?: string;
    packet_length?: number;
  }): Promise<{ id: number; ml_status: string; feature_complete: boolean }> {
    return request<{ id: number; ml_status: string; feature_complete: boolean }>('/traffic/ingest', {
      method: 'POST',
      body: JSON.stringify(packet),
    });
  },

  // ML Lab
  async getModelInfo(): Promise<MLModelResponse> {
    return request<MLModelResponse>('/ml/model');
  },

  async inferFeatures(features: Record<string, number> | number[]): Promise<{
    prediction: number;
    label: string;
    probability: number;
    model_version: string;
    class_probabilities: Record<string, number>;
  }> {
    return request<{
      prediction: number;
      label: string;
      probability: number;
      model_version: string;
      class_probabilities: Record<string, number>;
    }>('/ml/infer', {
      method: 'POST',
      body: JSON.stringify({ features }),
    });
  },

  async getTrainingRuns(): Promise<{ items: TrainingRunItem[] }> {
    return request<{ items: TrainingRunItem[] }>('/ml/training');
  },

  async startTraining(): Promise<{ id: string; status: string }> {
    return request<{ id: string; status: string }>('/ml/training', {
      method: 'POST',
    });
  },

  // Reports
  async getReports(): Promise<{ items: ReportItem[] }> {
    return request<{ items: ReportItem[] }>('/reports');
  },

  async createReport(): Promise<{ id: string; json_path: string; pdf_path?: string; created_at: string }> {
    return request<{ id: string; json_path: string; pdf_path?: string; created_at: string }>('/reports', {
      method: 'POST',
    });
  },

  getReportJsonUrl(reportId: string): string {
    return `${BASE_URL}/reports/${reportId}/json`;
  },

  getReportPdfUrl(reportId: string): string {
    return `${BASE_URL}/reports/${reportId}/pdf`;
  },

  // Settings & Targets
  async getSettings(): Promise<SettingsData> {
    return request<SettingsData>('/settings');
  },

  async updateSettings(values: Record<string, string>): Promise<SettingsData> {
    return request<SettingsData>('/settings', {
      method: 'PATCH',
      body: JSON.stringify({ values }),
    });
  },

  async addAuthorizedTarget(cidr: string, label?: string): Promise<{ id: number; cidr: string; label: string }> {
    return request<{ id: number; cidr: string; label: string }>('/settings/targets', {
      method: 'POST',
      body: JSON.stringify({ cidr, label: label || '' }),
    });
  },

  async deleteAuthorizedTarget(targetId: number): Promise<{ ok: boolean }> {
    return request<{ ok: boolean }>(`/settings/targets/${targetId}`, {
      method: 'DELETE',
    });
  },

  async seedDemoData(): Promise<{ status: string; message: string }> {
    return request<{ status: string; message: string }>('/settings/demo/seed', {
      method: 'POST',
    });
  },

  async clearDemoData(): Promise<{ status: string; message: string }> {
    return request<{ status: string; message: string }>('/settings/demo/seed', {
      method: 'DELETE',
    });
  },
};
