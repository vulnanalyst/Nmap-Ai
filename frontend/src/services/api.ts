import type {
  AlertItem,
  DashboardSummary,
  DatasetTargetItem,
  FindingItem,
  HostItem,
  IngestionStatusItem,
  ReportItem,
  ScanJobItem,
  ScanProfileItem,
  SettingsData,
  TopologyData,
  TrafficEventItem,
  WorkflowStatus,
} from '../types';

const BASE_URL = '/api/v1';

// Token management
const TOKEN_KEY = 'nmap_ai_auth_token';

export function getAuthToken(): string {
  return localStorage.getItem(TOKEN_KEY) || '';
}

export function setAuthToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function removeAuthToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// Unified fetch wrapper
async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getAuthToken();
  const headers: Record<string, string> = {
    ...(token ? { 'X-API-Key': token } : {}),
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
    throw new ApiError(errorDetail || `HTTP Error ${response.status}`, response.status);
  }

  return response.json();
}

// ----------------------------------------
// API Endpoints
// ----------------------------------------

export const api = {
  // Auth
  async login(username: string, password: string): Promise<{ token: string }> {
    const res = await request<{ token: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    setAuthToken(res.token);
    return res;
  },

  async logout(): Promise<void> {
    try {
      await request('/auth/logout', { method: 'POST' });
    } catch {
      // Ignore network/server errors during logout
    } finally {
      removeAuthToken();
    }
  },

  async checkHealth(): Promise<{ status: string }> {
    return request<{ status: string }>('/health');
  },

  // Dashboard
  async getDashboardSummary(): Promise<DashboardSummary> {
    return request<DashboardSummary>('/dashboard/summary');
  },

  // Hosts & Topology
  async getHosts(): Promise<{ items: HostItem[]; count: number }> {
    return request<{ items: HostItem[]; count: number }>('/hosts');
  },

  async getTopology(): Promise<TopologyData> {
    return request<TopologyData>('/topology');
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
    datasetTargetId?: number | null;
  }): Promise<ScanJobItem> {
    return request<ScanJobItem>('/scans', {
      method: 'POST',
      body: JSON.stringify({
        profile: params.profile,
        target: params.target,
        confirm_target: params.confirmTarget,
        confirm_authorization: params.confirmAuthorization,
        dry_run: params.dryRun || false,
        dataset_target_id: params.datasetTargetId ?? null,
      }),
    });
  },

  async getScans(): Promise<{ items: ScanJobItem[] }> {
    return request<{ items: ScanJobItem[] }>('/scans');
  },

  async getScan(scanId: string): Promise<ScanJobItem> {
    return request<ScanJobItem>(`/scans/${scanId}`);
  },

  async getDatasetTargets(): Promise<{ items: DatasetTargetItem[] }> {
    return request<{ items: DatasetTargetItem[] }>('/scans/targets');
  },

  async importTargetDataset(file: File): Promise<{ items: DatasetTargetItem[]; count: number }> {
    const formData = new FormData();
    formData.append('file', file, file.name);
    return request<{ items: DatasetTargetItem[]; count: number }>('/scans/targets/import', {
      method: 'POST',
      body: formData,
    });
  },

  async cancelScan(scanId: string): Promise<ScanJobItem> {
    return request<ScanJobItem>(`/scans/${scanId}/cancel`, { method: 'POST' });
  },

  async importXml(file: File): Promise<ScanJobItem & {
    scan_id: string;
    findings_created: number;
  }> {
    const formData = new FormData();
    formData.append('file', file, file.name);
    return request<ScanJobItem & {
      scan_id: string;
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
  }): Promise<{ items: FindingItem[]; count: number }> {
    const query = new URLSearchParams();
    if (params?.severity) query.set('severity', params.severity);
    if (params?.validation_status) query.set('validation_status', params.validation_status);
    if (params?.q) query.set('q', params.q);
    if (params?.cve) query.set('cve', params.cve);
    const qs = query.toString();
    return request<{ items: FindingItem[]; count: number }>(`/findings${qs ? `?${qs}` : ''}`);
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
  }): Promise<{ items: AlertItem[]; count: number }> {
    const query = new URLSearchParams();
    if (params?.status) query.set('status', params.status);
    if (params?.method) query.set('method', params.method);
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

  async getTrafficEvents(): Promise<{ items: TrafficEventItem[] }> {
    return request<{ items: TrafficEventItem[] }>('/traffic/events');
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

  async downloadReport(reportId: string, format: 'json' | 'pdf'): Promise<void> {
    const response = await fetch(`${BASE_URL}/reports/${reportId}/${format}`, {
      headers: getAuthToken() ? { 'X-API-Key': getAuthToken() } : {},
    });
    if (!response.ok) {
      throw new ApiError(response.statusText || `HTTP Error ${response.status}`, response.status);
    }
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement('a');
    link.href = url;
    link.download = `report-${reportId}.${format}`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
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

};
