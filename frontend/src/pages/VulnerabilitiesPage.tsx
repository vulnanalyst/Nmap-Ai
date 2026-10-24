import React, { useEffect, useState, useCallback } from 'react';
import {
  ShieldAlert,
  Search,
  ExternalLink,
  Eye,
  FileSpreadsheet,
} from 'lucide-react';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { Card } from '../components/common/Card';
import {
  SeverityBadge,
  ValidationBadge,
  WorkflowBadge,
  DataSourceBadge,
} from '../components/common/Badge';
import { Drawer } from '../components/common/Drawer';
import { LoadingSkeleton } from '../components/common/LoadingState';
import { EmptyState, ErrorBanner } from '../components/common/EmptyState';
import type { FindingItem, WorkflowStatus } from '../types';

export const VulnerabilitiesPage: React.FC = () => {
  const { showToast } = useApp();
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<FindingItem | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedValidation, setSelectedValidation] = useState<string>('');
  const [selectedCve, setSelectedCve] = useState<string>('');

  const fetchFindings = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getFindings({
        severity: selectedSeverity || undefined,
        validation_status: selectedValidation || undefined,
        q: searchQuery.trim() || undefined,
        cve: selectedCve.trim() || undefined,
      });
      setFindings(res.items);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch vulnerabilities');
    } finally {
      setLoading(false);
    }
  }, [selectedSeverity, selectedValidation, searchQuery, selectedCve]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  // Status patch
  const handleUpdateStatus = async (findingId: string, newStatus: WorkflowStatus) => {
    try {
      const updated = await api.updateFindingStatus(findingId, newStatus);
      setFindings((prev) => prev.map((f) => (f.id === findingId ? updated : f)));
      if (selectedFinding?.id === findingId) setSelectedFinding(updated);
      showToast(`Workflow updated to: ${newStatus}`, 'success');
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Failed to update finding status', 'error');
    }
  };

  // Export JSON
  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(findings, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnerability-intelligence-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Exported findings to JSON', 'info');
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-100">Vulnerability Findings</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Correlated vulnerability findings with explicit validation boundaries, CVE mappings, and evidence provenance.
          </p>
        </div>

        <button
          onClick={handleExportJson}
          className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-md border border-slate-700 flex items-center gap-2 transition-colors self-start"
        >
          <FileSpreadsheet className="w-3.5 h-3.5 text-cyan-400" />
          <span>Export JSON</span>
        </button>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchFindings} />}

      {/* Filter & Search Bar */}
      <Card className="py-3 px-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          {/* Search text */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search title, IP..."
              className="w-full bg-slate-900 border border-slate-700 rounded pl-8 pr-3 py-1.5 text-slate-200 text-xs focus:outline-hidden focus:border-cyan-500"
            />
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-300 text-xs"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          {/* Validation Status Filter */}
          <div>
            <select
              value={selectedValidation}
              onChange={(e) => setSelectedValidation(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-300 text-xs"
            >
              <option value="">All Validation States</option>
              <option value="validated_vulnerability">Validated Vulnerability</option>
              <option value="confirmed_by_check">Confirmed by Check</option>
              <option value="suspected">Suspected</option>
              <option value="potential_issue">Potential Issue</option>
              <option value="no_verified_cve_match">No Verified CVE Match</option>
            </select>
          </div>

          {/* CVE Search */}
          <div>
            <input
              type="text"
              value={selectedCve}
              onChange={(e) => setSelectedCve(e.target.value)}
              placeholder="Filter by CVE (e.g. CVE-2021-40438)"
              className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 text-xs font-mono uppercase focus:outline-hidden focus:border-cyan-500"
            />
          </div>
        </div>
      </Card>

      {/* Findings Data Table */}
      <Card
        title={`Vulnerability Findings (${findings.length})`}
        subtitle="Ranked security observations with supporting check evidence"
        icon={<ShieldAlert className="w-4 h-4" />}
      >
        {loading ? (
          <LoadingSkeleton rows={6} />
        ) : findings.length === 0 ? (
          <EmptyState
            icon={<ShieldAlert className="w-8 h-8 text-cyan-400" />}
            title="No Matching Findings"
            description="No vulnerability findings match the active filters, or no scans have been performed yet."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">CVE / Finding</th>
                  <th className="py-3 px-4">Target Host:Port</th>
                  <th className="py-3 px-4">Product / Version</th>
                  <th className="py-3 px-4">Validation Status</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Workflow</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {findings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-4">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="py-3 px-4 max-w-xs">
                      <div className="font-semibold text-slate-200 truncate">{f.title}</div>
                      {f.cve ? (
                        <span className="font-mono text-[10px] text-cyan-400 font-semibold block mt-0.5">
                          {f.cve} {f.cvss ? `(CVSS ${f.cvss.toFixed(1)})` : ''}
                        </span>
                      ) : (
                        <span className="text-[10px] text-slate-500 italic block mt-0.5">No direct CVE</span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan-300">
                      {f.host_ip}
                      {f.port ? `:${f.port}` : ''}
                    </td>
                    <td className="py-3 px-4 text-slate-300 max-w-xs truncate">
                      {f.product ? (
                        <span>
                          {f.product} {f.version || ''}
                        </span>
                      ) : (
                        <span className="text-slate-600 italic">None detected</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <ValidationBadge status={f.validation_status} />
                    </td>
                    <td className="py-3 px-4 font-mono font-bold text-slate-200">
                      {f.risk_score != null ? f.risk_score.toFixed(1) : '—'}
                    </td>
                    <td className="py-3 px-4">
                      <WorkflowBadge status={f.workflow_status} />
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedFinding(f)}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-cyan-950/60 hover:text-cyan-300 text-slate-300 rounded border border-slate-700 text-xs font-medium inline-flex items-center gap-1.5 transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Finding Detail Inspection Drawer */}
      <Drawer
        isOpen={Boolean(selectedFinding)}
        onClose={() => setSelectedFinding(null)}
        title={selectedFinding ? selectedFinding.title : 'Finding Inspection'}
        subtitle={selectedFinding ? `${selectedFinding.host_ip}${selectedFinding.port ? `:${selectedFinding.port}` : ''}` : undefined}
        width="max-w-2xl"
      >
        {selectedFinding && (
          <div className="space-y-5 text-xs">
            {/* Header Badges */}
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={selectedFinding.severity} />
              <ValidationBadge status={selectedFinding.validation_status} />
              <WorkflowBadge status={selectedFinding.workflow_status} />
              <DataSourceBadge source={selectedFinding.data_source} />
            </div>

            {/* Workflow Status Selector */}
            <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-slate-400 font-medium block">Triage Status</span>
                <span className="text-[11px] text-slate-500">Update analyst tracking state</span>
              </div>
              <select
                value={selectedFinding.workflow_status}
                onChange={(e) => handleUpdateStatus(selectedFinding.id, e.target.value as WorkflowStatus)}
                className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-slate-200 text-xs font-medium"
              >
                <option value="new">New</option>
                <option value="investigating">Investigating</option>
                <option value="confirmed">Confirmed</option>
                <option value="false_positive">False Positive</option>
                <option value="accepted_risk">Accepted Risk</option>
                <option value="resolved">Resolved</option>
              </select>
            </div>

            {/* Impact & Remediation */}
            {selectedFinding.impact && (
              <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
                <span className="text-slate-400 font-semibold block mb-1">Potential Impact</span>
                <p className="text-slate-300 leading-relaxed">{selectedFinding.impact}</p>
              </div>
            )}

            {selectedFinding.remediation && (
              <div className="p-3 bg-emerald-950/30 rounded-lg border border-emerald-900/60">
                <span className="text-emerald-400 font-semibold block mb-1">Remediation Guidance</span>
                <p className="text-emerald-200/90 leading-relaxed">{selectedFinding.remediation}</p>
              </div>
            )}

            {/* Evidence Card */}
            <div>
              <span className="text-slate-400 font-semibold block mb-1.5 uppercase tracking-wider text-[11px]">
                Supporting Evidence & Provenance
              </span>
              <pre className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto max-h-60 leading-normal">
                {JSON.stringify(selectedFinding.evidence, null, 2)}
              </pre>
            </div>

            {/* Risk Breakdown */}
            {selectedFinding.risk_breakdown && (
              <div className="p-3.5 bg-slate-900 rounded-lg border border-slate-800">
                <span className="text-slate-400 font-semibold block mb-2 uppercase tracking-wider text-[11px]">
                  Risk Score Breakdown (Composite: {selectedFinding.risk_score?.toFixed(1) || 'N/A'})
                </span>
                <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                  <div>CVSS Component: <span className="text-slate-200 font-semibold">{selectedFinding.risk_breakdown.cvss_component?.toFixed(2) || '0'}</span></div>
                  <div>Exposure Factor: <span className="text-slate-200 font-semibold">{selectedFinding.risk_breakdown.exposure_component?.toFixed(2) || '0'}</span></div>
                  <div>Confidence Signal: <span className="text-slate-200 font-semibold">{selectedFinding.risk_breakdown.confidence_component?.toFixed(2) || '0'}</span></div>
                  <div>ML Anomaly Signal: <span className="text-slate-200 font-semibold">{selectedFinding.risk_breakdown.ml_anomaly_signal?.toFixed(2) || '0'}</span></div>
                </div>
              </div>
            )}

            {/* Reference URL */}
            {selectedFinding.reference_url && (
              <div className="pt-2 flex items-center justify-between text-xs">
                <span className="text-slate-500">Official Advisory:</span>
                <a
                  href={selectedFinding.reference_url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 font-mono"
                >
                  <span>{selectedFinding.reference_url.slice(0, 45)}...</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
};
