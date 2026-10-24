import React, { useEffect, useState, useCallback } from 'react';
import {
  FileText,
  Download,
  Plus,
  FileCode,
} from 'lucide-react';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { Card } from '../components/common/Card';
import { LoadingSkeleton } from '../components/common/LoadingState';
import { EmptyState, ErrorBanner } from '../components/common/EmptyState';
import type { ReportItem } from '../types';

export const ReportsPage: React.FC = () => {
  const { showToast } = useApp();
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [generating, setGenerating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchReports = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getReports();
      setReports(res.items);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch report records');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const handleGenerateReport = async () => {
    try {
      setGenerating(true);
      const rec = await api.createReport();
      showToast(`Security Report compiled [ID: ${rec.id.slice(0, 8)}]`, 'success');
      fetchReports();
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Report generation failed', 'error');
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Evidence Reports & Compliance Export</h1>
          <p className="text-xs text-slate-400 mt-1">
            Audit-ready security intelligence summaries containing discovered hosts, validated vulnerabilities, ML detections, and explicit limitations.
          </p>
        </div>

        <button
          onClick={handleGenerateReport}
          disabled={generating}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-900 text-xs font-semibold rounded-md flex items-center gap-2 transition-colors shadow-lg shadow-cyan-950/50 self-start"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>{generating ? 'Compiling Report...' : 'Generate New Report'}</span>
        </button>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchReports} />}

      {/* Reports List */}
      <Card
        title={`Stored Executive Reports (${reports.length})`}
        subtitle="Immutable audit documents generated from database records"
        icon={<FileText className="w-4 h-4" />}
      >
        {loading && reports.length === 0 ? (
          <LoadingSkeleton rows={5} />
        ) : reports.length === 0 ? (
          <EmptyState
            icon={<FileText className="w-8 h-8 text-cyan-400" />}
            title="No Reports Generated Yet"
            description="Click 'Generate New Report' above to synthesize current database scan results, findings, and alerts into signed PDF and JSON exports."
          />
        ) : (
          <div className="space-y-3">
            {reports.map((report) => (
              <div
                key={report.id}
                className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg hover:border-slate-700 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="flex items-start gap-3.5">
                  <div className="p-2.5 bg-slate-800 rounded-lg text-cyan-400 border border-slate-700 shrink-0">
                    <FileText className="w-5 h-5" />
                  </div>
                  <div className="space-y-1">
                    <div className="font-semibold text-slate-200 text-xs">{report.title}</div>
                    <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono">
                      <span>ID: {report.id.slice(0, 8)}...</span>
                      <span>&bull;</span>
                      <span>Generated: {new Date(report.created_at).toLocaleString()}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center">
                  {/* Download JSON */}
                  <a
                    href={api.getReportJsonUrl(report.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium inline-flex items-center gap-1.5 transition-colors border border-slate-700"
                  >
                    <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Download JSON</span>
                  </a>

                  {/* Download PDF */}
                  <a
                    href={api.getReportPdfUrl(report.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-900 rounded text-xs font-semibold inline-flex items-center gap-1.5 transition-colors shadow-sm"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download PDF</span>
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
};
