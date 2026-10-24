import React, { useEffect, useState, useCallback } from 'react';
import {
  Bell,
  Send,
  MessageSquare,
  ShieldAlert,
  Cpu,
  Layers,
  Activity,
} from 'lucide-react';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { Card } from '../components/common/Card';
import { SeverityBadge, DataSourceBadge } from '../components/common/Badge';
import { Drawer } from '../components/common/Drawer';
import { LoadingSkeleton } from '../components/common/LoadingState';
import { EmptyState, ErrorBanner } from '../components/common/EmptyState';
import type { AlertItem } from '../types';

export const AlertsPage: React.FC = () => {
  const { demoMode, showToast } = useApp();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertItem | null>(null);
  const [selectedStatus, setSelectedStatus] = useState<string>('');
  const [selectedMethod, setSelectedMethod] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // New Note Input
  const [noteInput, setNoteInput] = useState<string>('');
  const [savingNote, setSavingNote] = useState<boolean>(false);

  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getAlerts({
        status: selectedStatus || undefined,
        method: selectedMethod || undefined,
        include_demo: demoMode,
      });
      setAlerts(res.items);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch alerts');
    } finally {
      setLoading(false);
    }
  }, [selectedStatus, selectedMethod, demoMode]);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 6000);
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  // Update status (e.g. acknowledge or resolve)
  const handleUpdateStatus = async (alertId: number, status: 'open' | 'acknowledged' | 'investigating' | 'resolved') => {
    try {
      const updated = await api.updateAlert(alertId, { status });
      setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)));
      if (selectedAlert?.id === alertId) setSelectedAlert(updated);
      showToast(`Alert marked as ${status}`, 'success');
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Failed to update alert', 'error');
    }
  };

  // Add analyst investigation note
  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAlert || !noteInput.trim()) return;
    try {
      setSavingNote(true);
      const updated = await api.updateAlert(selectedAlert.id, { note: noteInput.trim() });
      setAlerts((prev) => prev.map((a) => (a.id === selectedAlert.id ? updated : a)));
      setSelectedAlert(updated);
      setNoteInput('');
      showToast('Investigation note recorded', 'success');
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Failed to save note', 'error');
    } finally {
      setSavingNote(false);
    }
  };

  const getMethodIcon = (method: string) => {
    switch (method.toLowerCase()) {
      case 'ml_classification':
      case 'ml':
        return <Cpu className="w-3.5 h-3.5 text-cyan-400" />;
      case 'signature':
        return <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />;
      case 'rate_anomaly':
        return <Activity className="w-3.5 h-3.5 text-purple-400" />;
      default:
        return <Layers className="w-3.5 h-3.5 text-blue-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-100">Threat Alerts & Detection Timeline</h1>
            <DataSourceBadge source={demoMode ? 'demo' : 'live'} />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time security events originating from signature matching, flow ML classifications, and scanner checks.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] text-cyan-400">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            POLLING (6s INTERVAL)
          </span>
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchAlerts} />}

      {/* Filter Bar */}
      <Card className="py-3 px-4">
        <div className="flex flex-wrap items-center gap-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-medium">Status:</span>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 text-xs"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-slate-400 font-medium">Method:</span>
            <select
              value={selectedMethod}
              onChange={(e) => setSelectedMethod(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 text-xs"
            >
              <option value="">All Methods</option>
              <option value="ml_classification">ML Classification</option>
              <option value="signature">Signature Match</option>
              <option value="rate_anomaly">Rate Anomaly</option>
              <option value="vulnerability">Scanner Vulnerability</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Alert Feed */}
      <Card
        title={`Detection Timeline (${alerts.length})`}
        subtitle="Chronological audit trail of flagged security signals"
        icon={<Bell className="w-4 h-4" />}
      >
        {loading && alerts.length === 0 ? (
          <LoadingSkeleton rows={5} />
        ) : alerts.length === 0 ? (
          <EmptyState
            icon={<Bell className="w-8 h-8 text-cyan-400" />}
            title="No Alerts Detected"
            description="The persistent alert log is currently clear for the chosen filter criteria."
          />
        ) : (
          <div className="space-y-3">
            {alerts.map((alert) => (
              <div
                key={alert.id}
                onClick={() => setSelectedAlert(alert)}
                className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg hover:border-slate-700 cursor-pointer transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="flex items-start gap-3.5">
                  <div className="pt-0.5">{getMethodIcon(alert.detection_method)}</div>
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-semibold text-slate-100">{alert.title}</span>
                      <SeverityBadge severity={alert.severity} />
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                        {alert.detection_method.toUpperCase()}
                      </span>
                      {alert.confidence != null && (
                        <span className="text-[10px] font-mono text-cyan-400">
                          {(alert.confidence * 100).toFixed(1)}% conf
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">{alert.message}</p>
                    <div className="flex items-center gap-4 text-[11px] font-mono text-slate-500 pt-1">
                      {alert.src_addr && (
                        <span>
                          {alert.src_addr}{alert.src_port ? `:${alert.src_port}` : ''} &rarr; {alert.dst_addr}{alert.dst_port ? `:${alert.dst_port}` : ''}
                        </span>
                      )}
                      <span>{alert.protocol || 'IP'}</span>
                      {alert.timestamp && (
                        <span>{new Date(alert.timestamp).toLocaleString()}</span>
                      )}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase border ${
                      alert.status === 'open'
                        ? 'bg-amber-950/60 text-amber-300 border-amber-800'
                        : alert.status === 'resolved'
                        ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}
                  >
                    {alert.status}
                  </span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedAlert(alert);
                    }}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition-colors"
                  >
                    Investigate
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Alert Investigation Drawer */}
      <Drawer
        isOpen={Boolean(selectedAlert)}
        onClose={() => setSelectedAlert(null)}
        title={selectedAlert ? selectedAlert.title : 'Alert Investigation'}
        subtitle={selectedAlert?.rule_or_model ? `Rule/Model: ${selectedAlert.rule_or_model}` : undefined}
        width="max-w-xl"
      >
        {selectedAlert && (
          <div className="space-y-6 text-xs">
            {/* Status & Severity Card */}
            <div className="bg-slate-900 p-4 rounded-lg border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <SeverityBadge severity={selectedAlert.severity} />
                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'acknowledged')}
                    disabled={selectedAlert.status === 'acknowledged'}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-300 rounded text-xs font-medium"
                  >
                    Acknowledge
                  </button>
                  <button
                    onClick={() => handleUpdateStatus(selectedAlert.id, 'resolved')}
                    disabled={selectedAlert.status === 'resolved'}
                    className="px-2.5 py-1 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 disabled:opacity-50 rounded text-xs font-medium"
                  >
                    Resolve
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 font-mono text-[11px] pt-2 border-t border-slate-800">
                <div>
                  <span className="text-slate-500 block">Source IP:Port</span>
                  <span className="text-cyan-300">
                    {selectedAlert.src_addr || 'Unobserved'}{selectedAlert.src_port ? `:${selectedAlert.src_port}` : ''}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block">Destination IP:Port</span>
                  <span className="text-cyan-300">
                    {selectedAlert.dst_addr || 'Unobserved'}{selectedAlert.dst_port ? `:${selectedAlert.dst_port}` : ''}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block">Detection Method</span>
                  <span className="text-slate-200">{selectedAlert.detection_method}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Model/Signature Ref</span>
                  <span className="text-slate-200">{selectedAlert.rule_or_model || 'N/A'}</span>
                </div>
              </div>
            </div>

            {/* Alert Message Details */}
            <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
              <span className="text-slate-400 font-semibold block mb-1">Alert Description</span>
              <p className="text-slate-300 leading-relaxed">{selectedAlert.message}</p>
            </div>

            {/* Extra Event Data / Flow Features */}
            {selectedAlert.extra && Object.keys(selectedAlert.extra).length > 0 && (
              <div>
                <span className="text-slate-400 font-semibold block mb-1 uppercase tracking-wider text-[11px]">
                  Raw Telemetry Metadata
                </span>
                <pre className="p-3 bg-slate-950 rounded border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto max-h-48">
                  {JSON.stringify(selectedAlert.extra, null, 2)}
                </pre>
              </div>
            )}

            {/* Analyst Investigation Notes Thread */}
            <div className="space-y-3">
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                <MessageSquare className="w-3.5 h-3.5 text-cyan-400" />
                <span>Analyst Notes ({selectedAlert.notes?.length || 0})</span>
              </h4>

              <div className="space-y-2 max-h-48 overflow-y-auto">
                {selectedAlert.notes?.map((n) => (
                  <div key={n.id} className="p-2.5 bg-slate-900/80 rounded border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                      <span className="text-cyan-400 font-semibold">{n.author}</span>
                      <span>{n.created_at ? new Date(n.created_at).toLocaleString() : ''}</span>
                    </div>
                    <p className="text-slate-300 text-xs">{n.body}</p>
                  </div>
                ))}
                {(!selectedAlert.notes || selectedAlert.notes.length === 0) && (
                  <div className="text-slate-500 italic p-2 bg-slate-900/40 rounded">
                    No notes recorded yet. Document your triage notes below.
                  </div>
                )}
              </div>

              {/* Add Note Form */}
              <form onSubmit={handleAddNote} className="flex gap-2">
                <input
                  type="text"
                  value={noteInput}
                  onChange={(e) => setNoteInput(e.target.value)}
                  placeholder="Add investigation findings or notes..."
                  className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 text-xs focus:outline-hidden focus:border-cyan-500"
                />
                <button
                  type="submit"
                  disabled={savingNote || !noteInput.trim()}
                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-900 font-semibold text-xs rounded transition-colors flex items-center gap-1"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Post</span>
                </button>
              </form>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
};
