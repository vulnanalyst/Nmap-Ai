import { useCallback, useEffect, useState } from 'react';
import { api } from '../services/api';
import { SeverityBadge } from '../components/common/Badge';
import { Card } from '../components/common/Card';
import { EmptyState, ErrorBanner } from '../components/common/EmptyState';
import { LoadingSkeleton } from '../components/common/LoadingState';
import { useApp } from '../context/AppContext';
import type { AlertItem, IngestionStatusItem, TrafficEventItem } from '../types';

export function TrafficPage() {
  const { showToast } = useApp();
  const [status, setStatus] = useState<IngestionStatusItem | null>(null);
  const [events, setEvents] = useState<TrafficEventItem[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadTraffic = useCallback(async () => {
    try {
      setError(null);
      const [statusResponse, eventResponse, alertResponse] = await Promise.all([
        api.getTrafficStatus(),
        api.getTrafficEvents(),
        api.getAlerts(),
      ]);
      setStatus(statusResponse);
      setEvents(eventResponse.items);
      setAlerts(alertResponse.items);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Unable to load telemetry');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadTraffic();
    const interval = window.setInterval(loadTraffic, 5000);
    return () => window.clearInterval(interval);
  }, [loadTraffic]);

  const updateAlert = async (alert: AlertItem) => {
    const nextStatus = alert.status === 'resolved' ? 'open' : 'resolved';
    try {
      const updated = await api.updateAlert(alert.id, { status: nextStatus });
      setAlerts((current) => current.map((item) => item.id === updated.id ? updated : item));
      showToast(`Alert marked ${nextStatus}`, 'success');
    } catch (updateError) {
      showToast(updateError instanceof Error ? updateError.message : 'Unable to update alert', 'error');
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold">Live Traffic</h1>
        <p className="mt-1 text-sm text-slate-400">Telemetry appears only when an HTTP or framed-packet adapter sends observed events.</p>
      </div>

      {error && <ErrorBanner message={error} onRetry={loadTraffic} />}

      <Card title="Ingestion status">
        {status ? (
          <>
            <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div><dt className="text-xs text-slate-400">Adapter</dt><dd className="mt-1 text-sm text-slate-100">{status.adapter || 'Not reported'}</dd></div>
              <div><dt className="text-xs text-slate-400">State</dt><dd className="mt-1 text-sm text-slate-100">{status.state}</dd></div>
              <div><dt className="text-xs text-slate-400">Events processed</dt><dd className="mt-1 text-sm text-slate-100">{status.packets_processed}</dd></div>
              <div><dt className="text-xs text-slate-400">Parse errors / dropped</dt><dd className="mt-1 text-sm text-slate-100">{status.parse_errors} / {status.dropped_events}</dd></div>
            </dl>
            {status.guidance && <p className="mt-4 border-t border-slate-800 pt-3 text-sm text-slate-400">{status.guidance}</p>}
            {status.last_error && <p role="alert" className="mt-2 text-sm text-red-400">{status.last_error}</p>}
          </>
        ) : loading ? <LoadingSkeleton rows={2} /> : <p className="text-sm text-slate-400">Ingestion status unavailable.</p>}
      </Card>

      <Card title={`Detection alerts (${alerts.length})`}>
        {loading && alerts.length === 0 ? <LoadingSkeleton rows={3} /> : alerts.length === 0 ? (
          <EmptyState title="No alerts recorded" description="Alerts are created from received telemetry and configured detection rules." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-slate-400">
                <tr><th className="py-2 pr-4">Severity</th><th className="py-2 pr-4">Detection</th><th className="py-2 pr-4">Source → destination</th><th className="py-2 pr-4">Status</th><th className="py-2">Action</th></tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td className="py-2 pr-4"><SeverityBadge severity={alert.severity} /></td>
                    <td className="py-2 pr-4 text-slate-200">{alert.title}</td>
                    <td className="py-2 pr-4 font-mono text-xs text-slate-300">{alert.src_addr || '—'} → {alert.dst_addr || '—'}</td>
                    <td className="py-2 pr-4 text-slate-300">{alert.status}</td>
                    <td className="py-2">
                      <button onClick={() => updateAlert(alert)} className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800">
                        {alert.status === 'resolved' ? 'Reopen' : 'Resolve'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title={`Recent telemetry events (${events.length})`}>
        {loading && events.length === 0 ? <LoadingSkeleton rows={4} /> : events.length === 0 ? (
          <EmptyState title="No traffic events recorded" description="Configure a capture adapter or send observed telemetry to the local ingestion endpoint. No sample packets are generated by this page." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-slate-400">
                <tr><th className="py-2 pr-4">Time</th><th className="py-2 pr-4">Source → destination</th><th className="py-2 pr-4">Protocol</th><th className="py-2 pr-4">Flow status</th><th className="py-2 pr-4">Classifier</th><th className="py-2">Signatures</th></tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {events.map((event) => (
                  <tr key={event.id}>
                    <td className="py-2 pr-4 text-xs text-slate-400">{event.timestamp ? new Date(event.timestamp).toLocaleString() : '—'}</td>
                    <td className="py-2 pr-4 font-mono text-xs text-slate-200">{event.src_addr || '—'}:{event.src_port || '—'} → {event.dst_addr || '—'}:{event.dst_port || '—'}</td>
                    <td className="py-2 pr-4 text-slate-300">{event.protocol || '—'}</td>
                    <td className="py-2 pr-4 text-slate-300">{event.feature_complete ? 'Complete flow' : 'Insufficient features'}</td>
                    <td className="py-2 pr-4 text-slate-300">{event.ml_status}{event.ml_label ? ` · ${event.ml_label}` : ''}{event.ml_confidence == null ? '' : ` (${(event.ml_confidence * 100).toFixed(1)}%)`}</td>
                    <td className="py-2 text-slate-300">{event.signatures?.join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <p className="text-xs text-slate-500">Flow classifier output is a model prediction, not proof of compromise. Incomplete flows are not classified.</p>
    </div>
  );
}
