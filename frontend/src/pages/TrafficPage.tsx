import React, { useEffect, useState, useCallback } from 'react';
import {
  Activity,
  Radio,
  Send,
  AlertCircle,
  Clock,
  Terminal,
} from 'lucide-react';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { Card } from '../components/common/Card';
import { DataSourceBadge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';
import { LoadingSkeleton } from '../components/common/LoadingState';
import { EmptyState, ErrorBanner } from '../components/common/EmptyState';
import type { IngestionStatusItem, TrafficEventItem } from '../types';

export const TrafficPage: React.FC = () => {
  const { demoMode, showToast } = useApp();
  const [status, setStatus] = useState<IngestionStatusItem | null>(null);
  const [events, setEvents] = useState<TrafficEventItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Test Packet Ingestion Modal
  const [isTestModalOpen, setIsTestModalOpen] = useState<boolean>(false);
  const [testSrcIp, setTestSrcIp] = useState<string>('192.168.1.100');
  const [testDstIp, setTestDstIp] = useState<string>('192.168.1.50');
  const [testSrcPort, setTestSrcPort] = useState<number>(49152);
  const [testDstPort, setTestDstPort] = useState<number>(445);
  const [testProtocol, setTestProtocol] = useState<string>('TCP');
  const [testLength, setTestLength] = useState<number>(64);
  const [sendingTest, setSendingTest] = useState<boolean>(false);

  const fetchTrafficData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [statusRes, eventsRes] = await Promise.all([
        api.getTrafficStatus(),
        api.getTrafficEvents(demoMode),
      ]);
      setStatus(statusRes);
      setEvents(eventsRes.items);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch traffic monitoring status');
    } finally {
      setLoading(false);
    }
  }, [demoMode]);

  useEffect(() => {
    fetchTrafficData();
    const interval = setInterval(fetchTrafficData, 4000);
    return () => clearInterval(interval);
  }, [fetchTrafficData]);

  const handleSendTestPacket = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSendingTest(true);
      const res = await api.ingestPacket({
        src_addr: testSrcIp.trim(),
        dst_addr: testDstIp.trim(),
        src_port: testSrcPort,
        dst_port: testDstPort,
        protocol: testProtocol,
        packet_length: testLength,
      });
      showToast(
        `Telemetry event ingested (ID: ${res.id}, ML Status: ${res.ml_status})`,
        'success'
      );
      setIsTestModalOpen(false);
      fetchTrafficData();
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Packet ingestion failed', 'error');
    } finally {
      setSendingTest(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-100">Live Traffic & Telemetry Ingestion</h1>
            <DataSourceBadge source={demoMode ? 'demo' : 'live'} />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time flow aggregation and classification. Incomplete flows are marked as insufficient rather than evaluated with fabricated features.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsTestModalOpen(true)}
            className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-900 text-xs font-semibold rounded-md flex items-center gap-1.5 transition-colors shadow-md shadow-cyan-900/40"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Send Test Telemetry</span>
          </button>
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchTrafficData} />}

      {/* Ingestion Health & Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Adapter State */}
        <Card className="hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-medium text-slate-400">Ingestion Adapter</span>
              <div className="text-sm font-bold text-slate-100 mt-1 font-mono uppercase">
                {status?.adapter || 'tcp-framed'}
              </div>
            </div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800 text-cyan-400">
              <Radio className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 flex items-center gap-2 text-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                status?.state === 'running' ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'
              }`}
            />
            <span className="text-slate-300 capitalize">{status?.state || 'idle'}</span>
            <span className="text-slate-500">&bull;</span>
            <span className="text-slate-400 font-mono text-[11px]">{status?.interface || 'eth0'}</span>
          </div>
        </Card>

        {/* Packets Processed */}
        <Card className="hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-medium text-slate-400">Packets Ingested</span>
              <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">
                {status?.packets_processed ?? 0}
              </div>
            </div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800 text-emerald-400">
              <Activity className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-slate-400">
            <span>Flows Formed: </span>
            <span className="font-mono text-cyan-300 font-semibold">{status?.flows_processed ?? 0}</span>
          </div>
        </Card>

        {/* Framing & Parse Errors */}
        <Card className="hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-medium text-slate-400">Parse / Frame Errors</span>
              <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">
                {status?.parse_errors ?? 0}
              </div>
            </div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800 text-amber-400">
              <AlertCircle className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-slate-400">
            <span>Dropped: </span>
            <span className="font-mono text-slate-300">{status?.dropped_events ?? 0}</span>
          </div>
        </Card>

        {/* Last Event Time */}
        <Card className="hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-xs font-medium text-slate-400">Last Telemetry Timestamp</span>
              <div className="text-xs font-semibold text-slate-300 mt-2 font-mono truncate">
                {status?.last_event_at ? new Date(status.last_event_at).toLocaleTimeString() : 'Awaiting traffic'}
              </div>
            </div>
            <div className="p-2 bg-slate-900 rounded border border-slate-800 text-slate-400">
              <Clock className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-3 text-xs text-slate-500 truncate">
            {status?.permission_ok ? 'Root permissions active' : 'Standard capture permissions'}
          </div>
        </Card>
      </div>

      {/* Lab Telemetry Architecture Guidance Card */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 text-xs space-y-2">
        <div className="flex items-center gap-2 text-cyan-400 font-semibold">
          <Terminal className="w-4 h-4" />
          <span>Lab Telemetry Streaming Instructions</span>
        </div>
        <p className="text-slate-300 leading-relaxed">
          The listener runs on port 9999. Use length-prefixed streaming or local Scapy capture adapter. To start streaming telemetry from your Kali or gateway machine:
        </p>
        <div className="bg-slate-950 p-3 rounded font-mono text-[11px] text-cyan-300 border border-slate-800 overflow-x-auto">
          python3 capture/live_monitor.py
        </div>
        <p className="text-slate-400 text-[11px] italic">
          Raw packet features are accumulated in the stateful FlowTable until minimum statistics exist. If a single packet is seen, the ML status indicates `skipped_insufficient` to prevent deceptive classifications.
        </p>
      </div>

      {/* Traffic Events Table */}
      <Card
        title={`Recent Ingested Traffic Events (${events.length})`}
        subtitle="Individual packet and flow telemetry records in SQLite"
        icon={<Activity className="w-4 h-4" />}
      >
        {loading && events.length === 0 ? (
          <LoadingSkeleton rows={5} />
        ) : events.length === 0 ? (
          <EmptyState
            icon={<Activity className="w-8 h-8 text-cyan-400" />}
            title="No Traffic Events Logged"
            description="Start the capture script or click 'Send Test Telemetry' above to push sample packet telemetry into the pipeline."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Time</th>
                  <th className="py-3 px-4">Source &rarr; Destination</th>
                  <th className="py-3 px-4">Proto</th>
                  <th className="py-3 px-4">Flow Features</th>
                  <th className="py-3 px-4">ML Status</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4">Signatures</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {events.map((evt) => (
                  <tr key={evt.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                      {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : 'N/A'}
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan-300">
                      {evt.src_addr}:{evt.src_port || '—'} &rarr; {evt.dst_addr}:{evt.dst_port || '—'}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">
                      {evt.protocol || 'TCP'}
                    </td>
                    <td className="py-3 px-4">
                      {evt.feature_complete ? (
                        <span className="px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800 text-[10px] font-semibold">
                          FLOW READY
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 text-[10px]">
                          PARTIAL ({evt.packet_length || 0}B)
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                          evt.ml_status === 'classified'
                            ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {evt.ml_status}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {evt.ml_label ? (
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`font-semibold text-xs ${
                              evt.ml_label.toUpperCase() === 'ATTACK' ? 'text-red-400' : 'text-emerald-400'
                            }`}
                          >
                            {evt.ml_label}
                          </span>
                          {evt.ml_confidence != null && (
                            <span className="text-[10px] font-mono text-slate-500">
                              ({(evt.ml_confidence * 100).toFixed(1)}%)
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-600 italic">None</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {evt.signatures && evt.signatures.length > 0 ? (
                        <div className="flex gap-1 flex-wrap">
                          {evt.signatures.map((sig, i) => (
                            <span
                              key={i}
                              className="px-1.5 py-0.2 rounded bg-amber-950/70 text-amber-300 border border-amber-800 text-[10px] font-mono"
                            >
                              {sig}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Test Telemetry Ingestion Modal */}
      <Modal
        isOpen={isTestModalOpen}
        onClose={() => setIsTestModalOpen(false)}
        title="Send Test Lab Telemetry"
        subtitle="Submit a raw packet event to evaluate flow extraction, signature inspection, and ML inference."
        maxWidth="max-w-md"
      >
        <form onSubmit={handleSendTestPacket} className="space-y-4 text-xs">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-400 mb-1">Source IP</label>
              <input
                type="text"
                value={testSrcIp}
                onChange={(e) => setTestSrcIp(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs"
                required
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Source Port</label>
              <input
                type="number"
                value={testSrcPort}
                onChange={(e) => setTestSrcPort(parseInt(e.target.value, 10))}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs"
                required
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-400 mb-1">Destination IP</label>
              <input
                type="text"
                value={testDstIp}
                onChange={(e) => setTestDstIp(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs"
                required
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Destination Port</label>
              <input
                type="number"
                value={testDstPort}
                onChange={(e) => setTestDstPort(parseInt(e.target.value, 10))}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs"
                required
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-400 mb-1">Protocol</label>
              <select
                value={testProtocol}
                onChange={(e) => setTestProtocol(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs"
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
              </select>
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Packet Length (Bytes)</label>
              <input
                type="number"
                value={testLength}
                onChange={(e) => setTestLength(parseInt(e.target.value, 10))}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 font-mono text-xs"
                required
              />
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={sendingTest}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-900 font-semibold rounded text-xs transition-colors flex items-center gap-1.5"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{sendingTest ? 'Ingesting...' : 'Submit Telemetry'}</span>
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
