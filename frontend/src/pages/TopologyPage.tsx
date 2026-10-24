import React, { useEffect, useState, useCallback } from 'react';
import {
  Network,
  Server,
  Eye,
  GitCompare,
} from 'lucide-react';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { Card } from '../components/common/Card';
import { StateBadge, DataSourceBadge } from '../components/common/Badge';
import { Drawer } from '../components/common/Drawer';
import { Modal } from '../components/common/Modal';
import { LoadingSkeleton } from '../components/common/LoadingState';
import { EmptyState, ErrorBanner } from '../components/common/EmptyState';
import type { HostItem, TopologyData, ScanJobItem } from '../types';

export const TopologyPage: React.FC = () => {
  const { demoMode } = useApp();
  const [hosts, setHosts] = useState<HostItem[]>([]);
  const [topology, setTopology] = useState<TopologyData | null>(null);
  const [scans, setScans] = useState<ScanJobItem[]>([]);
  const [selectedHost, setSelectedHost] = useState<HostItem | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Scan Comparison State
  const [isCompareOpen, setIsCompareOpen] = useState<boolean>(false);
  const [leftScanId, setLeftScanId] = useState<string>('');
  const [rightScanId, setRightScanId] = useState<string>('');
  const [comparisonResult, setComparisonResult] = useState<Record<string, unknown> | null>(null);
  const [comparing, setComparing] = useState<boolean>(false);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [hostsRes, topoRes, scansRes] = await Promise.all([
        api.getHosts(demoMode),
        api.getTopology(demoMode),
        api.getScans(),
      ]);
      setHosts(hostsRes.items);
      setTopology(topoRes);
      setScans(scansRes.items.filter((s) => s.status === 'completed'));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load network discovery data');
    } finally {
      setLoading(false);
    }
  }, [demoMode]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleRunComparison = async () => {
    if (!leftScanId || !rightScanId) return;
    try {
      setComparing(true);
      const res = await api.compareScans(leftScanId, rightScanId);
      setComparisonResult(res);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Scan comparison failed');
    } finally {
      setComparing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-100">Network Discovery & Topology</h1>
            <DataSourceBadge source={demoMode ? 'demo' : 'live'} />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Verified network inventory with strict edge provenance. Edges reflect actual scan relationships.
          </p>
        </div>

        <button
          onClick={() => {
            if (scans.length >= 2) {
              setLeftScanId(scans[0].id);
              setRightScanId(scans[1].id);
            }
            setIsCompareOpen(true);
          }}
          className="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-md border border-slate-700 flex items-center gap-2 transition-colors self-start"
        >
          <GitCompare className="w-3.5 h-3.5 text-cyan-400" />
          <span>Compare Scans</span>
        </button>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchData} />}

      {/* Interactive Topology Graph Section */}
      <Card
        title="Network Topology Visualization"
        subtitle={topology?.note || 'Edges are rendered strictly when provenance confirms connectivity.'}
        icon={<Network className="w-4 h-4" />}
      >
        {loading ? (
          <div className="h-64 flex items-center justify-center">
            <LoadingSkeleton rows={4} />
          </div>
        ) : !topology || topology.nodes.length === 0 ? (
          <div className="h-56 flex flex-col items-center justify-center text-slate-500 text-xs">
            <Network className="w-8 h-8 mb-2 opacity-50" />
            <span>No topology nodes recorded yet. Run a discovery scan or configure your scanner identity.</span>
          </div>
        ) : (
          <div className="relative w-full h-72 bg-[#090d16] border border-slate-800/80 rounded-lg p-4 overflow-hidden flex items-center justify-center">
            {/* SVG Topology Render */}
            <svg className="w-full h-full" viewBox="0 0 800 260">
              <defs>
                <linearGradient id="edgeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.4" />
                </linearGradient>
              </defs>

              {/* Render edges */}
              {topology.edges.map((edge, idx) => {
                const targetIdx = topology.nodes.findIndex((n) => n.id === edge.to);
                const targetX = 350 + (targetIdx % 4) * 130;
                const targetY = 70 + Math.floor(targetIdx / 4) * 110;

                return (
                  <g key={`edge-${idx}`}>
                    <line
                      x1="120"
                      y1="130"
                      x2={targetX}
                      y2={targetY}
                      stroke="url(#edgeGrad)"
                      strokeWidth="2"
                      strokeDasharray="4,4"
                    />
                  </g>
                );
              })}

              {/* Render Nodes */}
              {topology.nodes.map((node, idx) => {
                const isScanner = node.role === 'scanner';
                const x = isScanner ? 120 : 350 + (idx % 4) * 130;
                const y = isScanner ? 130 : 70 + Math.floor(idx / 4) * 110;

                return (
                  <g
                    key={node.id}
                    className="cursor-pointer group"
                    onClick={() => {
                      if (!isScanner) {
                        const rawId = parseInt(node.id.replace('host-', ''), 10);
                        const host = hosts.find((h) => h.id === rawId);
                        if (host) setSelectedHost(host);
                      }
                    }}
                  >
                    <circle
                      cx={x}
                      cy={y}
                      r={isScanner ? '30' : '24'}
                      fill={isScanner ? '#083344' : '#0f172a'}
                      stroke={isScanner ? '#06b6d4' : '#334155'}
                      strokeWidth="2"
                      className="group-hover:stroke-cyan-400 transition-all"
                    />
                    <text
                      x={x}
                      y={y + (isScanner ? 46 : 38)}
                      textAnchor="middle"
                      fill="#e2e8f0"
                      fontSize="11"
                      fontFamily="monospace"
                      fontWeight="500"
                    >
                      {node.ip || node.label}
                    </text>
                    <text
                      x={x}
                      y={y + (isScanner ? 58 : 50)}
                      textAnchor="middle"
                      fill="#64748b"
                      fontSize="9"
                    >
                      {isScanner ? 'AUTHORIZED SCANNER' : node.os_guess ? 'OS GUESS' : 'OBSERVED HOST'}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        )}
      </Card>

      {/* Host & IP Inventory Table */}
      <Card
        title={`Observed Host Inventory (${hosts.length})`}
        subtitle="Every host record is backed by an imported Nmap XML scan or packet capture."
        icon={<Server className="w-4 h-4" />}
      >
        {loading ? (
          <LoadingSkeleton rows={5} />
        ) : hosts.length === 0 ? (
          <EmptyState
            icon={<Server className="w-8 h-8 text-cyan-400" />}
            title="No Hosts Discovered"
            description="Launch a host discovery or TCP connect scan in Scan Management to populate your network inventory."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">State</th>
                  <th className="py-3 px-4">IP Address</th>
                  <th className="py-3 px-4">Hostname</th>
                  <th className="py-3 px-4">MAC Address</th>
                  <th className="py-3 px-4">Operating System</th>
                  <th className="py-3 px-4">Open Ports</th>
                  <th className="py-3 px-4">Last Seen</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {hosts.map((host) => {
                  const openServices = host.services?.filter((s) => s.state === 'open') || [];
                  return (
                    <tr key={host.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="py-3 px-4">
                        <StateBadge state={host.state} />
                      </td>
                      <td className="py-3 px-4 font-mono font-semibold text-cyan-300">
                        {host.ip}
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {host.hostname || <span className="text-slate-500 italic">None resolved</span>}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        {host.mac ? (
                          <span>{host.mac}</span>
                        ) : (
                          <span className="text-slate-600">Not local / unobserved</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {host.os_guess ? (
                          <div className="flex items-center gap-1.5">
                            <span className="text-slate-300">{host.os_guess}</span>
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-amber-400 border border-amber-800/50">
                              GUESS ({host.os_accuracy || 0}%)
                            </span>
                          </div>
                        ) : (
                          <span className="text-slate-500 italic">Unknown</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1 flex-wrap">
                          {openServices.slice(0, 4).map((s) => (
                            <span
                              key={s.id}
                              className="px-1.5 py-0.5 rounded bg-slate-900 text-[11px] font-mono text-slate-300 border border-slate-700"
                            >
                              {s.port}/{s.protocol}
                            </span>
                          ))}
                          {openServices.length > 4 && (
                            <span className="text-[10px] text-slate-400">+{openServices.length - 4} more</span>
                          )}
                          {openServices.length === 0 && <span className="text-slate-500">None open</span>}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px] font-mono">
                        {host.last_seen ? new Date(host.last_seen).toLocaleString() : 'N/A'}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => setSelectedHost(host)}
                          className="px-2.5 py-1 bg-slate-800 hover:bg-cyan-950/60 hover:text-cyan-300 text-slate-300 rounded border border-slate-700 text-xs font-medium inline-flex items-center gap-1.5 transition-colors"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Host Details Drawer */}
      <Drawer
        isOpen={Boolean(selectedHost)}
        onClose={() => setSelectedHost(null)}
        title={selectedHost ? `Host Inspection: ${selectedHost.ip}` : 'Host Details'}
        subtitle={selectedHost?.hostname || undefined}
        width="max-w-2xl"
      >
        {selectedHost && (
          <div className="space-y-6 text-xs">
            {/* Host Metadata Card */}
            <div className="bg-slate-900/80 p-4 rounded-lg border border-slate-800 space-y-3">
              <div className="grid grid-cols-2 gap-3 font-mono">
                <div>
                  <span className="text-slate-500 text-[11px] block">IPv4 Address</span>
                  <span className="text-cyan-300 text-sm font-semibold">{selectedHost.ip}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[11px] block">MAC Address</span>
                  <span className="text-slate-300">{selectedHost.mac || 'Unobserved (routed hop)'}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[11px] block">State</span>
                  <StateBadge state={selectedHost.state} />
                </div>
                <div>
                  <span className="text-slate-500 text-[11px] block">Data Source</span>
                  <DataSourceBadge source={selectedHost.data_source} />
                </div>
              </div>

              {selectedHost.os_guess && (
                <div className="pt-2 border-t border-slate-800">
                  <span className="text-slate-500 text-[11px] block">Operating System Fingerprint</span>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-slate-200 font-medium">{selectedHost.os_guess}</span>
                    <span className="px-1.5 py-0.5 rounded bg-amber-950/60 text-amber-300 border border-amber-800 text-[10px]">
                      EXPLICIT GUESS ({selectedHost.os_accuracy || 0}% accuracy)
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* Discovered Services Table */}
            <div>
              <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-2">
                Discovered Services ({selectedHost.services?.length || 0})
              </h4>
              {selectedHost.services?.length === 0 ? (
                <div className="text-slate-500 italic p-3 bg-slate-900 rounded">No open services observed on this host.</div>
              ) : (
                <div className="border border-slate-800 rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-900 text-slate-400 font-semibold border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Port</th>
                        <th className="py-2.5 px-3">Protocol</th>
                        <th className="py-2.5 px-3">State</th>
                        <th className="py-2.5 px-3">Service</th>
                        <th className="py-2.5 px-3">Product / Version</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {selectedHost.services.map((svc) => (
                        <React.Fragment key={svc.id}>
                          <tr className="hover:bg-slate-900/40">
                            <td className="py-2.5 px-3 font-mono font-semibold text-cyan-300">{svc.port}</td>
                            <td className="py-2.5 px-3 font-mono text-slate-400">{svc.protocol.toUpperCase()}</td>
                            <td className="py-2.5 px-3">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                                  svc.state === 'open'
                                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                    : 'bg-slate-800 text-slate-400'
                                }`}
                              >
                                {svc.state.toUpperCase()}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-slate-300">{svc.name || 'unknown'}</td>
                            <td className="py-2.5 px-3 text-slate-300">
                              {svc.product ? `${svc.product} ${svc.version || ''}` : <span className="text-slate-600 italic">No banner</span>}
                            </td>
                          </tr>
                          {svc.scripts && svc.scripts.length > 0 && (
                            <tr className="bg-slate-950/60">
                              <td colSpan={5} className="py-2 px-3">
                                <div className="space-y-1">
                                  {svc.scripts.map((sc, i) => (
                                    <div key={i} className="text-[11px] font-mono text-slate-400 bg-slate-900/80 p-1.5 rounded border border-slate-800">
                                      <span className="text-cyan-400 font-semibold">{sc.id}: </span>
                                      <span>{sc.output}</span>
                                    </div>
                                  ))}
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </Drawer>

      {/* Scan Comparison Modal */}
      <Modal
        isOpen={isCompareOpen}
        onClose={() => setIsCompareOpen(false)}
        title="Scan Comparison & Delta Engine"
        subtitle="Verify changes in discovered ports and services between two scans without fabricating history."
        maxWidth="max-w-3xl"
      >
        <div className="space-y-4 text-xs">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-400 text-xs mb-1 font-medium">Baseline (Left) Scan</label>
              <select
                value={leftScanId}
                onChange={(e) => setLeftScanId(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-slate-200 text-xs font-mono"
              >
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id.slice(0, 8)}... - {s.profile} ({new Date(s.created_at || '').toLocaleDateString()})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-slate-400 text-xs mb-1 font-medium">Comparison (Right) Scan</label>
              <select
                value={rightScanId}
                onChange={(e) => setRightScanId(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-2 text-slate-200 text-xs font-mono"
              >
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id.slice(0, 8)}... - {s.profile} ({new Date(s.created_at || '').toLocaleDateString()})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex justify-end">
            <button
              onClick={handleRunComparison}
              disabled={comparing || !leftScanId || !rightScanId}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-900 text-xs font-semibold rounded transition-colors flex items-center gap-1.5"
            >
              <GitCompare className="w-3.5 h-3.5" />
              <span>{comparing ? 'Calculating Delta...' : 'Compare Scans'}</span>
            </button>
          </div>

          {comparisonResult && (
            <div className="mt-4 p-4 bg-slate-900 rounded-lg border border-slate-800 space-y-3">
              <h5 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">Comparison Output</h5>
              <pre className="text-[11px] font-mono text-cyan-300 bg-slate-950 p-3 rounded overflow-x-auto max-h-64">
                {JSON.stringify(comparisonResult, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </Modal>
    </div>
  );
};
