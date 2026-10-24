import React, { useEffect, useState, useCallback } from 'react';
import {
  Shield,
  Server,
  Radio,
  Cpu,
  Clock,
  CheckCircle,
  AlertTriangle,
  ChevronRight,
  TrendingUp,
  Layers,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { Card } from '../components/common/Card';
import { SeverityBadge, DataSourceBadge } from '../components/common/Badge';
import { CardSkeleton } from '../components/common/LoadingState';
import { EmptyState, ErrorBanner } from '../components/common/EmptyState';
import type { DashboardSummary } from '../types';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#0ea5e9',
  info: '#64748b',
};

const VALIDATION_COLORS: Record<string, string> = {
  validated_vulnerability: '#ef4444',
  confirmed_by_check: '#10b981',
  suspected: '#f59e0b',
  potential_issue: '#8b5cf6',
  observed: '#06b6d4',
  detected: '#3b82f6',
  no_verified_cve_match: '#475569',
};

export const OverviewPage: React.FC = () => {
  const { demoMode } = useApp();
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [findingsView, setFindingsView] = useState<'validation' | 'severity'>('validation');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchSummary = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const summary = await api.getDashboardSummary(demoMode);
      setData(summary);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load executive summary');
    } finally {
      setLoading(false);
    }
  }, [demoMode]);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  if (loading && !data) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="h-8 bg-slate-800 rounded w-64 animate-pulse" />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
          <CardSkeleton />
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-bold text-slate-100">Executive Security Overview</h1>
        <ErrorBanner message={error} onRetry={fetchSummary} />
      </div>
    );
  }

  const isEmpty =
    !data ||
    (data.hosts_total === 0 &&
      data.ports_open === 0 &&
      Object.keys(data.findings_by_severity || {}).length === 0);

  // Formatting chart data
  const severityChartData = Object.entries(data?.findings_by_severity || {}).map(([key, val]) => ({
    name: key.toUpperCase(),
    value: val,
    color: SEVERITY_COLORS[key] || '#64748b',
  }));

  const validationChartData = Object.entries(data?.findings_by_validation || {}).map(([key, val]) => ({
    name: key.replace(/_/g, ' '),
    value: val,
    color: VALIDATION_COLORS[key] || '#64748b',
  }));

  const portDistributionData = [
    { name: 'Open', count: data?.ports_open || 0, fill: '#10b981' },
    { name: 'Filtered', count: data?.ports_filtered || 0, fill: '#f59e0b' },
    { name: 'Closed', count: data?.ports_closed || 0, fill: '#475569' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner & Mode indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-100 tracking-tight">Executive Security Overview</h1>
            <DataSourceBadge source={demoMode ? 'demo' : 'live'} />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic security intelligence synthesized from verified database records.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            to="/scans"
            className="px-3.5 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-900 font-semibold text-xs rounded-md shadow-md shadow-cyan-900/40 flex items-center gap-1.5 transition-colors"
          >
            <span>Launch Scan</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>

      {isEmpty ? (
        <EmptyState
          icon={<Shield className="w-8 h-8 text-cyan-400" />}
          title="No Lab Evidence Found Yet"
          description="No hosts or scan results have been recorded in the database. Run an authorized scan from the Scan Manager or import an existing Nmap XML file."
          action={
            <div className="flex items-center gap-3 mt-2">
              <Link
                to="/scans"
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-slate-900 text-xs font-semibold rounded-md transition-colors"
              >
                Scan Manager
              </Link>
              <Link
                to="/settings"
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-md transition-colors"
              >
                Configure Lab
              </Link>
            </div>
          }
        />
      ) : (
        <>
          {/* Key Metrics Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Total Hosts */}
            <Card className="hover:border-slate-700 transition-colors">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-slate-400">Total Observed Hosts</span>
                  <div className="text-2xl font-bold text-slate-100 mt-1 font-mono">
                    {data.hosts_total}
                  </div>
                </div>
                <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 text-cyan-400">
                  <Server className="w-5 h-5" />
                </div>
              </div>
              <div className="mt-3 flex items-center gap-2 text-xs text-emerald-400">
                <CheckCircle className="w-3.5 h-3.5" />
                <span>{data.hosts_up} currently reachable</span>
              </div>
            </Card>

            {/* Ports Observed */}
            <Card className="hover:border-slate-700 transition-colors">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-slate-400">Open Services / Ports</span>
                  <div className="text-2xl font-bold text-emerald-400 mt-1 font-mono">
                    {data.ports_open}
                  </div>
                </div>
                <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 text-emerald-400">
                  <Radio className="w-5 h-5" />
                </div>
              </div>
              <div className="mt-3 flex items-center justify-between text-xs text-slate-400 font-mono">
                <span>{data.services_observed} identified services</span>
                <span>{data.ports_filtered} filtered</span>
              </div>
            </Card>

            {/* Critical & High Findings */}
            <Card className="hover:border-slate-700 transition-colors">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-slate-400">Crit / High Findings</span>
                  <div className="text-2xl font-bold text-red-400 mt-1 font-mono">
                    {(data.findings_by_severity?.critical || 0) + (data.findings_by_severity?.high || 0)}
                  </div>
                </div>
                <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 text-red-400">
                  <AlertTriangle className="w-5 h-5" />
                </div>
              </div>
              <div className="mt-3 flex items-center gap-2 text-xs text-slate-400">
                <span>Medium: {data.findings_by_severity?.medium || 0}</span>
                <span className="text-slate-600">|</span>
                <span>Low/Info: {(data.findings_by_severity?.low || 0) + (data.findings_by_severity?.info || 0)}</span>
              </div>
            </Card>

            {/* AI Model Status */}
            <Card className="hover:border-slate-700 transition-colors">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-xs font-medium text-slate-400">Active ML Classifier</span>
                  <div className="text-sm font-semibold text-cyan-300 mt-1 truncate max-w-[140px] font-mono">
                    {data.model?.version || 'No Model Active'}
                  </div>
                </div>
                <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 text-cyan-400">
                  <Cpu className="w-5 h-5" />
                </div>
              </div>
              <div className="mt-3 text-xs text-slate-400 flex items-center gap-1.5 truncate">
                <Clock className="w-3 h-3 text-slate-500" />
                <span className="truncate">
                  {data.model?.trained_at
                    ? new Date(data.model.trained_at).toLocaleString()
                    : 'Requires training in ML Lab'}
                </span>
              </div>
            </Card>
          </div>

          {/* Visual Analytics Row */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Findings by Validation or Severity */}
            <Card
              title={findingsView === 'validation' ? 'Vulnerability Provenance & Validation' : 'Vulnerabilities by Severity'}
              subtitle="Evidence-based distinction between detected, confirmed, and verified CVEs"
              icon={<Shield className="w-4 h-4" />}
              action={
                <div className="flex bg-slate-900 rounded p-0.5 border border-slate-800 text-[10px]">
                  <button
                    onClick={() => setFindingsView('validation')}
                    className={`px-2 py-0.5 rounded font-medium transition-colors ${
                      findingsView === 'validation' ? 'bg-cyan-950 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Validation
                  </button>
                  <button
                    onClick={() => setFindingsView('severity')}
                    className={`px-2 py-0.5 rounded font-medium transition-colors ${
                      findingsView === 'severity' ? 'bg-cyan-950 text-cyan-300 font-bold' : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Severity
                  </button>
                </div>
              }
            >
              {(findingsView === 'validation' ? validationChartData : severityChartData).length > 0 ? (
                <div className="h-52 w-full flex items-center justify-center">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={findingsView === 'validation' ? validationChartData : severityChartData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        innerRadius={45}
                        outerRadius={75}
                        paddingAngle={4}
                      >
                        {(findingsView === 'validation' ? validationChartData : severityChartData).map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#334155',
                          borderRadius: '6px',
                          fontSize: '12px',
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="h-52 flex items-center justify-center text-xs text-slate-500">
                  No findings recorded
                </div>
              )}
              <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                {(findingsView === 'validation' ? validationChartData : severityChartData).map((item) => (
                  <div key={item.name} className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: item.color }} />
                    <span className="text-slate-400 truncate">{item.name}:</span>
                    <span className="font-mono text-slate-200 ml-auto">{item.value}</span>
                  </div>
                ))}
              </div>
            </Card>

            {/* Ports Breakdown */}
            <Card
              title="Observed Port State Distribution"
              subtitle="Distinct open services vs closed and filtered targets"
              icon={<Radio className="w-4 h-4" />}
            >
              <div className="h-52 w-full pt-4">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={portDistributionData}>
                    <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#64748b" fontSize={11} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        borderColor: '#334155',
                        borderRadius: '6px',
                        fontSize: '12px',
                      }}
                    />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {portDistributionData.map((entry, index) => (
                        <Cell key={`port-${index}`} fill={entry.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-2 text-xs text-slate-400 flex justify-between px-2 font-mono">
                <span>Total Ports Evaluated: {data.ports_open + data.ports_filtered + data.ports_closed}</span>
              </div>
            </Card>

            {/* Scan History Trend */}
            <Card
              title="Scan History & Open Port Trends"
              subtitle="Historical port progression from stored scan artifacts"
              icon={<TrendingUp className="w-4 h-4" />}
              action={
                <Link to="/scans" className="text-xs text-cyan-400 hover:text-cyan-300">
                  All Scans &rarr;
                </Link>
              }
            >
              {data.scan_trend?.length > 0 ? (
                <div className="h-52 w-full pt-4">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={data.scan_trend}>
                      <XAxis
                        dataKey="id"
                        stroke="#64748b"
                        fontSize={10}
                        tickFormatter={(v) => v.slice(0, 6)}
                      />
                      <YAxis stroke="#64748b" fontSize={11} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          borderColor: '#334155',
                          borderRadius: '6px',
                          fontSize: '12px',
                        }}
                      />
                      <Bar dataKey="ports_open" fill="#06b6d4" radius={[3, 3, 0, 0]} name="Open Ports" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <div className="h-52 flex items-center justify-center text-xs text-slate-500">
                  No scan history recorded
                </div>
              )}
              {data.latest_scan && (
                <div className="mt-2 text-xs bg-slate-900/60 p-2.5 rounded border border-slate-800 text-slate-300 flex items-center justify-between">
                  <span className="truncate">Latest: {data.latest_scan.profile}</span>
                  <span className="font-mono text-cyan-400">{data.latest_scan.status.toUpperCase()}</span>
                </div>
              )}
            </Card>
          </div>

          {/* Recent Alerts & Live Timeline */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card
              title="Recent Threat Detections & Alerts"
              subtitle="Persistent real-time detections with traceable evidence references"
              icon={<Layers className="w-4 h-4" />}
              action={
                <Link to="/alerts" className="text-xs text-cyan-400 hover:text-cyan-300">
                  View All &rarr;
                </Link>
              }
            >
              {data.recent_alerts?.length > 0 ? (
                <div className="space-y-2.5">
                  {data.recent_alerts.map((alert) => (
                    <div
                      key={alert.id}
                      className="p-3 bg-slate-900/60 border border-slate-800/80 rounded-lg flex items-center justify-between gap-3 hover:border-slate-700 transition-colors"
                    >
                      <div className="flex items-center gap-3 truncate">
                        <SeverityBadge severity={alert.severity} />
                        <div className="truncate">
                          <div className="text-xs font-semibold text-slate-200 truncate">{alert.title}</div>
                          <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                            {alert.detection_method.toUpperCase()} &bull; {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'N/A'}
                          </div>
                        </div>
                      </div>
                      <Link
                        to="/alerts"
                        className="text-xs text-slate-400 hover:text-cyan-400 px-2 py-1 rounded bg-slate-800/50 hover:bg-slate-800 shrink-0"
                      >
                        Inspect
                      </Link>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-8 text-center text-xs text-slate-500">
                  No alerts generated yet. Awaiting packet telemetry or scanner checks.
                </div>
              )}
            </Card>

            {/* ML Inference Summary */}
            <Card
              title="ML Traffic Classification Distribution"
              subtitle="Trained model inferences on parsed flows"
              icon={<Cpu className="w-4 h-4" />}
              action={
                <Link to="/ml" className="text-xs text-cyan-400 hover:text-cyan-300">
                  ML Lab &rarr;
                </Link>
              }
            >
              <div className="space-y-4">
                <div className="bg-slate-900/80 p-3.5 rounded-lg border border-slate-800 text-xs">
                  <div className="text-slate-400 mb-1">Supervised Model Version</div>
                  <div className="font-mono text-cyan-300 font-semibold text-sm">
                    {data.model?.version || 'rf-baseline-active'}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1 italic">
                    {data.model?.disclaimer}
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-xs font-semibold text-slate-300">Flow Classification Counts:</div>
                  {Object.keys(data.traffic_ml_labels || {}).length > 0 ? (
                    <div className="grid grid-cols-2 gap-3">
                      {Object.entries(data.traffic_ml_labels).map(([label, count]) => (
                        <div
                          key={label}
                          className="p-3 bg-slate-900/50 border border-slate-800 rounded flex items-center justify-between"
                        >
                          <span
                            className={`text-xs font-semibold ${
                              label.toUpperCase() === 'ATTACK' ? 'text-red-400' : 'text-emerald-400'
                            }`}
                          >
                            {label}
                          </span>
                          <span className="font-mono text-sm text-slate-200">{count}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-xs text-slate-500 py-3">
                      No flow classifications recorded yet. Events with insufficient packets are safely marked as skipped rather than evaluated with fabricated features.
                    </div>
                  )}
                </div>
              </div>
            </Card>
          </div>
        </>
      )}
    </div>
  );
};
