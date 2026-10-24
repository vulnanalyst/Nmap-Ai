import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { Card } from '../components/common/Card';
import { EmptyState, ErrorBanner } from '../components/common/EmptyState';
import { SeverityBadge } from '../components/common/Badge';
import type { DashboardSummary, FindingItem, HostItem, ScanJobItem } from '../types';

export function OverviewPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [hosts, setHosts] = useState<HostItem[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [scans, setScans] = useState<ScanJobItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [summaryResponse, hostsResponse, findingsResponse, scansResponse] = await Promise.all([
        api.getDashboardSummary(),
        api.getHosts(),
        api.getFindings(),
        api.getScans(),
      ]);
      setSummary(summaryResponse);
      setHosts(hostsResponse.items.slice(0, 8));
      setFindings(findingsResponse.items.slice(0, 8));
      setScans(scansResponse.items.slice(0, 5));
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Unable to load dashboard data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  if (loading && !summary) return <p className="text-sm text-slate-400">Loading dashboard…</p>;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">Network Security Dashboard</h1>
          <p className="mt-1 text-sm text-slate-400">Current inventory and findings from recorded Nmap scans.</p>
        </div>
        <Link to="/scans" className="rounded border border-slate-700 px-3 py-2 text-sm text-slate-200 hover:bg-slate-900">
          New scan
        </Link>
      </div>

      {error && <ErrorBanner message={error} onRetry={loadDashboard} />}

      {summary && (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {[
            ['Observed hosts', summary.hosts_total],
            ['Open ports', summary.ports_open],
            ['Critical / high findings', (summary.findings_by_severity.critical || 0) + (summary.findings_by_severity.high || 0)],
            ['Latest scan', summary.latest_scan?.status || 'No scans'],
          ].map(([label, value]) => (
            <Card key={label}>
              <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
              <div className="mt-2 text-xl font-semibold text-slate-100">{value}</div>
            </Card>
          ))}
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={`Discovered hosts (${hosts.length})`}>
          {hosts.length === 0 ? (
            <EmptyState title="No hosts recorded" description="Import Nmap XML or run a scan against an explicitly authorized target." />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs text-slate-400">
                  <tr><th className="py-2 pr-4">Address</th><th className="py-2 pr-4">Hostname</th><th className="py-2">Open ports</th></tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {hosts.map((host) => (
                    <tr key={host.id}>
                      <td className="py-2 pr-4 font-mono text-slate-200">{host.ip}</td>
                      <td className="py-2 pr-4 text-slate-300">{host.hostname || '—'}</td>
                      <td className="py-2 text-slate-300">{host.services.filter((service) => service.state === 'open').length}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <Link to="/topology" className="mt-3 inline-block text-sm text-cyan-400 hover:text-cyan-300">View network inventory</Link>
        </Card>

        <Card title={`Recent findings (${findings.length})`}>
          {findings.length === 0 ? (
            <EmptyState title="No findings recorded" description="Findings are created from imported or completed Nmap scan evidence." />
          ) : (
            <div className="divide-y divide-slate-800">
              {findings.map((finding) => (
                <div key={finding.id} className="flex items-start justify-between gap-3 py-3">
                  <div>
                    <div className="text-sm text-slate-200">{finding.title}</div>
                    <div className="mt-1 font-mono text-xs text-slate-400">
                      {finding.host_ip}{finding.port ? `:${finding.port}` : ''}{finding.cve ? ` · ${finding.cve}` : ''}
                    </div>
                  </div>
                  <SeverityBadge severity={finding.severity} />
                </div>
              ))}
            </div>
          )}
          <Link to="/vulnerabilities" className="mt-3 inline-block text-sm text-cyan-400 hover:text-cyan-300">View all findings</Link>
        </Card>
      </div>

      <Card title="Recent scans">
        {scans.length === 0 ? (
          <EmptyState title="No scans recorded" description="Scan history appears here after a scan or Nmap XML import." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-slate-400">
                <tr><th className="py-2 pr-4">Target</th><th className="py-2 pr-4">Profile</th><th className="py-2 pr-4">Status</th><th className="py-2">Started</th></tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td className="py-2 pr-4 font-mono text-slate-200">{scan.targets}</td>
                    <td className="py-2 pr-4 text-slate-300">{scan.profile}</td>
                    <td className="py-2 pr-4 text-slate-300">{scan.status}{scan.error ? ` — ${scan.error}` : ''}</td>
                    <td className="py-2 text-slate-400">{scan.created_at ? new Date(scan.created_at).toLocaleString() : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
