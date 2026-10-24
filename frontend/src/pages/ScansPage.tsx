import React, { useEffect, useState, useCallback } from 'react';
import {
  Scan,
  Play,
  Upload,
  AlertCircle,
  Clock,
  StopCircle,
  Info,
} from 'lucide-react';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { Card } from '../components/common/Card';
import { Modal } from '../components/common/Modal';
import { LoadingSkeleton } from '../components/common/LoadingState';
import { EmptyState, ErrorBanner } from '../components/common/EmptyState';
import type { ScanJobItem, ScanProfileItem, SettingsData } from '../types';

export const ScansPage: React.FC = () => {
  const { showToast } = useApp();
  const [scans, setScans] = useState<ScanJobItem[]>([]);
  const [profiles, setProfiles] = useState<ScanProfileItem[]>([]);
  const [nmapStatus, setNmapStatus] = useState<{ installed: boolean; path: string; version?: string | null; guidance?: string } | null>(null);
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // New Scan Form State
  const [selectedProfile, setSelectedProfile] = useState<string>('tcp_connect');
  const [targetInput, setTargetInput] = useState<string>('');
  const [confirmTargetInput, setConfirmTargetInput] = useState<string>('');
  const [authorizedChecked, setAuthorizedChecked] = useState<boolean>(false);
  const [dryRunChecked, setDryRunChecked] = useState<boolean>(false);
  const [launching, setLaunching] = useState<boolean>(false);

  // Preview Modal
  const [previewData, setPreviewData] = useState<{ argv: string[]; profile: string; target: string } | null>(null);
  const [isPreviewOpen, setIsPreviewOpen] = useState<boolean>(false);

  // XML Import
  const [uploading, setUploading] = useState<boolean>(false);

  // Scan Inspector Modal
  const [inspectScan, setInspectScan] = useState<ScanJobItem | null>(null);

  const fetchScanData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [scansRes, profilesRes, settingsRes] = await Promise.all([
        api.getScans(),
        api.getScanProfiles(),
        api.getSettings(),
      ]);
      setScans(scansRes.items);
      setProfiles(profilesRes.profiles);
      setNmapStatus(profilesRes.nmap);
      setSettings(settingsRes);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch scan data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScanData();
    const interval = setInterval(fetchScanData, 5000);
    return () => clearInterval(interval);
  }, [fetchScanData]);

  // Dry run preview handler
  const handlePreview = async () => {
    if (!targetInput.trim()) {
      showToast('Enter a target IP or CIDR to preview', 'error');
      return;
    }
    try {
      const res = await api.previewScan(selectedProfile, targetInput.trim());
      setPreviewData(res);
      setIsPreviewOpen(true);
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Preview generation failed', 'error');
    }
  };

  // Launch scan handler
  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authorizedChecked) {
      showToast('Explicit operator authorization is required before launching scans', 'error');
      return;
    }
    if (confirmTargetInput.trim() !== targetInput.trim()) {
      showToast('Target confirmation string does not match the input target', 'error');
      return;
    }
    try {
      setLaunching(true);
      const job = await api.createScan({
        profile: selectedProfile,
        target: targetInput.trim(),
        confirmTarget: confirmTargetInput.trim(),
        confirmAuthorization: authorizedChecked,
        dryRun: dryRunChecked,
      });
      showToast(`Scan initiated [ID: ${job.id.slice(0, 8)}]`, 'success');
      setTargetInput('');
      setConfirmTargetInput('');
      setAuthorizedChecked(false);
      fetchScanData();
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Scan execution failed', 'error');
    } finally {
      setLaunching(false);
    }
  };

  // Cancel running scan
  const handleCancelScan = async (scanId: string) => {
    try {
      await api.cancelScan(scanId);
      showToast('Scan cancellation requested', 'info');
      fetchScanData();
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Failed to cancel scan', 'error');
    }
  };

  // XML File Import
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      setUploading(true);
      const res = await api.importXml(file);
      showToast(`XML Imported: ${res.hosts_up} hosts up, ${res.ports_open} open ports, ${res.findings_created} findings.`, 'success');
      fetchScanData();
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Failed to parse Nmap XML file', 'error');
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Scan Management & Execution</h1>
        <p className="text-xs text-slate-400 mt-1">
          Authorized lab execution engine. Commands run via structured argument arrays with timeout protection and target allowlist validation.
        </p>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchScanData} />}

      {/* Dependency Notice (if Nmap missing) */}
      {nmapStatus && !nmapStatus.installed && (
        <div className="bg-amber-950/50 border border-amber-600/80 rounded-lg p-4 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="flex-1 text-xs">
            <h4 className="font-semibold text-amber-300">Scanner Engine Not Detected on System PATH</h4>
            <p className="text-amber-200/80 mt-1">
              {nmapStatus.guidance || 'Nmap is required for active scans. On Kali Linux it is pre-installed. On Debian/Ubuntu run: `sudo apt install nmap`.'}
            </p>
            <p className="text-amber-300/70 mt-1 font-mono text-[11px]">
              Nmap XML imports remain available without a local Nmap installation. Flow classification runs only when a usable model and sufficient telemetry features are available.
            </p>
          </div>
        </div>
      )}

      {/* Top Grid: Scan Form + Allowlist & XML Upload */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Launch Form (2 Columns) */}
        <div className="lg:col-span-2">
          <Card
            title="Configure Authorized Lab Scan"
            subtitle="Strict input validation prevents arbitrary command execution"
            icon={<Scan className="w-4 h-4" />}
          >
            <form onSubmit={handleLaunchScan} className="space-y-4 text-xs">
              {/* Profile Selector */}
              <div>
                <label className="block text-slate-300 font-medium mb-1.5">Scan Profile</label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {profiles.map((p) => (
                    <button
                      type="button"
                      key={p.id}
                      onClick={() => setSelectedProfile(p.id)}
                      className={`p-3 rounded-lg border text-left transition-all ${
                        selectedProfile === p.id
                          ? 'bg-cyan-950/60 border-cyan-500 text-cyan-200 shadow-sm'
                          : 'bg-slate-900 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className="font-semibold text-xs text-slate-200">{p.label}</div>
                      <div className="font-mono text-[10px] text-cyan-400/80 mt-1 truncate">
                        flags: {p.flags.join(' ')}
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Target Input */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Target IP or CIDR</label>
                  <input
                    type="text"
                    value={targetInput}
                    onChange={(e) => setTargetInput(e.target.value)}
                    placeholder="e.g. 192.168.1.50 or 10.0.0.0/24"
                    className="w-full bg-slate-900 border border-slate-700 rounded-md px-3 py-2 text-slate-100 font-mono text-xs focus:outline-hidden focus:border-cyan-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Confirm Target String</label>
                  <input
                    type="text"
                    value={confirmTargetInput}
                    onChange={(e) => setConfirmTargetInput(e.target.value)}
                    placeholder="Re-enter target to confirm"
                    className="w-full bg-slate-900 border border-slate-700 rounded-md px-3 py-2 text-slate-100 font-mono text-xs focus:outline-hidden focus:border-cyan-500"
                    required
                  />
                </div>
              </div>

              {/* Authorization Checkboxes */}
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={authorizedChecked}
                    onChange={(e) => setAuthorizedChecked(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
                    required
                  />
                  <span>I confirm this target belongs to an authorized lab and I have explicit scanning permission.</span>
                </label>

                <label className="flex items-center gap-2 text-slate-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={dryRunChecked}
                    onChange={(e) => setDryRunChecked(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
                  />
                  <span>Dry-run only (record intended execution arguments without invoking process).</span>
                </label>
              </div>

              {/* Actions */}
              <div className="flex items-center justify-between pt-2">
                <button
                  type="button"
                  onClick={handlePreview}
                  className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-md transition-colors"
                >
                  Preview Arguments
                </button>

                <button
                  type="submit"
                  disabled={launching || !authorizedChecked || !targetInput.trim()}
                  className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-900 text-xs font-semibold rounded-md flex items-center gap-2 transition-colors shadow-lg shadow-cyan-950/50"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>{launching ? 'Validating & Starting...' : 'Execute Scan'}</span>
                </button>
              </div>
            </form>
          </Card>
        </div>

        {/* Allowlist & XML Upload Card (1 Column) */}
        <div className="space-y-4">
          {/* Target Allowlist Banner */}
          <Card title="Authorized Lab Target Allowlist" icon={<Info className="w-4 h-4" />}>
            <div className="space-y-2 text-xs">
              <p className="text-slate-400 text-[11px]">
                Scans are rejected by the backend unless the target falls within an authorized CIDR:
              </p>
              <div className="space-y-1.5 max-h-36 overflow-y-auto">
                {settings?.authorized_targets?.length ? (
                  settings.authorized_targets.map((t) => (
                    <div
                      key={t.id}
                      className="px-2.5 py-1.5 rounded bg-slate-900 border border-slate-800 font-mono text-[11px] text-cyan-300 flex items-center justify-between"
                    >
                      <span>{t.cidr}</span>
                      {t.label && <span className="text-[10px] text-slate-500">{t.label}</span>}
                    </div>
                  ))
                ) : (
                  <div className="text-amber-400 text-[11px] italic">
                    No authorized CIDRs defined. Go to Settings to add your lab subnet.
                  </div>
                )}
              </div>
            </div>
          </Card>

          {/* XML Upload Box */}
          <Card title="Import Existing Nmap XML" icon={<Upload className="w-4 h-4" />}>
            <div className="text-xs space-y-3">
              <p className="text-slate-400 text-[11px]">
                Import structured output from a prior scan (`-oX scan.xml`). Parsing is evidence-based and deterministic.
              </p>
              <label className="border-2 border-dashed border-slate-800 hover:border-cyan-500/80 rounded-lg p-4 flex flex-col items-center justify-center cursor-pointer transition-colors bg-slate-900/40">
                <Upload className="w-5 h-5 text-cyan-400 mb-1.5" />
                <span className="text-slate-300 font-medium">Choose .XML Scan File</span>
                <span className="text-[10px] text-slate-500 mt-0.5">Structured Nmap XML</span>
                <input
                  type="file"
                  accept=".xml"
                  onChange={handleFileUpload}
                  disabled={uploading}
                  className="hidden"
                />
              </label>
              {uploading && <div className="text-center text-cyan-400 text-[11px] animate-pulse">Normalizing and storing XML evidence...</div>}
            </div>
          </Card>
        </div>
      </div>

      {/* Scans History Table */}
      <Card
        title={`Scan Job Records (${scans.length})`}
        subtitle="Complete execution ledger with original raw XML and normalized JSON references"
        icon={<Clock className="w-4 h-4" />}
      >
        {loading ? (
          <LoadingSkeleton rows={5} />
        ) : scans.length === 0 ? (
          <EmptyState
            icon={<Scan className="w-8 h-8 text-cyan-400" />}
            title="No Scans Recorded"
            description="Launch a scan from the form above or import an XML scan artifact."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Scan ID</th>
                  <th className="py-3 px-4">Profile</th>
                  <th className="py-3 px-4">Target(s)</th>
                  <th className="py-3 px-4">Open Ports</th>
                  <th className="py-3 px-4">Duration</th>
                  <th className="py-3 px-4">Created At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold border ${
                          scan.status === 'completed'
                            ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                            : scan.status === 'running'
                            ? 'bg-cyan-950/60 text-cyan-300 border-cyan-800 animate-pulse'
                            : scan.status === 'error'
                            ? 'bg-red-950/60 text-red-400 border-red-800'
                            : 'bg-slate-800 text-slate-400 border-slate-700'
                        }`}
                      >
                        {scan.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono font-semibold text-cyan-300">
                      {scan.id.slice(0, 8)}...
                    </td>
                    <td className="py-3 px-4 font-medium text-slate-200">
                      {scan.profile}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">
                      {scan.targets}
                    </td>
                    <td className="py-3 px-4 font-mono">
                      <span className={scan.ports_open > 0 ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                        {scan.ports_open}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400">
                      {scan.duration_seconds != null ? `${scan.duration_seconds.toFixed(1)}s` : '—'}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px] font-mono">
                      {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {scan.status === 'running' && (
                          <button
                            onClick={() => handleCancelScan(scan.id)}
                            className="p-1.5 text-red-400 hover:text-red-300 hover:bg-slate-800 rounded transition-colors"
                            title="Cancel running scan"
                          >
                            <StopCircle className="w-4 h-4" />
                          </button>
                        )}
                        <button
                          onClick={() => setInspectScan(scan)}
                          className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition-colors"
                        >
                          Details
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Preview Modal */}
      <Modal
        isOpen={isPreviewOpen}
        onClose={() => setIsPreviewOpen(false)}
        title="Execution Parameter Preview"
        subtitle="Verifiable command argv array constructed without shell interpolation"
        maxWidth="max-w-xl"
      >
        {previewData && (
          <div className="space-y-4 text-xs font-mono">
            <div>
              <span className="text-slate-400 block mb-1">Target:</span>
              <div className="p-2 bg-slate-900 rounded text-cyan-300">{previewData.target}</div>
            </div>
            <div>
              <span className="text-slate-400 block mb-1">Safe Process Argument Array (argv):</span>
              <pre className="p-3 bg-slate-950 rounded text-emerald-300 border border-slate-800 overflow-x-auto">
                {JSON.stringify(previewData.argv, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>

      {/* Scan Inspector Modal */}
      <Modal
        isOpen={Boolean(inspectScan)}
        onClose={() => setInspectScan(null)}
        title={`Scan Inspection [${inspectScan?.id.slice(0, 8)}]`}
        subtitle={`Profile: ${inspectScan?.profile} &bull; Target: ${inspectScan?.targets}`}
        maxWidth="max-w-2xl"
      >
        {inspectScan && (
          <div className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-3 bg-slate-900 p-3 rounded-lg border border-slate-800 font-mono">
              <div>
                <span className="text-slate-500 block">Status</span>
                <span className="text-slate-200 font-semibold">{inspectScan.status.toUpperCase()}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Duration</span>
                <span className="text-slate-200">
                  {inspectScan.duration_seconds != null ? `${inspectScan.duration_seconds.toFixed(1)}s` : 'N/A'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Hosts Discovered</span>
                <span className="text-cyan-300">{inspectScan.hosts_up} Up / {inspectScan.hosts_down} Down</span>
              </div>
              <div>
                <span className="text-slate-500 block">Open Ports</span>
                <span className="text-emerald-400 font-bold">{inspectScan.ports_open}</span>
              </div>
            </div>

            {inspectScan.error && (
              <div className="bg-red-950/50 border border-red-800 rounded p-3 text-red-300">
                <span className="font-semibold block mb-1">Execution Failure / Guidance:</span>
                <p className="font-mono text-[11px]">{inspectScan.error}</p>
              </div>
            )}

            <div>
              <span className="text-slate-400 block mb-1 font-semibold">Executed Command Argument Array:</span>
              <pre className="p-3 bg-slate-950 rounded text-slate-300 font-mono text-[11px] border border-slate-800 overflow-x-auto">
                {JSON.stringify(inspectScan.argv, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
