import React, { useEffect, useState, useCallback } from 'react';
import {
  Terminal,
  Monitor,
  Shield,
  Plus,
  Trash2,
  Save,
  Radio,
  Sparkles,
} from 'lucide-react';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { Card } from '../components/common/Card';
import { LoadingSkeleton } from '../components/common/LoadingState';
import { ErrorBanner } from '../components/common/EmptyState';
import type { SettingsData } from '../types';

export const SettingsPage: React.FC = () => {
  const { demoMode, setDemoMode, refreshSettings, showToast } = useApp();
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Form Fields
  const [scannerName, setScannerName] = useState<string>('');
  const [scannerIp, setScannerIp] = useState<string>('');
  const [targetName, setTargetName] = useState<string>('');
  const [targetIp, setTargetIp] = useState<string>('');
  const [captureInterface, setCaptureInterface] = useState<string>('');
  const [nmapPath, setNmapPath] = useState<string>('');
  const [timezone, setTimezone] = useState<string>('UTC');
  const [logLevel, setLogLevel] = useState<string>('INFO');

  // New Target Form
  const [newCidr, setNewCidr] = useState<string>('');
  const [newCidrLabel, setNewCidrLabel] = useState<string>('');
  const [addingCidr, setAddingCidr] = useState<boolean>(false);

  const fetchSettings = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getSettings();
      setSettings(data);
      setScannerName(data.scanner_name || '');
      setScannerIp(data.scanner_ip || '');
      setTargetName(data.target_name || '');
      setTargetIp(data.target_ip || '');
      setCaptureInterface(data.capture_interface || '');
      setNmapPath(data.nmap?.path || '/usr/bin/nmap');
      setTimezone(data.timezone || 'UTC');
      setLogLevel(data.log_level || 'INFO');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch settings');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  // Save Settings
  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setSaving(true);
      await api.updateSettings({
        scanner_name: scannerName.trim(),
        scanner_ip: scannerIp.trim(),
        target_name: targetName.trim(),
        target_ip: targetIp.trim(),
        capture_interface: captureInterface.trim(),
        nmap_path: nmapPath.trim(),
        timezone: timezone.trim(),
        log_level: logLevel.trim(),
      });
      await refreshSettings();
      showToast('Settings successfully updated', 'success');
      fetchSettings();
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Failed to save settings', 'error');
    } finally {
      setSaving(false);
    }
  };

  // Add Authorized Target
  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCidr.trim()) return;
    try {
      setAddingCidr(true);
      await api.addAuthorizedTarget(newCidr.trim(), newCidrLabel.trim());
      setNewCidr('');
      setNewCidrLabel('');
      showToast(`Added authorized target subnet: ${newCidr}`, 'success');
      fetchSettings();
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Failed to add target', 'error');
    } finally {
      setAddingCidr(false);
    }
  };

  // Delete Target
  const handleDeleteTarget = async (targetId: number) => {
    try {
      await api.deleteAuthorizedTarget(targetId);
      showToast('Authorized target removed', 'info');
      fetchSettings();
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Failed to remove target', 'error');
    }
  };

  // Seed Demo Data
  const handleSeedDemo = async () => {
    try {
      const res = await api.seedDemoData();
      showToast(res.message, 'success');
      setDemoMode(true);
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Failed to seed demo data', 'error');
    }
  };

  // Clear Demo Data
  const handleClearDemo = async () => {
    try {
      const res = await api.clearDemoData();
      showToast(res.message, 'info');
      setDemoMode(false);
    } catch (err: unknown) {
      showToast(err instanceof Error ? err.message : 'Failed to clear demo data', 'error');
    }
  };

  if (loading && !settings) {
    return (
      <div className="space-y-4">
        <div className="h-8 bg-slate-800 rounded w-64 animate-pulse" />
        <LoadingSkeleton rows={6} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Lab & System Configuration</h1>
        <p className="text-xs text-slate-400 mt-1">
          Configure authorized scanner and target identities, CIDR allowlists, capture interfaces, and demo data fixtures.
        </p>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchSettings} />}

      <form onSubmit={handleSaveSettings} className="space-y-6 text-xs">
        {/* Lab Machine Identities Card */}
        <Card
          title="Authorized Lab Machine Identities"
          subtitle="Configure explicit Kali scanner and Windows 10 victim labels. Target IPs are never assumed or hard-coded."
          icon={<Terminal className="w-4 h-4" />}
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Scanner Identity */}
            <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 space-y-3">
              <div className="flex items-center gap-2 text-cyan-400 font-semibold">
                <Terminal className="w-4 h-4" />
                <span>Authorized Scanner (Kali Linux)</span>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Scanner Display Name</label>
                <input
                  type="text"
                  value={scannerName}
                  onChange={(e) => setScannerName(e.target.value)}
                  placeholder="e.g. Kali-Attacker-Lab"
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-slate-200 text-xs focus:outline-hidden focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Scanner Interface IP</label>
                <input
                  type="text"
                  value={scannerIp}
                  onChange={(e) => setScannerIp(e.target.value)}
                  placeholder="e.g. 192.168.1.10 or leave empty if dynamic"
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-slate-200 font-mono text-xs focus:outline-hidden focus:border-cyan-500"
                />
              </div>
            </div>

            {/* Target Identity */}
            <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 space-y-3">
              <div className="flex items-center gap-2 text-blue-400 font-semibold">
                <Monitor className="w-4 h-4" />
                <span>Authorized Target (Windows 10)</span>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Target Display Name</label>
                <input
                  type="text"
                  value={targetName}
                  onChange={(e) => setTargetName(e.target.value)}
                  placeholder="e.g. Windows-10-Victim"
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-slate-200 text-xs focus:outline-hidden focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Target Host IP</label>
                <input
                  type="text"
                  value={targetIp}
                  onChange={(e) => setTargetIp(e.target.value)}
                  placeholder="e.g. 192.168.1.50 (keep configurable)"
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-slate-200 font-mono text-xs focus:outline-hidden focus:border-cyan-500"
                />
              </div>
            </div>
          </div>
        </Card>

        {/* Target Allowlist Management */}
        <Card
          title="Authorized Target CIDR Allowlist"
          subtitle="Strict validation boundary: any scan request outside these subnets is automatically rejected"
          icon={<Shield className="w-4 h-4" />}
        >
          <div className="space-y-4">
            {/* Target list */}
            <div className="space-y-2">
              {settings?.authorized_targets && settings.authorized_targets.length > 0 ? (
                settings.authorized_targets.map((t) => (
                  <div
                    key={t.id}
                    className="p-2.5 bg-slate-900/80 rounded border border-slate-800 flex items-center justify-between font-mono"
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-cyan-300 font-semibold text-xs">{t.cidr}</span>
                      {t.label && <span className="text-slate-400 text-[11px] font-sans">({t.label})</span>}
                    </div>
                    <button
                      type="button"
                      onClick={() => handleDeleteTarget(t.id)}
                      className="p-1 text-slate-500 hover:text-red-400 transition-colors"
                      title="Remove subnet"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))
              ) : (
                <div className="text-amber-400 text-xs italic p-2 bg-slate-900 rounded">
                  No subnets in allowlist. Add your lab subnet below (e.g. 192.168.1.0/24 or 10.0.0.0/24).
                </div>
              )}
            </div>

            {/* Add CIDR Form */}
            <div className="pt-2 border-t border-slate-800 flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                value={newCidr}
                onChange={(e) => setNewCidr(e.target.value)}
                placeholder="CIDR subnet (e.g. 192.168.1.0/24)"
                className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 font-mono text-xs focus:outline-hidden focus:border-cyan-500"
              />
              <input
                type="text"
                value={newCidrLabel}
                onChange={(e) => setNewCidrLabel(e.target.value)}
                placeholder="Subnet Label (e.g. Lab Target Segment)"
                className="flex-1 bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 text-xs focus:outline-hidden focus:border-cyan-500"
              />
              <button
                type="button"
                onClick={handleAddTarget}
                disabled={addingCidr || !newCidr.trim()}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 font-medium rounded text-xs transition-colors flex items-center justify-center gap-1.5 shrink-0"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Subnet</span>
              </button>
            </div>
          </div>
        </Card>

        {/* Network & Ingestion Parameters */}
        <Card
          title="Network Ingestion & Scanner Paths"
          subtitle="System binary locations and socket telemetry configuration"
          icon={<Radio className="w-4 h-4" />}
        >
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label className="block text-slate-400 mb-1">Nmap Executable Path</label>
              <input
                type="text"
                value={nmapPath}
                onChange={(e) => setNmapPath(e.target.value)}
                placeholder="/usr/bin/nmap"
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 font-mono text-xs focus:outline-hidden focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Capture Interface</label>
              <input
                type="text"
                value={captureInterface}
                onChange={(e) => setCaptureInterface(e.target.value)}
                placeholder="eth0 or wlan0"
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 font-mono text-xs focus:outline-hidden focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Telemetry Socket Port</label>
              <input
                type="text"
                value={`${settings?.ingest_host}:${settings?.ingest_port}`}
                disabled
                className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-slate-500 font-mono text-xs"
              />
            </div>
          </div>
        </Card>

        {/* Demo Mode & Lab Simulation Fixtures */}
        <Card
          title="Simulated Lab Demo Fixtures"
          subtitle="Load or purge realistic test lab evidence (tagged data_source='demo') without polluting real operational scans."
          icon={<Sparkles className="w-4 h-4" />}
        >
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <span className="text-slate-200 font-medium">Demo Mode Switch:</span>
              <p className="text-slate-400 text-[11px]">
                Currently: <span className="font-mono text-cyan-300 font-bold">{demoMode ? 'ENABLED (Showing Demo Records)' : 'DISABLED (Strict Live Evidence)'}</span>
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={handleSeedDemo}
                className="px-3.5 py-1.5 bg-cyan-950 border border-cyan-800 hover:bg-cyan-900 text-cyan-300 text-xs font-medium rounded transition-colors"
              >
                Seed Demo Lab Data
              </button>
              <button
                type="button"
                onClick={handleClearDemo}
                className="px-3.5 py-1.5 bg-red-950 border border-red-800 hover:bg-red-900 text-red-300 text-xs font-medium rounded transition-colors"
              >
                Clear Demo Data
              </button>
            </div>
          </div>
        </Card>

        {/* Save Bar */}
        <div className="flex justify-end pt-2">
          <button
            type="submit"
            disabled={saving}
            className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-slate-900 font-bold rounded-md text-xs transition-colors flex items-center gap-2 shadow-lg shadow-cyan-950/60"
          >
            <Save className="w-4 h-4" />
            <span>{saving ? 'Saving...' : 'Save Configuration'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};
