import React, { useEffect, useState, useCallback } from 'react';
import {
  Terminal,
  Monitor,
  Shield,
  Plus,
  Trash2,
  Save,
  Radio,
} from 'lucide-react';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { Card } from '../components/common/Card';
import { LoadingSkeleton } from '../components/common/LoadingState';
import { ErrorBanner } from '../components/common/EmptyState';
import type { SettingsData } from '../types';

export const SettingsPage: React.FC = () => {
  const { refreshSettings, showToast } = useApp();
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Form Fields
  const [scannerName, setScannerName] = useState<string>('');
  const [scannerIp, setScannerIp] = useState<string>('');
  const [targetName, setTargetName] = useState<string>('');
  const [targetIp, setTargetIp] = useState<string>('');
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
      });
      await refreshSettings();
      showToast('Settings successfully updated', 'success');
      await fetchSettings();
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
          Configure scanner and target labels, the authorized scan range, and inspect local scanner readiness.
        </p>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchSettings} />}

      <form onSubmit={handleSaveSettings} className="space-y-6 text-xs">
        {/* Lab Machine Identities Card */}
        <Card
          title="Scanner and Target Identities"
          subtitle="Optional labels appear in topology and reports. Scan authorization is controlled separately by the CIDR allowlist."
          icon={<Terminal className="w-4 h-4" />}
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Scanner Identity */}
            <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 space-y-3">
              <div className="flex items-center gap-2 text-cyan-400 font-semibold">
                <Terminal className="w-4 h-4" />
                <span>Scanner</span>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Scanner Display Name</label>
                <input
                  type="text"
                  value={scannerName}
                  onChange={(e) => setScannerName(e.target.value)}
                  placeholder="e.g. Lab scanner"
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
                <span>Target</span>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Target Display Name</label>
                <input
                  type="text"
                  value={targetName}
                  onChange={(e) => setTargetName(e.target.value)}
                  placeholder="e.g. Test host"
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-slate-200 text-xs focus:outline-hidden focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Target Host IP</label>
                <input
                  type="text"
                  value={targetIp}
                  onChange={(e) => setTargetIp(e.target.value)}
                  placeholder="Optional; report context only"
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

        {/* Scanner readiness */}
        <Card
          title="Local Scanner Readiness"
          subtitle="Nmap executable is configured by the server operator with NMAP_AI_NMAP_PATH."
          icon={<Radio className="w-4 h-4" />}
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-slate-400 mb-1">Nmap</label>
              <p className={settings?.nmap.installed ? 'text-emerald-400' : 'text-amber-400'}>
                {settings?.nmap.installed ? settings.nmap.version : 'Not available'}
              </p>
              <p className="mt-1 break-all font-mono text-slate-500">{settings?.nmap.path}</p>
              {!settings?.nmap.installed && settings?.nmap.guidance && (
                <p className="mt-2 text-slate-400">{settings.nmap.guidance}</p>
              )}
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Telemetry listener</label>
              <p className="font-mono text-slate-300">{settings?.ingest_host}:{settings?.ingest_port}</p>
              <p className="mt-1 text-slate-500">Requires an authorized external capture source.</p>
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
