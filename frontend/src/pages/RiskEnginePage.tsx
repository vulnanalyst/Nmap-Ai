import React, { useEffect, useState, useCallback } from 'react';
import {
  Zap,
  ShieldCheck,
  Sliders,
} from 'lucide-react';
import { api } from '../services/api';
import { useApp } from '../context/AppContext';
import { Card } from '../components/common/Card';
import { SeverityBadge, ValidationBadge, DataSourceBadge } from '../components/common/Badge';
import { LoadingSkeleton } from '../components/common/LoadingState';
import { EmptyState, ErrorBanner } from '../components/common/EmptyState';
import type { FindingItem } from '../types';

export const RiskEnginePage: React.FC = () => {
  const { demoMode } = useApp();
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchRankings = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getFindings({ include_demo: demoMode });
      // Sort by risk score descending
      const sorted = [...res.items].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
      setFindings(sorted);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch risk prioritization');
    } finally {
      setLoading(false);
    }
  }, [demoMode]);

  useEffect(() => {
    fetchRankings();
  }, [fetchRankings]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-100">Explainable AI & Risk Prioritization</h1>
            <DataSourceBadge source={demoMode ? 'demo' : 'live'} />
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Transparent composite scoring. Every risk value is deconstructed into observable evidence signals without opaque black-box heuristics.
          </p>
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={fetchRankings} />}

      {/* Formula Explanation Card */}
      <Card
        title="Deterministic Risk Scoring Formula"
        subtitle="Mathematical composition of contributing security vectors"
        icon={<Sliders className="w-4 h-4" />}
      >
        <div className="space-y-3 text-xs">
          <div className="p-3 bg-slate-900 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-300">
            Risk_Score = [ 0.45 * CVSS + 0.25 * Service_Exposure + 0.15 * Evidence_Confidence + 0.15 * ML_Anomaly_Signal ] * Freshness_Factor
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-slate-300">
            <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
              <span className="font-semibold text-cyan-400 block mb-0.5">CVSS Component (45%)</span>
              <p className="text-[11px] text-slate-400">Trustworthy CVE base metrics from NIST NVD / advisory catalog.</p>
            </div>
            <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
              <span className="font-semibold text-blue-400 block mb-0.5">Service Exposure (25%)</span>
              <p className="text-[11px] text-slate-400">Based on service reachability, public vs local segment exposure, and open state.</p>
            </div>
            <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
              <span className="font-semibold text-emerald-400 block mb-0.5">Evidence Confidence (15%)</span>
              <p className="text-[11px] text-slate-400">Validated check (+1.0), suspected banner (+0.5), or unverified match (+0.25).</p>
            </div>
            <div className="p-2.5 bg-slate-900/60 rounded border border-slate-800">
              <span className="font-semibold text-purple-400 block mb-0.5">ML Signal & Freshness (15%)</span>
              <p className="text-[11px] text-slate-400">Correlated flow anomaly score combined with observation time decay.</p>
            </div>
          </div>
        </div>
      </Card>

      {/* Prioritized Findings List */}
      <Card
        title={`Prioritized Vulnerability Action Queue (${findings.length})`}
        subtitle="Ranked in descending order of remediative urgency based on verified signals"
        icon={<Zap className="w-4 h-4" />}
      >
        {loading ? (
          <LoadingSkeleton rows={5} />
        ) : findings.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck className="w-8 h-8 text-cyan-400" />}
            title="No Risk Findings Logged"
            description="Run an authorized vulnerability scan to populate the risk engine."
          />
        ) : (
          <div className="space-y-3">
            {findings.map((finding, rank) => {
              const breakdown = finding.risk_breakdown || {};
              const score = finding.risk_score || 0;

              return (
                <div
                  key={finding.id}
                  className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg hover:border-slate-700 transition-colors space-y-3"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-3">
                      <span className="w-6 h-6 rounded bg-slate-800 text-slate-400 font-mono text-xs flex items-center justify-center font-bold">
                        #{rank + 1}
                      </span>
                      <SeverityBadge severity={finding.severity} />
                      <span className="font-semibold text-slate-100 text-xs">{finding.title}</span>
                      <ValidationBadge status={finding.validation_status} />
                    </div>

                    <div className="flex items-center gap-3 self-end sm:self-center font-mono">
                      <span className="text-slate-400 text-xs">Risk Index:</span>
                      <span className={`text-base font-bold ${score >= 7 ? 'text-red-400' : score >= 4 ? 'text-amber-400' : 'text-cyan-400'}`}>
                        {score.toFixed(1)} / 10.0
                      </span>
                    </div>
                  </div>

                  {/* Signal Breakdown Progress Bar */}
                  <div className="space-y-1">
                    <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden flex border border-slate-800">
                      <div
                        className="bg-red-500 h-full"
                        style={{ width: `${((breakdown.cvss_component || 0) / 10) * 100}%` }}
                        title={`CVSS: ${breakdown.cvss_component?.toFixed(2)}`}
                      />
                      <div
                        className="bg-blue-500 h-full"
                        style={{ width: `${((breakdown.exposure_component || 0) / 10) * 100}%` }}
                        title={`Exposure: ${breakdown.exposure_component?.toFixed(2)}`}
                      />
                      <div
                        className="bg-emerald-500 h-full"
                        style={{ width: `${((breakdown.confidence_component || 0) / 10) * 100}%` }}
                        title={`Confidence: ${breakdown.confidence_component?.toFixed(2)}`}
                      />
                      <div
                        className="bg-purple-500 h-full"
                        style={{ width: `${((breakdown.ml_anomaly_signal || 0) / 10) * 100}%` }}
                        title={`ML Signal: ${breakdown.ml_anomaly_signal?.toFixed(2)}`}
                      />
                    </div>
                    <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                      <span>Host: {finding.host_ip}:{finding.port || '—'}</span>
                      <span>CVSS: {finding.cvss?.toFixed(1) || 'N/A'}</span>
                      <span>Remediation Status: {finding.workflow_status.toUpperCase()}</span>
                    </div>
                  </div>

                  {/* Remediation Summary */}
                  {finding.remediation && (
                    <div className="p-2.5 bg-slate-950/60 rounded border border-slate-850 text-[11px] text-slate-300">
                      <span className="font-semibold text-emerald-400">Action Plan: </span>
                      <span>{finding.remediation}</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
};
