import type { FC } from 'react';
import type { Severity, ValidationStatus, WorkflowStatus } from '../../types';

export const SeverityBadge: FC<{ severity: Severity; className?: string }> = ({ severity, className = '' }) => {
  const styles: Record<Severity, string> = {
    critical: 'bg-red-950/70 text-red-400 border border-red-800/80',
    high: 'bg-orange-950/70 text-orange-400 border border-orange-800/80',
    medium: 'bg-amber-950/70 text-amber-400 border border-amber-800/80',
    low: 'bg-sky-950/70 text-sky-400 border border-sky-800/80',
    info: 'bg-slate-800/80 text-slate-300 border border-slate-700',
  };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium tracking-wide uppercase ${styles[severity] || styles.info} ${className}`}>
      {severity}
    </span>
  );
};

export const ValidationBadge: React.FC<{ status: ValidationStatus; className?: string }> = ({ status, className = '' }) => {
  const labels: Record<ValidationStatus, { text: string; style: string }> = {
    observed: { text: 'Observed', style: 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/70' },
    detected: { text: 'Detected', style: 'bg-blue-950/60 text-blue-300 border border-blue-800/70' },
    suspected: { text: 'Suspected', style: 'bg-amber-950/60 text-amber-300 border border-amber-800/70' },
    confirmed_by_check: { text: 'Confirmed by Check', style: 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/70' },
    validated_vulnerability: { text: 'Validated Vulnerability', style: 'bg-red-950/70 text-red-300 border border-red-800/80' },
    potential_issue: { text: 'Potential Issue (Needs Validation)', style: 'bg-purple-950/60 text-purple-300 border border-purple-800/70' },
    no_verified_cve_match: { text: 'No Verified CVE Match', style: 'bg-slate-800/70 text-slate-400 border border-slate-700' },
  };

  const item = labels[status] || { text: status, style: 'bg-slate-800 text-slate-300 border border-slate-700' };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${item.style} ${className}`}>
      {item.text}
    </span>
  );
};

export const WorkflowBadge: React.FC<{ status: WorkflowStatus; className?: string }> = ({ status, className = '' }) => {
  const styles: Record<WorkflowStatus, { text: string; color: string }> = {
    new: { text: 'New', color: 'bg-blue-900/40 text-blue-300 border-blue-700/60' },
    investigating: { text: 'Investigating', color: 'bg-amber-900/40 text-amber-300 border-amber-700/60' },
    confirmed: { text: 'Confirmed', color: 'bg-rose-900/40 text-rose-300 border-rose-700/60' },
    false_positive: { text: 'False Positive', color: 'bg-slate-800 text-slate-400 border-slate-700' },
    accepted_risk: { text: 'Accepted Risk', color: 'bg-purple-900/40 text-purple-300 border-purple-700/60' },
    resolved: { text: 'Resolved', color: 'bg-emerald-900/40 text-emerald-300 border-emerald-700/60' },
  };

  const current = styles[status] || { text: status, color: 'bg-slate-800 text-slate-300 border-slate-700' };

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${current.color} ${className}`}>
      {current.text}
    </span>
  );
};

export const DataSourceBadge: React.FC<{ source: string; className?: string }> = ({ source, className = '' }) => {
  if (source === 'demo') {
    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-amber-900/50 text-amber-300 border border-amber-600/70 ${className}`}>
        SIMULATED DEMO
      </span>
    );
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold bg-cyan-950/60 text-cyan-400 border border-cyan-800/60 ${className}`}>
      LIVE EVIDENCE
    </span>
  );
};

export const StateBadge: React.FC<{ state: string; className?: string }> = ({ state, className = '' }) => {
  const isUp = state.toLowerCase() === 'up' || state.toLowerCase() === 'open';
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border ${
        isUp
          ? 'bg-emerald-950/50 text-emerald-400 border-emerald-800/60'
          : 'bg-slate-800/60 text-slate-400 border-slate-700'
      } ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${isUp ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
      {state.toUpperCase()}
    </span>
  );
};
