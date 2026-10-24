import React from 'react';
import { Database, AlertCircle } from 'lucide-react';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description: string;
  action?: React.ReactNode;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon,
  title,
  description,
  action,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-10 text-center bg-slate-900/30 border border-dashed border-slate-800 rounded-lg">
      <div className="p-3 bg-slate-800/80 rounded-full text-slate-400 mb-3 border border-slate-700">
        {icon || <Database className="w-6 h-6" />}
      </div>
      <h4 className="text-base font-semibold text-slate-200 mb-1">{title}</h4>
      <p className="text-xs text-slate-400 max-w-sm mb-4 leading-relaxed">{description}</p>
      {action && <div>{action}</div>}
    </div>
  );
};

export const ErrorBanner: React.FC<{ message: string; onRetry?: () => void }> = ({
  message,
  onRetry,
}) => {
  return (
    <div className="bg-red-950/40 border border-red-800/80 rounded-lg p-4 flex items-start gap-3">
      <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
      <div className="flex-1">
        <h4 className="text-sm font-semibold text-red-300">Operation Error</h4>
        <p className="text-xs text-red-300/80 mt-0.5">{message}</p>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="px-3 py-1 bg-red-900/60 hover:bg-red-800 text-red-200 text-xs font-medium rounded transition-colors"
        >
          Retry
        </button>
      )}
    </div>
  );
};
