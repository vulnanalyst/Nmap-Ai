import React from 'react';

export const LoadingSkeleton: React.FC<{ rows?: number; height?: string }> = ({
  rows = 4,
  height = 'h-12',
}) => {
  return (
    <div className="space-y-3 w-full animate-pulse">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className={`w-full ${height} bg-slate-800/60 rounded border border-slate-750`} />
      ))}
    </div>
  );
};

export const CardSkeleton: React.FC = () => {
  return (
    <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 animate-pulse">
      <div className="h-4 bg-slate-800 rounded w-1/3 mb-4" />
      <div className="h-8 bg-slate-800/80 rounded w-1/2 mb-3" />
      <div className="h-3 bg-slate-800/40 rounded w-2/3" />
    </div>
  );
};
