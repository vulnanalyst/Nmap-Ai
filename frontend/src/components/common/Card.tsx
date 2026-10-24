import React from 'react';

interface CardProps {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: React.ReactNode;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  headerClassName?: string;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  icon,
  action,
  children,
  className = '',
  headerClassName = '',
}) => {
  const hasHeader = title || subtitle || icon || action;

  return (
    <div className={`bg-[#111827] border border-slate-800 rounded-lg shadow-lg overflow-hidden ${className}`}>
      {hasHeader && (
        <div className={`px-5 py-4 border-b border-slate-800/80 flex items-center justify-between gap-4 ${headerClassName}`}>
          <div className="flex items-center gap-3">
            {icon && <div className="text-cyan-400 p-1.5 bg-slate-900 rounded border border-slate-800">{icon}</div>}
            <div>
              {title && <h3 className="text-sm font-semibold text-slate-100 tracking-wide">{title}</h3>}
              {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
            </div>
          </div>
          {action && <div className="flex items-center gap-2">{action}</div>}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
};
