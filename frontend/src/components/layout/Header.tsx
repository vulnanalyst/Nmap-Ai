import React from 'react';
import { AlertTriangle, LogOut, Shield } from 'lucide-react';
import { useApp } from '../../context/AppContext';

export const Header: React.FC = () => {
  const { backendOnline, authenticated, logout } = useApp();

  return (
    <header className="sticky top-0 z-40 bg-slate-950 border-b border-slate-800 px-5 py-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-slate-800 text-slate-200">
            <Shield className="h-4 w-4" />
          </div>
          <div className="text-sm font-semibold text-slate-100">Nmap-AI</div>
        </div>

        <div className="flex items-center gap-3">
          <span className={`flex items-center gap-1.5 text-xs ${backendOnline ? 'text-emerald-400' : 'text-red-400'}`}>
            {!backendOnline && <AlertTriangle className="h-3.5 w-3.5" />}
            {backendOnline ? 'API online' : 'API offline'}
          </span>
          {authenticated && (
            <button onClick={logout} className="flex items-center gap-1.5 rounded border border-slate-700 px-2.5 py-1.5 text-xs text-slate-300 hover:bg-slate-800">
              <LogOut className="h-3.5 w-3.5" />
              Sign out
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
