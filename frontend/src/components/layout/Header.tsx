import React from 'react';
import { Shield, Radio, Terminal, Monitor, Sparkles, CheckCircle2, AlertTriangle } from 'lucide-react';
import { useApp } from '../../context/AppContext';

export const Header: React.FC = () => {
  const { demoMode, setDemoMode, settings, backendOnline, toast } = useApp();

  const scannerText = settings?.scanner_name
    ? `${settings.scanner_name}${settings.scanner_ip ? ` (${settings.scanner_ip})` : ''}`
    : settings?.placeholders?.scanner || 'Kali Scanner: Unconfigured';

  const targetText = settings?.target_name
    ? `${settings.target_name}${settings.target_ip ? ` (${settings.target_ip})` : ''}`
    : settings?.placeholders?.target || 'Target: Unconfigured';

  return (
    <header className="sticky top-0 z-40 bg-[#0d121f]/95 backdrop-blur-md border-b border-slate-800 px-6 py-3">
      <div className="flex items-center justify-between gap-4">
        {/* Lab Entities & Status */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <div>
              <span className="text-xs font-bold tracking-wider text-cyan-400 uppercase">Nmap-AI Platform</span>
              <div className="text-[10px] text-slate-400 font-mono">SOC / LAB INTELLIGENCE</div>
            </div>
          </div>

          <div className="h-5 w-px bg-slate-800 mx-1 hidden sm:block" />

          {/* Scanner Tag */}
          <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">Scanner:</span>
            <span className={`font-mono text-xs ${settings?.scanner_ip ? 'text-slate-200' : 'text-slate-400 italic'}`}>
              {scannerText}
            </span>
          </div>

          {/* Target Tag */}
          <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs">
            <Monitor className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-slate-400">Target:</span>
            <span className={`font-mono text-xs ${settings?.target_ip ? 'text-slate-200' : 'text-slate-400 italic'}`}>
              {targetText}
            </span>
          </div>
        </div>

        {/* Global Controls & Mode Switch */}
        <div className="flex items-center gap-3">
          {/* Backend Health */}
          <div className="flex items-center gap-1.5 text-xs text-slate-300">
            {backendOnline ? (
              <span className="flex items-center gap-1 text-emerald-400 bg-emerald-950/40 border border-emerald-800/60 px-2 py-0.5 rounded text-[11px]">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                API ONLINE
              </span>
            ) : (
              <span className="flex items-center gap-1 text-red-400 bg-red-950/40 border border-red-800/60 px-2 py-0.5 rounded text-[11px]">
                <AlertTriangle className="w-3 h-3" />
                API OFFLINE
              </span>
            )}
          </div>

          {/* Mode Switch: Live Evidence vs Demo Fixtures */}
          <button
            onClick={() => setDemoMode(!demoMode)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-semibold tracking-wide border transition-all ${
              demoMode
                ? 'bg-amber-950/70 border-amber-500/80 text-amber-300 hover:bg-amber-900/60 shadow-lg shadow-amber-950/40'
                : 'bg-cyan-950/50 border-cyan-500/70 text-cyan-300 hover:bg-cyan-900/50 shadow-lg shadow-cyan-950/40'
            }`}
            title="Toggle between Live Evidence Mode and Demo Fixture Mode"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>{demoMode ? 'DEMO MODE: ACTIVE' : 'LIVE EVIDENCE MODE'}</span>
            <span className="text-[10px] px-1 py-0.2 rounded bg-black/40 font-mono">
              {demoMode ? 'SIMULATED' : 'STRICT'}
            </span>
          </button>
        </div>
      </div>

      {/* Global Floating Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 animate-in slide-in-from-bottom duration-200">
          <div
            className={`px-4 py-3 rounded-lg shadow-2xl border flex items-center gap-3 max-w-md ${
              toast.type === 'error'
                ? 'bg-red-950 border-red-800 text-red-200'
                : toast.type === 'success'
                ? 'bg-emerald-950 border-emerald-800 text-emerald-200'
                : 'bg-slate-900 border-cyan-800 text-cyan-200'
            }`}
          >
            {toast.type === 'success' ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : toast.type === 'error' ? (
              <AlertTriangle className="w-4 h-4 text-red-400" />
            ) : (
              <Radio className="w-4 h-4 text-cyan-400" />
            )}
            <span className="text-xs font-medium">{toast.message}</span>
          </div>
        </div>
      )}
    </header>
  );
};
