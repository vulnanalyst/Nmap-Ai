import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Network,
  Scan,
  ShieldAlert,
  Bell,
  Activity,
  Cpu,
  Zap,
  FileText,
  Settings,
} from 'lucide-react';

const NAV_ITEMS = [
  { name: 'Executive Overview', path: '/', icon: LayoutDashboard },
  { name: 'Discovery & Topology', path: '/topology', icon: Network },
  { name: 'Scan Management', path: '/scans', icon: Scan },
  { name: 'Vulnerability Intel', path: '/vulnerabilities', icon: ShieldAlert },
  { name: 'Threat Alerts', path: '/alerts', icon: Bell },
  { name: 'Live Traffic Monitor', path: '/traffic', icon: Activity },
  { name: 'AI / ML Lab', path: '/ml', icon: Cpu },
  { name: 'Explainable Risk', path: '/risk', icon: Zap },
  { name: 'Evidence Reports', path: '/reports', icon: FileText },
  { name: 'Lab Settings', path: '/settings', icon: Settings },
];

export const Sidebar: React.FC = () => {
  return (
    <aside className="w-64 shrink-0 bg-[#0c101c] border-r border-slate-800/80 min-h-[calc(100vh-57px)] flex flex-col justify-between py-4">
      <div className="space-y-1 px-3">
        <div className="px-3 pb-2 pt-1 text-[11px] font-semibold tracking-wider text-slate-500 uppercase font-mono">
          Security Intelligence
        </div>
        <nav className="space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800/60 shadow-sm shadow-cyan-950/50'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                  }`
                }
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span>{item.name}</span>
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Lab Environment Info Footer */}
      <div className="px-4 pt-4 border-t border-slate-800/80 text-[11px] text-slate-500">
        <div className="font-mono text-[10px] text-slate-400 font-semibold mb-1">AUTHORIZED LAB</div>
        <div className="text-slate-400">Strict Provenance Engine</div>
        <div className="text-[10px] text-slate-500 mt-1 font-mono">FastAPI + Vite SOC Stack</div>
      </div>
    </aside>
  );
};
