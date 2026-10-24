import React from 'react';
import { NavLink } from 'react-router-dom';
import { Activity, FileText, LayoutDashboard, Network, Scan, Settings, ShieldAlert } from 'lucide-react';

const NAV_ITEMS = [
  { name: 'Dashboard', path: '/', icon: LayoutDashboard },
  { name: 'Network Discovery', path: '/topology', icon: Network },
  { name: 'Scan Management', path: '/scans', icon: Scan },
  { name: 'Vulnerability Findings', path: '/vulnerabilities', icon: ShieldAlert },
  { name: 'Live Traffic', path: '/traffic', icon: Activity },
  { name: 'Reports', path: '/reports', icon: FileText },
  { name: 'Settings', path: '/settings', icon: Settings },
];

export const Sidebar: React.FC = () => {
  return (
    <aside className="w-60 shrink-0 bg-slate-950 border-r border-slate-800 min-h-[calc(100vh-57px)] flex flex-col py-4">
      <div className="space-y-1 px-3">
        <nav className="space-y-1">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded text-sm font-medium ${
                    isActive
                      ? 'bg-slate-800 text-slate-100'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
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
    </aside>
  );
};
