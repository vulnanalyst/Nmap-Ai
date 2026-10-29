import React from 'react';
import { Outlet } from 'react-router-dom';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { useApp } from '../../context/AppContext';

export const AppLayout: React.FC = () => {
  const { toast } = useApp();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Header />
      <div className="flex-1 flex overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto px-6 py-6">
          <div className="max-w-7xl mx-auto">
            <Outlet />
          </div>
        </main>
      </div>
      {toast && (
        <div
          role="status"
          className={`fixed bottom-4 right-4 z-50 max-w-md rounded border px-4 py-3 text-sm shadow-xl ${
            toast.type === 'error'
              ? 'border-red-800 bg-red-950 text-red-200'
              : toast.type === 'success'
              ? 'border-emerald-800 bg-emerald-950 text-emerald-200'
              : 'border-slate-700 bg-slate-900 text-slate-200'
          }`}
        >
          {toast.message}
        </div>
      )}
    </div>
  );
};
