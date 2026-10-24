import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { useApp } from '../../context/AppContext';

export const AppLayout: React.FC = () => {
  const { authenticated, login, toast } = useApp();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username, password);
    } catch (loginError) {
      setError(loginError instanceof Error ? loginError.message : 'Sign in failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Header />
      <div className="flex-1 flex overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto px-6 py-6">
          <div className="max-w-7xl mx-auto">
            {authenticated ? (
              <Outlet />
            ) : (
              <div className="mx-auto mt-16 max-w-sm rounded border border-slate-800 bg-slate-900 p-6">
                <h1 className="text-lg font-semibold">Sign in</h1>
                <p className="mt-1 text-sm text-slate-400">Use the application credentials configured in your local environment.</p>
                <form onSubmit={handleLogin} className="mt-5 space-y-4">
                  <label className="block text-sm text-slate-300">
                    Username
                    <input required autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
                  </label>
                  <label className="block text-sm text-slate-300">
                    Password
                    <input required type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm" />
                  </label>
                  {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
                  <button disabled={submitting} className="w-full rounded bg-slate-700 px-3 py-2 text-sm font-medium hover:bg-slate-600 disabled:opacity-50">
                    {submitting ? 'Signing in…' : 'Sign in'}
                  </button>
                </form>
              </div>
            )}
          </div>
        </main>
      </div>
      {toast && (
        <div role="status" className={`fixed bottom-4 right-4 z-50 max-w-md rounded border px-4 py-3 text-sm ${
          toast.type === 'error' ? 'border-red-800 bg-red-950 text-red-200' :
          toast.type === 'success' ? 'border-emerald-800 bg-emerald-950 text-emerald-200' :
          'border-slate-700 bg-slate-900 text-slate-200'
        }`}>
          {toast.message}
        </div>
      )}
    </div>
  );
};
