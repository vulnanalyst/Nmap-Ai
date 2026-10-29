import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  AlertCircle,
  Eye,
  EyeOff,
  Loader2,
  Lock,
  Radio,
  Server,
  Shield,
  User,
} from 'lucide-react';
import { useApp } from '../context/AppContext';

export const LoginPage: React.FC = () => {
  const { authenticated, login, backendOnline } = useApp();
  const navigate = useNavigate();
  const location = useLocation();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Field-level validation states
  const [usernameTouched, setUsernameTouched] = useState(false);
  const [passwordTouched, setPasswordTouched] = useState(false);

  const destination = (location.state as { from?: string } | null)?.from || '/';

  // Redirect if already authenticated
  useEffect(() => {
    if (authenticated) {
      navigate(destination, { replace: true });
    }
  }, [authenticated, navigate, destination]);

  const usernameError =
    usernameTouched && !username.trim() ? 'Operator ID or username is required.' : null;
  const passwordError =
    passwordTouched && !password ? 'Password is required.' : null;

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setUsernameTouched(true);
    setPasswordTouched(true);

    const cleanUser = username.trim();
    if (!cleanUser || !password) {
      setError('Please provide both username and password.');
      return;
    }

    setError(null);
    setSubmitting(true);

    try {
      await login(cleanUser, password);
      navigate(destination, { replace: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Authentication failed. Please verify credentials.';
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="relative min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center px-4 py-12 selection:bg-emerald-500 selection:text-slate-950 font-sans">
      {/* Background cyber ambient glow */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[700px] h-[400px] bg-emerald-500/10 blur-[120px] rounded-full" />
        <div className="absolute -bottom-40 left-1/2 -translate-x-1/2 w-[600px] h-[350px] bg-cyan-500/10 blur-[140px] rounded-full" />
        <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-30" />
      </div>

      <div className="relative w-full max-w-md">
        {/* Branding header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700/80 shadow-lg shadow-emerald-950/40 text-emerald-400 mb-3 ring-1 ring-emerald-500/20">
            <Shield className="w-7 h-7" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center justify-center gap-2">
            Nmap-AI <span className="text-xs font-mono font-normal uppercase px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">SecOps</span>
          </h1>
          <p className="mt-1 text-xs text-slate-400 tracking-wide">
            Automated Network Reconnaissance & Security Telemetry
          </p>
        </div>

        {/* Security badge / system status */}
        <div className="mb-4 flex items-center justify-between px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/60 backdrop-blur-sm text-xs">
          <span className="flex items-center gap-1.5 text-slate-400 font-mono">
            <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            CONSOLE // RESTRICTED ACCESS
          </span>
          <span className={`inline-flex items-center gap-1.5 font-medium ${backendOnline ? 'text-emerald-400' : 'text-red-400'}`}>
            <Server className="w-3 h-3" />
            {backendOnline ? 'API Gateway Live' : 'API Gateway Offline'}
          </span>
        </div>

        {/* Login form card */}
        <div className="rounded-xl border border-slate-800/90 bg-slate-900/90 backdrop-blur-xl p-6 sm:p-7 shadow-2xl shadow-black/80">
          <div className="mb-5 border-b border-slate-800/70 pb-3">
            <h2 className="text-base font-semibold text-slate-100">Operator Authentication</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Enter your provisioned lab credentials to access the intelligence platform.
            </p>
          </div>

          {/* Error Banner */}
          {error && (
            <div
              role="alert"
              className="mb-5 flex items-start gap-2.5 rounded-lg border border-red-900/80 bg-red-950/60 px-3.5 py-2.5 text-xs text-red-200"
            >
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div className="flex-1 leading-relaxed">
                <span className="font-semibold block text-red-300">Access Denied</span>
                {error}
              </div>
            </div>
          )}

          <form onSubmit={handleSubmit} noValidate className="space-y-4">
            {/* Username / Operator ID Field */}
            <div>
              <label
                htmlFor="username"
                className="block text-xs font-medium text-slate-300 mb-1.5"
              >
                Operator ID / Username
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                  <User className="h-4 w-4" />
                </div>
                <input
                  id="username"
                  name="username"
                  type="text"
                  autoComplete="username"
                  required
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                    if (error) setError(null);
                  }}
                  onBlur={() => setUsernameTouched(true)}
                  aria-invalid={Boolean(usernameError)}
                  aria-describedby={usernameError ? 'username-error' : undefined}
                  placeholder="e.g. lab"
                  className={`w-full rounded-lg border bg-slate-950/90 py-2 pl-9 pr-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 transition-colors ${
                    usernameError
                      ? 'border-red-500/80 focus:border-red-500 focus:ring-red-500/50'
                      : 'border-slate-700/80 focus:border-emerald-500 focus:ring-emerald-500/50'
                  }`}
                />
              </div>
              {usernameError && (
                <p id="username-error" role="alert" className="mt-1 text-xs text-red-400">
                  {usernameError}
                </p>
              )}
            </div>

            {/* Password Field */}
            <div>
              <label
                htmlFor="password"
                className="block text-xs font-medium text-slate-300 mb-1.5"
              >
                Security Password
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                  <Lock className="h-4 w-4" />
                </div>
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (error) setError(null);
                  }}
                  onBlur={() => setPasswordTouched(true)}
                  aria-invalid={Boolean(passwordError)}
                  aria-describedby={passwordError ? 'password-error' : undefined}
                  placeholder="••••••••••••"
                  className={`w-full rounded-lg border bg-slate-950/90 py-2 pl-9 pr-10 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 transition-colors ${
                    passwordError
                      ? 'border-red-500/80 focus:border-red-500 focus:ring-red-500/50'
                      : 'border-slate-700/80 focus:border-emerald-500 focus:ring-emerald-500/50'
                  }`}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute inset-y-0 right-0 flex items-center pr-3 text-slate-400 hover:text-slate-200 focus:outline-none focus:text-slate-200"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {passwordError && (
                <p id="password-error" role="alert" className="mt-1 text-xs text-red-400">
                  {passwordError}
                </p>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={submitting || !username.trim() || !password}
              className="w-full mt-2 flex items-center justify-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 px-4 py-2.5 text-sm font-semibold text-slate-950 shadow-md shadow-emerald-950/40 transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2 focus:ring-offset-slate-900"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-slate-950" />
                  <span>Verifying Credentials…</span>
                </>
              ) : (
                <span>Authenticate Session</span>
              )}
            </button>
          </form>

          {/* Lab note: Login only */}
          <div className="mt-5 pt-4 border-t border-slate-800/70 text-center">
            <p className="text-[11px] text-slate-400 leading-relaxed">
              <span className="font-semibold text-slate-300">Login-Only Application:</span> Public registration and account self-enrollment are disabled. Credentials and scanner tokens are provisioned by system administrators in the local environment (<code className="font-mono text-slate-300">.env</code>).
            </p>
          </div>
        </div>

        {/* Security footer badges */}
        <div className="mt-6 flex flex-wrap items-center justify-center gap-3 text-[11px] font-mono text-slate-400">
          <span>AES-256 / SHA-256</span>
          <span>•</span>
          <span>NIST SP 800-63B ALIGNED</span>
          <span>•</span>
          <span>RATE-LIMITED GATEWAY</span>
        </div>
      </div>
    </div>
  );
};
