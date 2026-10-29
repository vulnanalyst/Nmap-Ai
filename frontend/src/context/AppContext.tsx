import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { ApiError, api, getAuthToken, removeAuthToken } from '../services/api';
import type { SettingsData } from '../types';

interface Toast {
  message: string;
  type: 'success' | 'error' | 'info';
}

interface AppContextValue {
  settings: SettingsData | null;
  refreshSettings: () => Promise<void>;
  backendOnline: boolean;
  authenticated: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  toast: Toast | null;
  showToast: (message: string, type?: 'success' | 'error' | 'info') => void;
}

const AppContext = createContext<AppContextValue | undefined>(undefined);

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [authenticated, setAuthenticated] = useState(() => Boolean(getAuthToken()));
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [backendOnline, setBackendOnline] = useState<boolean>(false);
  const [toast, setToast] = useState<Toast | null>(null);

  const showToast = useCallback((message: string, type: 'success' | 'error' | 'info' = 'info') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast((curr) => (curr?.message === message ? null : curr));
    }, 4000);
  }, []);

  const refreshSettings = useCallback(async () => {
    try {
      const data = await api.getSettings();
      setSettings(data);
      setAuthenticated(true);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        removeAuthToken();
        setSettings(null);
        setAuthenticated(false);
      }
    }
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    await api.login(username, password);
    setAuthenticated(true);
    await refreshSettings();
  }, [refreshSettings]);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } finally {
      removeAuthToken();
      setAuthenticated(false);
      setSettings(null);
    }
  }, []);

  useEffect(() => {
    const refreshHealth = async () => {
      try {
        await api.checkHealth();
        setBackendOnline(true);
      } catch {
        setBackendOnline(false);
      }
    };
    refreshHealth();
    const interval = setInterval(refreshHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!authenticated) return;
    refreshSettings();
    const interval = setInterval(refreshSettings, 15000);
    return () => clearInterval(interval);
  }, [authenticated, refreshSettings]);

  return (
    <AppContext.Provider
      value={{
        settings,
        refreshSettings,
        backendOnline,
        authenticated,
        login,
        logout,
        toast,
        showToast,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export function useApp(): AppContextValue {
  const context = useContext(AppContext);
  if (!context) {
    throw new Error('useApp must be used within an AppProvider');
  }
  return context;
}
