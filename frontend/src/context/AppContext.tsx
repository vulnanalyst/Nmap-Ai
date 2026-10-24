import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { api } from '../services/api';
import type { SettingsData } from '../types';

interface Toast {
  message: string;
  type: 'success' | 'error' | 'info';
}

interface AppContextValue {
  demoMode: boolean;
  setDemoMode: (val: boolean) => void;
  settings: SettingsData | null;
  refreshSettings: () => Promise<void>;
  backendOnline: boolean;
  toast: Toast | null;
  showToast: (message: string, type?: 'success' | 'error' | 'info') => void;
}

const AppContext = createContext<AppContextValue | undefined>(undefined);

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [demoMode, setDemoModeState] = useState<boolean>(() => {
    return localStorage.getItem('nmap_ai_demo_mode') === 'true';
  });
  const [settings, setSettings] = useState<SettingsData | null>(null);
  const [backendOnline, setBackendOnline] = useState<boolean>(true);
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
      setBackendOnline(true);
    } catch {
      setBackendOnline(false);
    }
  }, []);

  const setDemoMode = useCallback((val: boolean) => {
    setDemoModeState(val);
    localStorage.setItem('nmap_ai_demo_mode', val ? 'true' : 'false');
    showToast(val ? 'Demo Mode enabled (showing simulated lab fixtures)' : 'Live Evidence Mode active (real records only)', 'info');
  }, [showToast]);

  useEffect(() => {
    refreshSettings();
    const interval = setInterval(refreshSettings, 15000);
    return () => clearInterval(interval);
  }, [refreshSettings]);

  return (
    <AppContext.Provider
      value={{
        demoMode,
        setDemoMode,
        settings,
        refreshSettings,
        backendOnline,
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
