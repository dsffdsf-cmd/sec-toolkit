import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import type { IntegrationConfig } from '../../shared/integration-config';
import { DEFAULT_INTEGRATION_CONFIG, mergeIntegrationConfig } from '../../shared/integration-config';

export type Theme = 'dark' | 'light';
export type FontSize = 'small' | 'medium' | 'large';

export interface Settings {
  theme: Theme;
  fontSize: FontSize;
  compactList: boolean;
  highContrast: boolean;
}

interface SettingsContextType {
  settings: Settings;
  setTheme: (theme: Theme) => void;
  setFontSize: (fontSize: FontSize) => void;
  setCompactList: (compact: boolean) => void;
  setHighContrast: (high: boolean) => void;
  integration: IntegrationConfig;
  setIntegration: (next: Partial<IntegrationConfig>) => void;
}

const defaultSettings: Settings = {
  theme: 'dark',
  fontSize: 'medium',
  compactList: false,
  highContrast: false,
};

const SettingsContext = createContext<SettingsContextType | undefined>(undefined);

const STORAGE_KEY = 'cleantraffic-settings';
const INTEGRATION_KEY = 'cleantraffic-integration';

function loadSettings(): Settings {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      return {
        theme: parsed.theme || defaultSettings.theme,
        fontSize: parsed.fontSize || defaultSettings.fontSize,
        compactList: parsed.compactList ?? defaultSettings.compactList,
        highContrast: parsed.highContrast ?? defaultSettings.highContrast,
      };
    }
  } catch {
    // Ignore parse errors
  }
  return defaultSettings;
}

function loadIntegration(): IntegrationConfig {
  try {
    const stored = localStorage.getItem(INTEGRATION_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      return mergeIntegrationConfig(parsed);
    }
  } catch {
    // Ignore parse errors
  }
  return { ...DEFAULT_INTEGRATION_CONFIG };
}

function saveSettings(settings: Settings): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  } catch {
    // Ignore storage errors
  }
}

function saveIntegration(config: IntegrationConfig): void {
  try {
    localStorage.setItem(INTEGRATION_KEY, JSON.stringify(config));
  } catch {
    // Ignore storage errors
  }
}

function applySettingsToDocument(settings: Settings): void {
  if (typeof document === 'undefined') return;
  document.documentElement.setAttribute('data-theme', settings.theme);
  document.documentElement.setAttribute('data-font-size', settings.fontSize);
  if (settings.compactList) document.documentElement.setAttribute('data-compact', 'true');
  else document.documentElement.removeAttribute('data-compact');
  if (settings.highContrast) document.documentElement.setAttribute('data-high-contrast', 'true');
  else document.documentElement.removeAttribute('data-high-contrast');
}

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Settings>(() => {
    const s = loadSettings();
    applySettingsToDocument(s);
    return s;
  });
  const [integration, setIntegrationState] = useState<IntegrationConfig>(loadIntegration);

  useEffect(() => {
    saveSettings(settings);
    applySettingsToDocument(settings);
  }, [settings]);

  useEffect(() => {
    saveIntegration(integration);
    if (typeof window !== 'undefined' && window.electronAPI?.saveIntegrationConfig) {
      window.electronAPI.saveIntegrationConfig(integration).catch(() => {});
    }
  }, [integration]);

  useEffect(() => {
    if (typeof window === 'undefined' || !window.electronAPI?.getIntegrationConfig) return;
    let cancelled = false;
    window.electronAPI.getIntegrationConfig().then((fromMain) => {
      if (cancelled || fromMain == null) return;
      const merged = mergeIntegrationConfig(fromMain);
      const hasPersisted =
        Boolean((merged.githubToken ?? '').trim()) ||
        Boolean((merged.webhookUrl ?? '').trim());
      if (hasPersisted) setIntegrationState(merged);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, []);

  const setTheme = useCallback((theme: Theme) => {
    setSettings((prev) => ({ ...prev, theme }));
  }, []);

  const setFontSize = useCallback((fontSize: FontSize) => {
    setSettings((prev) => ({ ...prev, fontSize }));
  }, []);

  const setCompactList = useCallback((compactList: boolean) => {
    setSettings((prev) => ({ ...prev, compactList }));
  }, []);

  const setHighContrast = useCallback((highContrast: boolean) => {
    setSettings((prev) => ({ ...prev, highContrast }));
  }, []);

  const setIntegration = useCallback((next: Partial<IntegrationConfig>) => {
    setIntegrationState((prev) => mergeIntegrationConfig({ ...prev, ...next }));
  }, []);

  return (
    <SettingsContext.Provider
      value={{
        settings,
        setTheme,
        setFontSize,
        setCompactList,
        setHighContrast,
        integration,
        setIntegration,
      }}
    >
      {children}
    </SettingsContext.Provider>
  );
}

export function useSettings(): SettingsContextType {
  const context = useContext(SettingsContext);
  if (!context) {
    throw new Error('useSettings must be used within a SettingsProvider');
  }
  return context;
}
