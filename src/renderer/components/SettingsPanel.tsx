import React, { useState } from 'react';
import { useSettings } from '../context/SettingsContext';
import type { Theme, FontSize } from '../context/SettingsContext';
import './SettingsPanel.css';

interface SettingsPanelProps {
  onClose: () => void;
}

type SettingsTab = 'appearance' | 'integrations';

export function SettingsPanel({ onClose }: SettingsPanelProps) {
  const {
    settings,
    setTheme,
    setFontSize,
    setCompactList,
    setHighContrast,
    integration,
    setIntegration,
  } = useSettings();
  const [tab, setTab] = useState<SettingsTab>('appearance');

  return (
    <div className="settings-panel-overlay" onClick={onClose} role="presentation">
      <div className="settings-panel settings-panel-wide" onClick={(e) => e.stopPropagation()} role="dialog" aria-labelledby="settings-title">
        <div className="settings-panel-header">
          <h2 id="settings-title">Settings</h2>
          <button type="button" className="settings-panel-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        <div className="settings-tabs">
          {(['appearance', 'integrations'] as const).map((t) => (
            <button
              key={t}
              type="button"
              className={`settings-tab ${tab === t ? 'active' : ''}`}
              onClick={() => setTab(t)}
            >
              {t === 'appearance' ? 'Appearance' : 'Integrations'}
            </button>
          ))}
        </div>
        <div className="settings-panel-body">
          {tab === 'appearance' && (
            <>
              <div className="settings-group">
                <label className="settings-label">Theme</label>
                <div className="settings-options">
                  {(['dark', 'light'] as Theme[]).map((t) => (
                    <button
                      key={t}
                      type="button"
                      className={`settings-option ${settings.theme === t ? 'active' : ''}`}
                      onClick={() => setTheme(t)}
                    >
                      {t === 'dark' ? 'Dark' : 'Light'}
                    </button>
                  ))}
                </div>
              </div>
              <div className="settings-group">
                <label className="settings-label">Font size</label>
                <div className="settings-options">
                  {(['small', 'medium', 'large'] as FontSize[]).map((f) => (
                    <button
                      key={f}
                      type="button"
                      className={`settings-option ${settings.fontSize === f ? 'active' : ''}`}
                      onClick={() => setFontSize(f)}
                    >
                      {f === 'small' ? 'Small' : f === 'medium' ? 'Medium' : 'Large'}
                    </button>
                  ))}
                </div>
              </div>
              <div className="settings-group">
                <label className="settings-toggle-row">
                  <span className="settings-label">Compact request list</span>
                  <input
                    type="checkbox"
                    checked={settings.compactList}
                    onChange={(e) => setCompactList(e.target.checked)}
                    className="settings-checkbox"
                  />
                </label>
              </div>
              <div className="settings-group">
                <label className="settings-toggle-row">
                  <span className="settings-label">High contrast (accessibility)</span>
                  <input
                    type="checkbox"
                    checked={settings.highContrast}
                    onChange={(e) => setHighContrast(e.target.checked)}
                    className="settings-checkbox"
                  />
                </label>
              </div>
            </>
          )}

          {tab === 'integrations' && (
            <>
              <div className="settings-group">
                <label className="settings-label">GitHub token (optional – private repos, rate limits)</label>
                <input
                  type="password"
                  className="settings-input"
                  placeholder="ghp_..."
                  value={integration.githubToken}
                  onChange={(e) => setIntegration({ githubToken: e.target.value })}
                  autoComplete="off"
                />
              </div>
              <div className="settings-group">
                <label className="settings-label">Webhook URL (optional – scan results to Slack/Discord)</label>
                <input
                  type="url"
                  className="settings-input"
                  placeholder="https://..."
                  value={integration.webhookUrl}
                  onChange={(e) => setIntegration({ webhookUrl: e.target.value })}
                  autoComplete="off"
                />
              </div>
              <div className="settings-group">
                <label className="settings-label">Semgrep Cloud token (optional – future)</label>
                <input
                  type="password"
                  className="settings-input"
                  placeholder="..."
                  value={integration.semgrepCloudToken}
                  onChange={(e) => setIntegration({ semgrepCloudToken: e.target.value })}
                  autoComplete="off"
                />
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
