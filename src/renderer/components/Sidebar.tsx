import React from 'react';
import { TOOL_CONFIG, GROUP_LABELS, type ViewMode } from '../../shared/view-types';
import { SidebarIcon } from './SidebarIcons';
import './Sidebar.css';

import logoUrl from '../assets/logo.svg';
import launchUrl from '../assets/launch.svg';

interface SidebarProps {
  viewMode: ViewMode;
  onViewModeChange: (mode: ViewMode) => void;
  proxyRunning: boolean;
  proxyPort: number | null;
  launching?: boolean;
  onLaunchBrowser: () => void;
  onOpenSettings?: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({
  viewMode,
  onViewModeChange,
  proxyRunning,
  proxyPort,
  launching = false,
  onLaunchBrowser,
  onOpenSettings,
}) => {
  // Group tools by category
  const groups = TOOL_CONFIG.reduce<{ group: string; tools: typeof TOOL_CONFIG }[]>(
    (acc, tool) => {
      const label = GROUP_LABELS[tool.group];
      const existing = acc.find((g) => g.group === label);
      if (existing) existing.tools.push(tool);
      else acc.push({ group: label, tools: [tool] });
      return acc;
    },
    []
  );

  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <div className="logo">
          <img src={logoUrl} alt="CleanTraffic" className="logo-svg" width={20} height={20} />
        </div>
        <div className="app-name">
          <span className="app-name-main">CleanTraffic</span>
        </div>
      </div>

      {!proxyRunning && (
        <div className="launch-browser-section">
          <button
            type="button"
            className={`launch-browser-btn ${launching ? 'loading' : ''}`}
            onClick={onLaunchBrowser}
            disabled={launching}
            title={launching ? 'Starting…' : 'Start browser'}
            aria-busy={launching}
            aria-label={launching ? 'Starting browser' : 'Start browser for traffic interception'}
          >
            <span className="launch-browser-icon" aria-hidden="true">
              {launching ? (
                <span className="launch-browser-spinner" />
              ) : (
                <img src={launchUrl} alt="" width={18} height={18} className="launch-icon-img" />
              )}
            </span>
          </button>
        </div>
      )}

      <div className="sidebar-section">
        {groups.map(({ group, tools }, groupIdx) => (
          <React.Fragment key={group}>
            {groupIdx > 0 && <div className="sidebar-divider" />}
            {tools.map((tool) => (
              <div
                key={tool.id}
                className={`sidebar-item ${viewMode === tool.id ? 'active' : ''}`}
                onClick={() => onViewModeChange(tool.id)}
                title={tool.label}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onViewModeChange(tool.id);
                  }
                }}
              >
                <SidebarIcon id={tool.id} />
                <span>{tool.label}</span>
              </div>
            ))}
          </React.Fragment>
        ))}
      </div>

      <div className="sidebar-footer">
        <div className="sidebar-status">
          <div className={`status-indicator ${proxyRunning ? 'running' : 'stopped'}`} />
          <div className="status-text">{proxyRunning ? `${proxyPort}` : 'Off'}</div>
        </div>
        {onOpenSettings && (
          <button
            type="button"
            className="sidebar-settings-btn"
            onClick={onOpenSettings}
            title="Settings"
            aria-label="Settings"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
            </svg>
          </button>
        )}
      </div>
    </div>
  );
};

export default Sidebar;
