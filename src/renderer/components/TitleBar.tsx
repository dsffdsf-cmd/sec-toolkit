import React, { useEffect, useState } from 'react';
import './TitleBar.css';

export const TitleBar: React.FC = () => {
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    let mounted = true;
    const refresh = async () => {
      try {
        const res = await window.electronAPI.isWindowMaximized?.();
        if (mounted && res && typeof res.maximized === 'boolean') setMaximized(res.maximized);
      } catch {
        // ignore
      }
    };
    refresh();
    const id = setInterval(refresh, 800);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  return (
    <div className="titlebar">
      <div className="titlebar-left">
        <div className="titlebar-dot" />
        <div className="titlebar-brand">CleanTraffic</div>
      </div>

      <div className="titlebar-center" />

      <div className="titlebar-controls">
        <button className="tb-btn" title="Minimize" onClick={() => window.electronAPI.minimizeWindow?.()}>
          —
        </button>
        <button
          className="tb-btn"
          title={maximized ? 'Restore' : 'Maximize'}
          onClick={async () => {
            const res = await window.electronAPI.toggleMaximizeWindow?.();
            if (res && typeof res.maximized === 'boolean') setMaximized(res.maximized);
          }}
        >
          {maximized ? '❐' : '□'}
        </button>
        <button className="tb-btn tb-close" title="Close" onClick={() => window.electronAPI.closeWindow?.()}>
          ×
        </button>
      </div>
    </div>
  );
};

