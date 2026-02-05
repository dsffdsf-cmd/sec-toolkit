import React, { useState, useEffect, useRef, useCallback } from 'react';
import { HttpRequest } from '../main/proxy-server';
import { TOOL_CONFIG, type ViewMode } from '../shared/view-types';
import Sidebar from './components/Sidebar';
import RequestList from './components/RequestList';
import DetailsView from './components/DetailsView';
import Repeater from './components/Repeater';
import ScannerView from './components/ScannerView';
import JWTDecoder from './components/JWTDecoder';
import NotesTagsView from './components/NotesTagsView';
import ResponseDiff from './components/ResponseDiff';
import Intruder from './components/Intruder';
import Sequencer from './components/Sequencer';
import Extractor from './components/Extractor';
import ResponseAnalyzer from './components/ResponseAnalyzer';
import GitHubScanner from './components/GitHubScanner';
import Web3Tools from './components/Web3Tools';
import { TitleBar } from './components/TitleBar';
import { ErrorBoundary } from './components/ErrorBoundary';
import { SettingsPanel } from './components/SettingsPanel';
import { CommandPalette, type CommandPaletteAction } from './components/CommandPalette';
import { getContentTypeColor } from './components/DetailsView';
import { useToast } from './context/ToastContext';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
import './App.css';

function App() {
  const [requests, setRequests] = useState<HttpRequest[]>([]);
  const [selectedRequest, setSelectedRequest] = useState<HttpRequest | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('view');
  const [proxyRunning, setProxyRunning] = useState(false);
  const [proxyPort, setProxyPort] = useState<number | null>(null);
  const [browserReady, setBrowserReady] = useState(false);
  const [launching, setLaunching] = useState(false);
  const [diffRequest1, setDiffRequest1] = useState<HttpRequest | null>(null);
  const [diffRequest2, setDiffRequest2] = useState<HttpRequest | null>(null);
  const [showDiff, setShowDiff] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showCommandPalette, setShowCommandPalette] = useState(false);
  const [listPanelWidth, setListPanelWidth] = useState(340);
  const [isResizing, setIsResizing] = useState(false);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const resizeRef = useRef<{ startX: number; startWidth: number } | null>(null);
  const toast = useToast();

  // Resizable panel handlers
  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
    resizeRef.current = { startX: e.clientX, startWidth: listPanelWidth };
  }, [listPanelWidth]);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing || !resizeRef.current) return;
      const delta = e.clientX - resizeRef.current.startX;
      const newWidth = Math.max(200, Math.min(600, resizeRef.current.startWidth + delta));
      setListPanelWidth(newWidth);
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      resizeRef.current = null;
    };

    if (isResizing) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = 'col-resize';
      document.body.style.userSelect = 'none';
    }

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
  }, [isResizing]);

  const handleLaunchBrowser = async () => {
    if (launching) return;
    setLaunching(true);
    try {
      const result = await window.electronAPI.startProxy();
      if (result.success) {
        setProxyRunning(true);
        setProxyPort(result.port ?? null);
        setBrowserReady(true);
        toast.success('Browser launched – traffic interception active');
      } else {
        const err = (result as { error?: string }).error || 'Unknown error';
        toast.error(`Launch failed: ${err}`);
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      toast.error(`Launch failed: ${msg}`);
    } finally {
      setLaunching(false);
    }
  };

  const focusSearch = useCallback(() => {
    searchInputRef.current?.focus();
  }, []);

  const handleQuickSave = useCallback(async () => {
    try {
      const res = await window.electronAPI.saveSessionDialog?.(requests);
      if (res?.success) toast.success('Session saved');
      else if (res && !(res as { canceled?: boolean }).canceled)
        toast.error((res as { error?: string }).error || 'Save failed');
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : 'Save failed');
    }
  }, [requests, toast]);

  const closeDiff = useCallback(() => {
    setShowDiff(false);
    setDiffRequest1(null);
    setDiffRequest2(null);
  }, []);

  useKeyboardShortcuts(
    [
      { key: 'k', ctrl: true, allowInInput: true, handler: () => setShowCommandPalette((v) => !v) },
      { key: 'r', ctrl: true, handler: () => setViewMode('repeater') },
      { key: 'f', ctrl: true, allowInInput: true, handler: focusSearch },
      { key: 's', ctrl: true, handler: handleQuickSave },
      {
        key: 'Escape',
        handler: () => {
          if (showCommandPalette) setShowCommandPalette(false);
          else if (showDiff) closeDiff();
          else if (showSettings) setShowSettings(false);
        },
      },
    ],
    true
  );

  useEffect(() => {
    const cleanup = window.electronAPI.onRequestUpdate((newRequests: HttpRequest[]) => {
      setRequests(newRequests);
    });

    (async () => {
      try {
        const initial = await window.electronAPI.getRequests();
        setRequests(initial);
      } catch (_) {}
    })();

    return cleanup;
  }, []);

  // Keep selectedRequest in sync with requests array so we don't hold a stale ref.
  // Detail views are memoized by request id+content so they won't re-render when only new requests are added.
  useEffect(() => {
    setSelectedRequest((prev) => {
      if (!prev) return null;
      const found = requests.find((r) => r.id === prev!.id);
      return found ?? prev;
    });
  }, [requests]);

  const handleRequestSelect = (request: HttpRequest) => {
    setSelectedRequest(request);
    // Don't change viewMode if already in repeater or scanner
    if (viewMode === 'view') {
      setViewMode('view');
    }
  };

  const handleSendToRepeater = (request: HttpRequest) => {
    setSelectedRequest(request);
    setViewMode('repeater');
  };

  const handleViewModeChange = (mode: ViewMode) => {
    setViewMode(mode);
    // If switching to repeater/scanner without a selected request, keep current request
    // If switching to view, keep current request
  };

  const handleSendToScanner = async (request: HttpRequest) => {
    setSelectedRequest(request);
    setViewMode('scanner');
    await window.electronAPI.sendToScanner(request);
  };

  const handleCompareRequests = (request1: HttpRequest, request2: HttpRequest) => {
    setDiffRequest1(request1);
    setDiffRequest2(request2);
    setShowDiff(true);
  };

  const handleSendToIntruder = (request: HttpRequest) => {
    setSelectedRequest(request);
    setViewMode('intruder');
  };

  const handleCompareWith = useCallback((request: HttpRequest, as: 'A' | 'B') => {
    if (as === 'A') {
      setDiffRequest1(request);
    } else {
      setDiffRequest2(request);
      setShowDiff(true);
    }
  }, []);

  const viewLabels = TOOL_CONFIG.map((t) => ({ id: t.id, label: t.label }));

  const handleCommandAction = useCallback(
    async (action: CommandPaletteAction) => {
      if (action.type === 'view') {
        setViewMode(action.id as ViewMode);
      } else if (action.type === 'save-session') {
        await handleQuickSave();
      } else if (action.type === 'export-har') {
        try {
          const res = await window.electronAPI.exportToHARDialog?.(requests);
          if (res?.success && res.filePath) toast.success('HAR exported');
          else if (res && !res.canceled) toast.error(res.error || 'Export failed');
        } catch (e: unknown) {
          toast.error(e instanceof Error ? e.message : 'Export failed');
        }
      } else if (action.type === 'export-postman') {
        try {
          const res = await window.electronAPI.exportToPostmanDialog?.(requests);
          if (res?.success && res.filePath) toast.success('Postman collection exported');
          else if (res && !res.canceled) toast.error(res.error || 'Export failed');
        } catch (e: unknown) {
          toast.error(e instanceof Error ? e.message : 'Export failed');
        }
      } else if (action.type === 'settings') {
        setShowSettings(true);
      }
    },
    [requests, toast]
  );

  return (
    <div className="app-shell">
      {showSettings && <SettingsPanel onClose={() => setShowSettings(false)} />}
      <CommandPalette
        open={showCommandPalette}
        onClose={() => setShowCommandPalette(false)}
        onAction={handleCommandAction}
        viewLabels={viewLabels}
        canSaveSession={requests.length > 0}
        canExportHar={requests.length > 0}
        canExportPostman={requests.length > 0}
      />
      <ErrorBoundary label="App">
        <TitleBar />
        <div className="app">
          <Sidebar
          viewMode={viewMode}
          onViewModeChange={handleViewModeChange}
          proxyRunning={proxyRunning}
          proxyPort={proxyPort}
          launching={launching}
          onLaunchBrowser={handleLaunchBrowser}
          onOpenSettings={() => setShowSettings(true)}
        />
        <div className="main-content">
          <div className="list-panel" style={{ width: listPanelWidth, minWidth: 200, maxWidth: 600 }}>
            <RequestList
              requests={requests}
              selectedRequest={selectedRequest}
              onRequestSelect={handleRequestSelect}
              onSendToRepeater={handleSendToRepeater}
              onSendToScanner={handleSendToScanner}
              onSendToIntruder={handleSendToIntruder}
              onCompareWith={handleCompareWith}
              getContentTypeColor={getContentTypeColor}
              searchInputRef={searchInputRef}
            />
          </div>
          <div 
            className={`resize-handle ${isResizing ? 'active' : ''}`}
            onMouseDown={handleResizeStart}
            title="Drag to resize"
          />
          <div className="details-pane">
            {showDiff && diffRequest1 && diffRequest2 ? (
              <ResponseDiff
                request1={diffRequest1}
                request2={diffRequest2}
                onClose={closeDiff}
              />
            ) : viewMode === 'jwt-decoder' ? (
              <JWTDecoder />
            ) : viewMode === 'github-scanner' ? (
              <ErrorBoundary label="GitHub Scanner">
                <GitHubScanner />
              </ErrorBoundary>
            ) : viewMode === 'web3-tools' ? (
              <ErrorBoundary label="Web3 Tools">
                <Web3Tools />
              </ErrorBoundary>
            ) : viewMode === 'notes-tags' ? (
              <NotesTagsView request={selectedRequest} />
            ) : viewMode === 'intruder' ? (
              <Intruder request={selectedRequest} />
            ) : viewMode === 'sequencer' ? (
              <Sequencer request={selectedRequest} />
            ) : viewMode === 'extractor' ? (
              <Extractor request={selectedRequest} />
            ) : viewMode === 'analyzer' ? (
              <ResponseAnalyzer request={selectedRequest} />
            ) : selectedRequest ? (
              <>
                {viewMode === 'view' && (
                  <ErrorBoundary label="View">
                    <DetailsView request={selectedRequest} />
                  </ErrorBoundary>
                )}
                {viewMode === 'repeater' && (
                  <ErrorBoundary label="Repeater">
                    <Repeater request={selectedRequest!} />
                  </ErrorBoundary>
                )}
                {viewMode === 'scanner' && (
                  <ErrorBoundary label="Scanner">
                    <ScannerView request={selectedRequest!} />
                  </ErrorBoundary>
                )}
              </>
            ) : (
              <div className="empty-state">
                <div className="empty-icon">←</div>
                <p>
                  {viewMode === 'repeater'
                    ? 'Select a request to send to Repeater'
                    : viewMode === 'scanner'
                      ? 'Select a JavaScript request to scan'
                      : viewMode === 'view'
                        ? 'Select an exchange to see the full details'
                        : 'Select a request'}
                </p>
              </div>
            )}
          </div>
        </div>
        </div>
      </ErrorBoundary>
    </div>
  );
}

export default App;

