import React, { useMemo, useState, useEffect, useCallback, memo } from 'react';
import { HttpRequest } from '../../main/proxy-server';
import { requestDetailEqual } from '../utils/requestEqual';
import { ScanResult } from '../../main/scanner';
import Editor, { OnMount } from '@monaco-editor/react';
import { EmptyState } from './EmptyState';
import { ScanLoader, FilterEmptyIcon } from './ToolIcons';
import { useToast } from '../context/ToastContext';
import './ScannerView.css';

interface ScannerViewProps {
  request: HttpRequest;
}

const ScannerView: React.FC<ScannerViewProps> = ({ request }) => {
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [scanning, setScanning] = useState(false);
  const [scanPhase, setScanPhase] = useState<{ phase: number; label: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();
  // Noise controls / scoring - defaults are permissive to show findings, user can filter down
  const [minExploitability, setMinExploitability] = useState<number>(0); // Show all by default
  const [maxExploitability, setMaxExploitability] = useState<number>(10);
  const [minConfidence, setMinConfidence] = useState<'unknown' | 'low' | 'medium' | 'high' | 'very-high'>('unknown'); // Show all confidence levels
  const [showWarnings, setShowWarnings] = useState<boolean>(true); // Show warnings by default
  const [showInfo, setShowInfo] = useState<boolean>(false); // Keep info hidden to reduce noise
  const [showNonChainable, setShowNonChainable] = useState<boolean>(true); // Show non-chainable
  const [showLowConfidence, setShowLowConfidence] = useState<boolean>(true); // Show low confidence
  const [showTestsAndPayloads, setShowTestsAndPayloads] = useState<boolean>(true);
  const [showFullContext, setShowFullContext] = useState<boolean>(false);
  const [filtersExpanded, setFiltersExpanded] = useState<boolean>(false);
  const [customPatternInput, setCustomPatternInput] = useState<string>('');

  // Removed auto-scan - user must click "Scan" button explicitly
  // useEffect(() => {
  //   if (request) {
  //     performScan();
  //   }
  // }, [request.id]);

  const performScan = async () => {
    setScanning(true);
    setError(null);
    setScanPhase(null);
    const unsub = window.electronAPI.onScannerPhase?.((data) =>
      setScanPhase({ phase: data.phase, label: data.label })
    ) ?? (() => {});
    try {
      const customPatterns = customPatternInput
        ? customPatternInput.split(/\n/).map((p) => p.trim()).filter(Boolean)
        : undefined;
      const results = await window.electronAPI.sendToScanner(request, customPatterns?.length ? { customPatterns } : undefined);
      if (Array.isArray(results)) {
        setScanResults(results);
        setSelectedIndex(0);
      } else if (results && (results as any).error) {
        setError(String((results as any).error));
        setScanResults([]);
      } else {
        setError('Scanner returned an unexpected response.');
        setScanResults([]);
      }
    } catch (err) {
      setError(String(err));
    } finally {
      unsub();
      setScanPhase(null);
      setScanning(false);
    }
  };

  useEffect(() => {
    // Keep selection stable when results change
    if (scanResults.length === 0) setSelectedIndex(0);
  }, [scanResults]);

  const filteredResults = useMemo(() => {
    const isLowConfidence = (c?: string) => !c || c === 'unknown' || c === 'low';
    const confRank = (c?: string) => {
      switch (c) {
        case 'very-high':
          return 4;
        case 'high':
          return 3;
        case 'medium':
          return 2;
        case 'low':
          return 1;
        default:
          return 0;
      }
    };
    const filtered = scanResults.filter(r => {
      const score = typeof r.exploitability === 'number' ? r.exploitability : 0;
      if (score < minExploitability) return false;
      if (score > maxExploitability) return false;
      if (!showWarnings && r.severity === 'warning') return false;
      if (!showInfo && r.severity === 'info') return false;
      if (!showNonChainable && r.chainable === false) return false;
      if (!showLowConfidence && isLowConfidence(r.confidence)) return false;
      if (confRank(r.confidence) < confRank(minConfidence)) return false;
      return true;
    });
    return filtered;
  }, [scanResults, minExploitability, maxExploitability, minConfidence, showWarnings, showInfo, showNonChainable, showLowConfidence]);

  const severityCounts = useMemo(() => ({
    error: filteredResults.filter(r => r.severity === 'error').length,
    warning: filteredResults.filter(r => r.severity === 'warning').length,
    info: filteredResults.filter(r => r.severity === 'info').length,
  }), [filteredResults]);

  useEffect(() => {
    if (filteredResults.length === 0) {
      setSelectedIndex(0);
    } else if (selectedIndex >= filteredResults.length) {
      setSelectedIndex(0);
    }
  }, [filteredResults, selectedIndex]);

  useEffect(() => {
    // Default to small snippet per selection
    setShowFullContext(false);
  }, [selectedIndex]);

  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'error':
        return '#e74c3c';
      case 'warning':
        return '#f39c12';
      case 'info':
        return '#3498db';
      default:
        return '#858585';
    }
  };

  const SeverityIcon: React.FC<{ severity: string; size?: number }> = ({ severity, size = 16 }) => {
    const color = getSeverityColor(severity);
    const s = severity.toLowerCase();
    
    // Error/Critical - Shield with X
    if (s === 'error' || s === 'critical') {
      return (
        <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
          <path 
            d="M8 1L2 4v4c0 3.5 2.5 6.5 6 7.5 3.5-1 6-4 6-7.5V4L8 1z" 
            fill={color} 
            opacity="0.15"
            stroke={color}
            strokeWidth="1.2"
          />
          <path 
            d="M6 6l4 4M10 6l-4 4" 
            stroke={color} 
            strokeWidth="1.5" 
            strokeLinecap="round"
          />
        </svg>
      );
    }
    
    // Warning - Triangle with !
    if (s === 'warning' || s === 'warn') {
      return (
        <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
          <path 
            d="M8 2L1.5 13.5h13L8 2z" 
            fill={color} 
            opacity="0.15"
            stroke={color}
            strokeWidth="1.2"
            strokeLinejoin="round"
          />
          <path d="M8 6v3.5" stroke={color} strokeWidth="1.5" strokeLinecap="round"/>
          <circle cx="8" cy="11.5" r="0.8" fill={color}/>
        </svg>
      );
    }
    
    // Info - Circle with i
    return (
      <svg width={size} height={size} viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <circle 
          cx="8" 
          cy="8" 
          r="6.5" 
          fill={color} 
          opacity="0.15"
          stroke={color}
          strokeWidth="1.2"
        />
        <circle cx="8" cy="5" r="0.8" fill={color}/>
        <path d="M8 7v4.5" stroke={color} strokeWidth="1.5" strokeLinecap="round"/>
      </svg>
    );
  };

  const getCategoryColor = (category?: string): string => {
    if (!category) return 'hsl(210, 10%, 50%)';
    const c = category.toLowerCase();
    if (c.includes('xss') || c.includes('dom')) return '#ef4444';
    if (c.includes('sql') || c.includes('injection')) return '#dc2626';
    if (c.includes('ssrf') || c.includes('redirect')) return '#f59e0b';
    if (c.includes('prototype') || c.includes('pollution')) return '#8b5cf6';
    if (c.includes('path') || c.includes('traversal')) return '#ec4899';
    if (c.includes('command')) return '#be185d';
    if (c.includes('secret') || c.includes('hardcoded')) return '#f97316';
    return 'hsl(210, 12%, 55%)';
  };

  const FindingRow = memo(function FindingRow(props: {
    result: ScanResult;
    active: boolean;
    severityColor: string;
    onSelect: () => void;
  }) {
    const { result, active, severityColor, onSelect } = props;
    const catColor = getCategoryColor(result.category);
    return (
      <button
        type="button"
        className={`result-row ${active ? 'active' : ''}`}
        style={{ '--severity-color': severityColor } as React.CSSProperties}
        onClick={onSelect}
      >
        <span className="result-row-icon">
          <SeverityIcon severity={result.severity} size={14} />
        </span>
        <span className="result-row-main">
          <span className="result-row-title">{result.ruleId}</span>
          <span className="result-row-msg">{result.message}</span>
          <span className="result-row-meta">
            {result.line > 0 ? `L${result.line}` : '—'}
            {result.flowPath && <span className="result-row-flow"> • {result.flowPath}</span>}
            {result.confidence ? ` • ${String(result.confidence).replace('-', ' ')}` : ''}
            {result.cwe ? ` • ${result.cwe}` : ''}
          </span>
          {result.category && (
            <span className="result-row-cat" style={{ color: catColor, borderColor: catColor }}>
              {result.category}
            </span>
          )}
        </span>
        <span className="result-row-sev" style={{ color: severityColor }}>
          {result.severity.toUpperCase()}
        </span>
      </button>
    );
  });

  const handleSelectIndex = useCallback((index: number) => setSelectedIndex(index), []);

  // Memoize selected finding to prevent refresh on new requests
  const selected = useMemo(() => {
    return filteredResults[selectedIndex];
  }, [filteredResults, selectedIndex]);

  const MonacoContext: React.FC<{
    code: string;
    startLine: number;
    highlightLine: number;
    heightPx: number;
  }> = ({ code, startLine, highlightLine, heightPx }) => {
    const localHitLine = Math.max(1, highlightLine - startLine + 1);
    const editorKey = useMemo(() => `${startLine}-${highlightLine}-${code.length}`, [startLine, highlightLine, code.length]);

    const onMount: OnMount = (editor, monaco) => {
      try {
        // Highlight hit line
        editor.deltaDecorations(
          [],
          [
            {
              range: new monaco.Range(localHitLine, 1, localHitLine, 1),
              options: {
                isWholeLine: true,
                className: 'monaco-hit-line',
                glyphMarginClassName: 'monaco-hit-glyph',
              },
            },
          ]
        );

        editor.revealLineInCenter(localHitLine);
      } catch {
        // ignore
      }
    };

    return (
      <div className="monaco-context">
        <Editor
          key={editorKey}
          height={`${Math.max(120, heightPx)}px`}
          theme="vs-dark"
          language="javascript"
          value={code}
          onMount={onMount}
          options={{
            readOnly: true,
            domReadOnly: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            wordWrap: 'on',
            fontSize: 12,
            lineNumbers: (n) => String(startLine + n - 1),
            glyphMargin: true,
            folding: false,
            renderLineHighlight: 'none',
            automaticLayout: true,
            fontFamily:
              'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
          }}
        />
      </div>
    );
  };

  const MonacoEvidence: React.FC<{
    code: string;
    highlights?: ScanResult['matchedCodeHighlights'];
    heightPx: number;
  }> = ({ code, highlights, heightPx }) => {
    const editorKey = useMemo(() => `${code.length}-${highlights?.length || 0}`, [code.length, highlights?.length]);

    const onMount: OnMount = (editor, monaco) => {
      try {
        const decos = (highlights || []).map(h => {
          const range = new monaco.Range(h.startLine, h.startCol, h.endLine, h.endCol);
          let cls = 'monaco-evidence-metavar';
          
          switch (h.kind) {
            case 'vulnerable':
              cls = 'monaco-evidence-vulnerable';
              break;
            case 'source':
              cls = 'monaco-evidence-source';
              break;
            case 'sink':
              cls = 'monaco-evidence-sink';
              break;
            case 'taint':
              cls = 'monaco-evidence-taint';
              break;
            case 'metavar':
            default:
              cls = 'monaco-evidence-metavar';
              break;
          }
          
          return { range, options: { inlineClassName: cls } };
        });

        editor.deltaDecorations([], decos);
        const first = highlights?.[0];
        if (first) editor.revealLineInCenter(first.startLine);
      } catch {
        // ignore
      }
    };

    return (
      <div className="monaco-context">
        <Editor
          key={editorKey}
          height={`${Math.max(120, heightPx)}px`}
          theme="vs-dark"
          language="javascript"
          value={code}
          onMount={onMount}
          options={{
            readOnly: true,
            domReadOnly: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            wordWrap: 'on',
            fontSize: 12,
            lineNumbers: (n) => String(n),
            glyphMargin: false,
            folding: false,
            renderLineHighlight: 'none',
            automaticLayout: true,
            fontFamily:
              'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
          }}
        />
      </div>
    );
  };

  const renderCodeFrame = (result: ScanResult) => {
    if (!result.contextCode) return null;
    const startLine = result.contextStartLine ?? 1;
    const highlightLine = result.line > 0 ? result.line : startLine;

    // Default: show a small GitHub-style snippet (4 lines context each side)
    const lines = result.contextCode.split('\n');
    const localHit = Math.max(1, highlightLine - startLine + 1);
    const before = 4;
    const after = 4;
    const sLocal = Math.max(1, localHit - before);
    const eLocal = Math.min(lines.length, localHit + after);
    const snippet = lines.slice(sLocal - 1, eLocal).join('\n');
    const snippetStartLine = startLine + (sLocal - 1);

    return (
      <div className="result-section">
        <div className="result-section-header">
          <div className="result-section-title">Context</div>
          <div className="context-actions">
            <button
              type="button"
              className="send-to-notes-btn"
              onClick={async () => {
                try {
                  // Get current notes
                  const currentNotes = request.notes || '';
                  
                  // Format the context code for notes - clean and readable
                  const timestamp = new Date().toLocaleString();
                  let noteContent = '';
                  
                  // Add separator if notes already exist
                  if (currentNotes) {
                    noteContent = `${currentNotes}\n\n${'='.repeat(60)}\n\n`;
                  }
                  
                  // Header with timestamp
                  noteContent += `[${timestamp}] Context Code\n`;
                  noteContent += `${'─'.repeat(50)}\n\n`;
                  
                  // Finding details
                  noteContent += `Rule ID: ${result.ruleId}\n`;
                  if (result.file) {
                    noteContent += `File: ${result.file}\n`;
                  }
                  if (result.line > 0) {
                    noteContent += `Location: Line ${result.line}${result.column > 0 ? `, Column ${result.column}` : ''}\n`;
                  }
                  
                  // Context code with proper formatting
                  if (result.contextCode) {
                    noteContent += `\nContext Code:\n\`\`\`javascript\n${result.contextCode.trim()}\n\`\`\`\n`;
                  }
                  noteContent += '\nStatus: open\n';
                  // Update notes
                  const updateResult = await (window as any).electronAPI.updateRequestNotesTags?.(
                    request.id,
                    noteContent,
                    request.tags || []
                  );
                  
                  if (updateResult?.success) {
                    toast.success('Context code sent to Notes');
                  } else {
                    toast.error(updateResult?.error || 'Failed to send to Notes');
                  }
                } catch (err) {
                  toast.error(err instanceof Error ? err.message : 'Failed to send to Notes');
                }
              }}
              title="Send context code to Notes"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                <polyline points="17 8 12 3 7 8"></polyline>
                <line x1="12" y1="3" x2="12" y2="15"></line>
              </svg>
              Send to Notes
            </button>
            <button
              type="button"
              className="context-toggle"
              onClick={() => setShowFullContext(v => !v)}
              title={showFullContext ? 'Show small snippet' : 'Show full context (scrollable)'}
            >
              {showFullContext ? 'Show snippet' : 'Show full'}
            </button>
          </div>
        </div>
        <MonacoContext
          code={showFullContext ? result.contextCode : snippet}
          startLine={showFullContext ? startLine : snippetStartLine}
          highlightLine={highlightLine}
          heightPx={showFullContext ? 320 : 160}
        />
      </div>
    );
  };

  const copyText = async (text: string, label?: string) => {
    try {
      await navigator.clipboard.writeText(text);
      toast.success(label ? `Copied ${label}` : 'Copied to clipboard');
    } catch {
      toast.error('Copy failed');
    }
  };

  return (
    <div className="scanner-view">
      <div className="scanner-header">
        <div className="scanner-header-row">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="scanner-icon">
            <defs>
              <linearGradient id="scannerHeaderGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#ff5555" />
                <stop offset="100%" stopColor="#cc2222" />
              </linearGradient>
            </defs>
            <path d="M12 2L4 6V12C4 17 8 21 12 22.5C16 21 20 17 20 12V6L12 2Z" fill="url(#scannerHeaderGrad)" fillOpacity="0.15" stroke="url(#scannerHeaderGrad)" strokeWidth="1.5" strokeLinejoin="round"/>
            <circle cx="12" cy="10" r="3" stroke="url(#scannerHeaderGrad)" strokeWidth="1.5" fill="none"/>
            <circle cx="12" cy="10" r="1.2" fill="url(#scannerHeaderGrad)"/>
          </svg>
          <button className="scan-btn" onClick={performScan} disabled={scanning}>
            {scanning ? 'Scanning...' : scanResults.length > 0 ? 'Scan Again' : 'Start Scan'}
          </button>
        </div>
        <div className="scanner-custom-pattern">
          <textarea
            className="scanner-custom-pattern-input"
            placeholder="Custom regex patterns (one per line). e.g. password|api_key|secret"
            value={customPatternInput}
            onChange={(e) => setCustomPatternInput(e.target.value)}
            disabled={scanning}
            title="Optional: one or more regex patterns, one per line. Matches appear as info findings."
            rows={2}
          />
        </div>
      </div>

      <div className="scanner-content">
        {error && (
          <div className="error-message">{error}</div>
        )}

        {scanning && (
          <div className="scanning-indicator">
            <ScanLoader
              label={scanPhase?.label ?? 'Starting scan…'}
              badge={scanPhase ? `Phase ${scanPhase.phase}` : undefined}
            />
          </div>
        )}

        {!scanning && scanResults.length === 0 && !error && (
          <div className="no-results">
            <EmptyState
              icon="scanner"
              title='Click "Start Scan" to analyze this request'
              subtitle="Only JavaScript files can be scanned"
              brandName="CleanTraffic"
            />
          </div>
        )}

        {scanResults.length > 0 && (
          <div className="scan-results">
            <div className="results-summary">
              <div className="summary-item error">
                <span className="summary-count">{severityCounts.error}</span>
                <span className="summary-label">Errors</span>
              </div>
              <div className="summary-item warning">
                <span className="summary-count">{severityCounts.warning}</span>
                <span className="summary-label">Warnings</span>
              </div>
              <div className="summary-item info">
                <span className="summary-count">{severityCounts.info}</span>
                <span className="summary-label">Info</span>
              </div>
              <div className="summary-item info">
                <span className="summary-count">{filteredResults.length}</span>
                <span className="summary-label">Shown</span>
              </div>
              <div className="summary-item info">
                <span className="summary-count">{scanResults.length}</span>
                <span className="summary-label">Total</span>
              </div>
              {scanResults.length > 0 && (
                <div className="scanner-export-buttons">
                  {window.electronAPI.exportFindingsToSarifFile && (
                    <button
                      type="button"
                      className="scanner-export-btn"
                      onClick={async () => {
                        const exportSarif = window.electronAPI.exportFindingsToSarifFile;
                        if (!exportSarif) return;
                        try {
                          const res = await exportSarif(scanResults, 'CleanTraffic Scanner');
                          if (res.success && res.filePath) toast.success('SARIF saved');
                          else if (res.canceled) { /* no toast */ }
                          else toast.error(res.error || 'Export failed');
                        } catch (e) {
                          toast.error(e instanceof Error ? e.message : 'Export failed');
                        }
                      }}
                      title="Save SARIF for GitHub/GitLab CI"
                    >
                      <svg className="scanner-export-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                        <polyline points="7 10 12 15 17 10" />
                        <line x1="12" y1="15" x2="12" y2="3" />
                      </svg>
                      <span>SARIF</span>
                    </button>
                  )}
                  {window.electronAPI.exportFindingsToJunitFile && (
                    <button
                      type="button"
                      className="scanner-export-btn"
                      onClick={async () => {
                        const exportJunit = window.electronAPI.exportFindingsToJunitFile;
                        if (!exportJunit) return;
                        try {
                          const res = await exportJunit(scanResults, 'CleanTraffic Scanner');
                          if (res.success && res.filePath) toast.success('JUnit XML saved');
                          else if (res.canceled) { /* no toast */ }
                          else toast.error(res.error || 'Export failed');
                        } catch (e) {
                          toast.error(e instanceof Error ? e.message : 'Export failed');
                        }
                      }}
                      title="Save JUnit XML for Jenkins/GitLab CI"
                    >
                      <svg className="scanner-export-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                        <polyline points="7 10 12 15 17 10" />
                        <line x1="12" y1="15" x2="12" y2="3" />
                      </svg>
                      <span>JUnit</span>
                    </button>
                  )}
                </div>
              )}
            </div>

            <div className="results-controls">
              <button
                type="button"
                className="filters-toggle"
                onClick={() => setFiltersExpanded(v => !v)}
                aria-expanded={filtersExpanded}
              >
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={filtersExpanded ? 'rotated' : ''}>
                  <polyline points="6 9 12 15 18 9" />
                </svg>
                Filters
              </button>
              {filtersExpanded && (
              <div className="controls-inner">
              <div className="control-row">
                <span className="control-label">Min exploitability</span>
                <input
                  className="control-range"
                  type="range"
                  min={0}
                  max={10}
                  step={1}
                  value={minExploitability}
                  onChange={(e) => setMinExploitability(parseInt(e.target.value, 10))}
                />
                <span className="control-value">{minExploitability}</span>
              </div>
              <div className="control-row">
                <span className="control-label">Max exploitability</span>
                <input
                  className="control-range"
                  type="range"
                  min={0}
                  max={10}
                  step={1}
                  value={maxExploitability}
                  onChange={(e) => setMaxExploitability(parseInt(e.target.value, 10))}
                />
                <span className="control-value">{maxExploitability}</span>
              </div>
              <div className="control-row">
                <span className="control-label">Min confidence</span>
                <select className="control-select" value={minConfidence} onChange={(e) => setMinConfidence(e.target.value as any)}>
                  <option value="unknown">Unknown+</option>
                  <option value="low">Low+</option>
                  <option value="medium">Medium+</option>
                  <option value="high">High+</option>
                  <option value="very-high">Very-high</option>
                </select>
                <span className="control-value">{minConfidence}</span>
              </div>
              <label className="control-check">
                <input type="checkbox" checked={showWarnings} onChange={(e) => setShowWarnings(e.target.checked)} />
                Show warnings
              </label>
              <label className="control-check">
                <input type="checkbox" checked={showInfo} onChange={(e) => setShowInfo(e.target.checked)} />
                Show info
              </label>
              <label className="control-check">
                <input type="checkbox" checked={showNonChainable} onChange={(e) => setShowNonChainable(e.target.checked)} />
                Show non-chainable
              </label>
              <label className="control-check">
                <input type="checkbox" checked={showLowConfidence} onChange={(e) => setShowLowConfidence(e.target.checked)} />
                Show low/unknown confidence
              </label>
              <label className="control-check">
                <input
                  type="checkbox"
                  checked={showTestsAndPayloads}
                  onChange={(e) => setShowTestsAndPayloads(e.target.checked)}
                />
                Show tests/payloads
              </label>
              </div>
              )}
            </div>

            <div className="results-layout">
              <div className="results-sidebar">
                {filteredResults.length === 0 && (
                  <div className="filtered-empty">
                    <FilterEmptyIcon />
                    <div className="filtered-empty-body">
                      <div className="filtered-empty-title">No findings shown (filters)</div>
                    <div className="filtered-empty-text">
                      Results exist, but they’re hidden by the current exploitability/confidence toggles.
                    </div>
                    <div className="filtered-empty-actions">
                      <button
                        type="button"
                        className="scan-btn compact"
                        onClick={() => {
                          setMinExploitability(0);
                          setMaxExploitability(10);
                          setMinConfidence('unknown');
                          setShowWarnings(true);
                          setShowInfo(true);
                          setShowNonChainable(true);
                          setShowLowConfidence(true);
                        }}
                      >
                        Show everything
                      </button>
                      <button
                        type="button"
                        className="scan-btn compact secondary"
                        onClick={() => {
                          setMinExploitability(4);
                          setMaxExploitability(10);
                          setMinConfidence('medium');
                          setShowWarnings(false);
                          setShowInfo(false);
                          setShowNonChainable(false);
                          setShowLowConfidence(false);
                        }}
                      >
                        Relax filters (recommended)
                      </button>
                      </div>
                    </div>
                  </div>
                )}
                {filteredResults.map((result, index) => (
                  <FindingRow
                    key={`${result.ruleId}-${result.line}-${result.column}-${index}`}
                    result={result}
                    active={index === selectedIndex}
                    severityColor={getSeverityColor(result.severity)}
                    onSelect={() => handleSelectIndex(index)}
                  />
                ))}
              </div>

              <div className="results-details">
                {selected && (
                  <>
                    <div className="details-header">
                      <div className="details-title">
                        <span className="severity-icon">
                          <SeverityIcon severity={selected.severity} />
                        </span>
                        <span className="details-title-text">{selected.ruleId}</span>
                        <span
                          className="severity-badge"
                          style={{ color: getSeverityColor(selected.severity) }}
                        >
                          {selected.severity.toUpperCase()}
                        </span>
                        {typeof selected.exploitability === 'number' && (
                          <span className="meta-pill">{`EXP ${selected.exploitability}/10`}</span>
                        )}
                        {selected.confidence && (
                          <span className="meta-pill">{String(selected.confidence).toUpperCase()}</span>
                        )}
                        {selected.category && <span className="meta-pill">{selected.category}</span>}
                        {selected.cwe && (
                          <a
                            href={`https://cwe.mitre.org/data/definitions/${selected.cwe.replace('CWE-', '')}.html`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="meta-pill meta-pill-link"
                            title="View CWE definition"
                          >
                            {selected.cwe}
                          </a>
                        )}
                        {selected.owasp && <span className="meta-pill">{selected.owasp}</span>}
                      </div>

                      <div className="details-loc">
                        <a
                          href={selected.file}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="result-file-link"
                        >
                          {selected.file}
                        </a>
                        {selected.line > 0 && (
                          <span className="result-line-info">
                            {' '}
                            • Line {selected.line}
                            {selected.column > 0 ? `, Column ${selected.column}` : ''}
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="details-body">
                      <div className="result-section">
                        <div className="result-section-title">Summary</div>
                        {selected.title && <div className="details-message">{selected.title}</div>}
                        <div className="details-message">{selected.message}</div>
                        {(selected.entryPoint || selected.parameter || selected.impact) && (
                          <div className="details-submeta">
                            {selected.entryPoint && (
                              <>
                                Entry: <code className="inline-code">{selected.entryPoint}</code>{' '}
                              </>
                            )}
                            {selected.parameter && (
                              <>
                                • Param: <code className="inline-code">{selected.parameter}</code>{' '}
                              </>
                            )}
                            {selected.impact && <>• Impact: {selected.impact}</>}
                            {typeof selected.chainable === 'boolean' && <> • Chainable: {selected.chainable ? 'Yes' : 'No'}</>}
                          </div>
                        )}
                        {selected.exploitabilityReasons && selected.exploitabilityReasons.length > 0 && (
                          <div className="details-submeta">
                            Score: {selected.exploitabilityReasons.join(' • ')}
                          </div>
                        )}
                        {selected.frameworks && selected.frameworks.length > 0 && (
                          <div className="details-submeta">
                            Frameworks: {selected.frameworks.join(', ')}
                          </div>
                        )}
                        {selected.flowPath && (
                          <div className="details-submeta">
                            Flow: <code className="inline-code">{selected.flowPath}</code>
                          </div>
                        )}
                      </div>

                      {(selected.pattern || selected.matchedCode) && (
                        <div className="result-section">
                          <div className="result-section-header">
                            <div className="result-section-title">Evidence</div>
                            <button
                              type="button"
                              className="send-to-notes-btn"
                              onClick={async () => {
                                try {
                                  // Get current notes
                                  const currentNotes = request.notes || '';
                                  
                                  // Format the evidence for notes - clean and readable
                                  const timestamp = new Date().toLocaleString();
                                  let noteContent = '';
                                  
                                  // Add separator if notes already exist
                                  if (currentNotes) {
                                    noteContent = `${currentNotes}\n\n${'='.repeat(60)}\n\n`;
                                  }
                                  
                                  // Header with timestamp
                                  noteContent += `[${timestamp}] Security Finding\n`;
                                  noteContent += `${'─'.repeat(50)}\n\n`;
                                  
                                  // Finding details
                                  noteContent += `Rule ID: ${selected.ruleId}\n`;
                                  noteContent += `Severity: ${selected.severity.toUpperCase()}\n`;
                                  noteContent += `Confidence: ${selected.confidence || 'unknown'}\n`;
                                  
                                  if (selected.message) {
                                    noteContent += `\nMessage:\n${selected.message}\n`;
                                  }
                                  
                                  if (selected.file) {
                                    noteContent += `\nFile: ${selected.file}\n`;
                                  }
                                  
                                  if (selected.line > 0) {
                                    noteContent += `Location: Line ${selected.line}${selected.column > 0 ? `, Column ${selected.column}` : ''}\n`;
                                  }
                                  
                                  // Pattern
                                  if (selected.pattern) {
                                    noteContent += `\nPattern:\n${selected.pattern}\n`;
                                  }
                                  
                                  // Matched code with proper formatting
                                  if (selected.matchedCode) {
                                    noteContent += `\nMatched Code:\n\`\`\`javascript\n${selected.matchedCode.trim()}\n\`\`\`\n`;
                                  }
                                  
                                  // Context code (if available)
                                  if (selected.contextCode) {
                                    noteContent += `\nContext Code:\n\`\`\`javascript\n${selected.contextCode.trim()}\n\`\`\`\n`;
                                  }
                                  
                                  // Execution trace
                                  if (selected.trace && selected.trace.length > 0) {
                                    noteContent += `\nExecution Path:\n${selected.trace.map(t => `  → ${t}`).join('\n')}\n`;
                                  }
                                  
                                  // Remediation
                                  if (selected.remediation) {
                                    noteContent += `\nRemediation:\n${selected.remediation}\n`;
                                  }
                                  
                                  // Manual test ideas
                                  if (selected.manualTest && selected.manualTest.length > 0) {
                                    noteContent += `\nManual Test Ideas:\n${selected.manualTest.map(t => `  • ${t}`).join('\n')}\n`;
                                  }
                                  noteContent += '\nStatus: open\n';
                                  // Update notes
                                  const result = await (window as any).electronAPI.updateRequestNotesTags?.(
                                    request.id,
                                    noteContent,
                                    request.tags || []
                                  );
                                  
                                  if (result?.success) {
                                    toast.success('Evidence sent to Notes');
                                  } else {
                                    toast.error(result?.error || 'Failed to send to Notes');
                                  }
                                } catch (err) {
                                  toast.error(err instanceof Error ? err.message : 'Failed to send to Notes');
                                }
                              }}
                              title="Send evidence code to Notes"
                            >
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="17 8 12 3 7 8"></polyline>
                                <line x1="12" y1="3" x2="12" y2="15"></line>
                              </svg>
                              Send to Notes
                            </button>
                          </div>
                          {selected.pattern && (
                            <div className="evidence-block">
                              <div className="evidence-label">
                                Pattern
                                <button
                                  type="button"
                                  className="evidence-copy-btn"
                                  onClick={() => copyText(selected.pattern!, 'pattern')}
                                  title="Copy pattern"
                                >
                                  Copy
                                </button>
                              </div>
                              <code className="pattern-code">{selected.pattern}</code>
                            </div>
                          )}
                          {selected.matchedCode && (
                            <div className="evidence-block">
                              <div className="evidence-label">
                                Matched code (snippet)
                                <button
                                  type="button"
                                  className="evidence-copy-btn"
                                  onClick={() => copyText(selected.matchedCode!, 'evidence')}
                                  title="Copy matched code"
                                >
                                  Copy
                                </button>
                              </div>
                              <MonacoEvidence
                                code={selected.matchedCode}
                                highlights={selected.matchedCodeHighlights}
                                heightPx={180}
                              />
                            </div>
                          )}
                        </div>
                      )}

                      {renderCodeFrame(selected)}

                      {selected.taintTrace && selected.taintTrace.length > 0 && (
                        <div className="result-section">
                          <div className="result-section-title">Taint flow</div>
                          <div className="taint-flow">
                            {selected.taintTrace.map((t, i) => (
                              <React.Fragment key={i}>
                                <div className={`taint-flow-item taint-flow-${t.type}`}>
                                  <span className="taint-flow-type">{t.type}</span>
                                  <span className="taint-flow-line">L{t.line}</span>
                                  {t.variable && <code className="taint-flow-var">{t.variable}</code>}
                                  {t.description && (
                                    <span className="taint-flow-desc">{t.description}</span>
                                  )}
                                </div>
                                {i < selected.taintTrace!.length - 1 && (
                                  <div className="taint-flow-connector">↓</div>
                                )}
                              </React.Fragment>
                            ))}
                          </div>
                        </div>
                      )}

                      {selected.trace && selected.trace.length > 0 && !selected.taintTrace?.length && (
                        <div className="result-section">
                          <div className="result-section-title">Execution path</div>
                          <ul className="tips-list">
                            {selected.trace.map((t, i) => (
                              <li key={i}>{t}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {showTestsAndPayloads && selected.manualTest && selected.manualTest.length > 0 && (
                        <div className="result-section">
                          <div className="result-section-title">Manual test ideas</div>
                          <ul className="tips-list">
                            {selected.manualTest.map((t, i) => (
                              <li key={i}>{t}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {selected.remediation && (
                        <div className="result-section">
                          <div className="result-section-title">Remediation</div>
                          <div className="details-message">{selected.remediation}</div>
                        </div>
                      )}

                      {showTestsAndPayloads && selected.exploit && (
                        <div className="result-section">
                          <div className="result-section-title">Bug bounty notes</div>
                          {selected.exploit.description && (
                            <div className="details-message">{selected.exploit.description}</div>
                          )}
                          {selected.exploit.payloads && selected.exploit.payloads.length > 0 && (
                            <div className="evidence-block">
                              <div className="evidence-label">Payload ideas</div>
                              <div className="payload-list">
                                {selected.exploit.payloads.map((p, i) => (
                                  <button
                                    key={i}
                                    type="button"
                                    className="payload-pill"
                                    onClick={() => copyText(p, 'payload')}
                                    title="Click to copy"
                                  >
                                    {p}
                                  </button>
                                ))}
                              </div>
                            </div>
                          )}
                          {selected.exploit.tips && selected.exploit.tips.length > 0 && (
                            <ul className="tips-list">
                              {selected.exploit.tips.map((t, i) => (
                                <li key={i}>{t}</li>
                              ))}
                            </ul>
                          )}
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default memo(ScannerView, (prev, next) => requestDetailEqual(prev.request, next.request));

