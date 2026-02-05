import React, { useState, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import { useSettings } from '../context/SettingsContext';
import './GitHubScanner.css';

interface GitHubScanResult {
  id: string;
  ruleId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
  file: string;
  line: number;
  endLine: number;
  column: number;
  endColumn: number;
  code: string;
  category: string;
  cweIds?: string[];
  owaspIds?: string[];
  fix?: string;
  references?: string[];
}

interface ScanProgress {
  stage: 'cloning' | 'analyzing' | 'scanning' | 'complete' | 'error';
  message: string;
  progress?: number;
  totalFiles?: number;
  scannedFiles?: number;
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ff2244',
  HIGH: '#ff4444',
  MEDIUM: '#ffaa33',
  LOW: '#4488ff',
  INFO: '#44cc66',
};

const CATEGORY_ICONS: Record<string, string> = {
  'reentrancy': '🔄',
  'access-control': '🔐',
  'arithmetic': '🔢',
  'secrets': '🔑',
  'injection': '💉',
  'cryptography': '🔒',
  'configuration': '⚙️',
  'error-handling': '⚠️',
  'gas': '⛽',
  'default': '🛡️',
};

const GitHubScanner: React.FC = () => {
  const { integration } = useSettings();
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [results, setResults] = useState<GitHubScanResult[]>([]);
  const [selectedResult, setSelectedResult] = useState<GitHubScanResult | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [categoryFilter, setCategoryFilter] = useState('');
  const [searchFilter, setSearchFilter] = useState('');
  const [customRules, setCustomRules] = useState('');
  const [showRulesEditor, setShowRulesEditor] = useState(false);
  const [useDefaultRules, setUseDefaultRules] = useState(true);
  const [recentRepos, setRecentRepos] = useState<string[]>([]);

  // Load recent repos from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem('github-scanner-recent');
      if (saved) {
        setRecentRepos(JSON.parse(saved));
      }
    } catch {}
  }, []);

  // Listen for progress updates from main process
  useEffect(() => {
    const cleanup = (window as any).electronAPI?.onGitHubScanProgress?.((prog: ScanProgress) => {
      setProgress(prog);
    });
    return () => cleanup?.();
  }, []);

  // Get language from file extension
  const getLanguage = (file: string): string => {
    const ext = file.split('.').pop()?.toLowerCase() || '';
    const langMap: Record<string, string> = {
      'sol': 'sol',
      'rs': 'rust',
      'js': 'javascript',
      'ts': 'typescript',
      'jsx': 'javascript',
      'tsx': 'typescript',
      'py': 'python',
      'go': 'go',
      'move': 'plaintext',
      'cairo': 'plaintext',
      'vy': 'python',
    };
    return langMap[ext] || 'plaintext';
  };

  const addToRecentRepos = (url: string) => {
    const updated = [url, ...recentRepos.filter(r => r !== url)].slice(0, 5);
    setRecentRepos(updated);
    localStorage.setItem('github-scanner-recent', JSON.stringify(updated));
  };

  const handleScan = async () => {
    if (!repoUrl.trim()) return;

    setIsScanning(true);
    setResults([]);
    setSelectedResult(null);
    setProgress({ stage: 'cloning', message: 'Preparing scan...', progress: 0 });

    try {
      addToRecentRepos(repoUrl.trim());

      const scanResults = await window.electronAPI.scanGitHubRepo({
        repoUrl: repoUrl.trim(),
        branch: branch.trim() || undefined,
        githubToken: integration.githubToken?.trim() || undefined,
        useDefaultRules,
        customRules: customRules.trim() || undefined,
      });

      setResults(scanResults || []);
      setProgress({ stage: 'complete', message: `Found ${scanResults?.length || 0} vulnerabilities`, progress: 100 });

    } catch (error) {
      setProgress({ 
        stage: 'error', 
        message: `Scan failed: ${(error as Error).message}` 
      });
    } finally {
      setIsScanning(false);
    }
  };

  const filteredResults = results.filter(r => {
    if (severityFilter.length > 0 && !severityFilter.includes(r.severity)) return false;
    if (categoryFilter && r.category !== categoryFilter) return false;
    if (searchFilter) {
      const search = searchFilter.toLowerCase();
      return (
        r.message.toLowerCase().includes(search) ||
        r.file.toLowerCase().includes(search) ||
        r.ruleId.toLowerCase().includes(search) ||
        r.category.toLowerCase().includes(search)
      );
    }
    return true;
  }).sort((a, b) => {
    return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
  });

  const categories = [...new Set(results.map(r => r.category))];
  const severityCounts = SEVERITY_ORDER.reduce((acc, sev) => {
    acc[sev] = results.filter(r => r.severity === sev).length;
    return acc;
  }, {} as Record<string, number>);

  const getCategoryIcon = (category: string) => {
    return CATEGORY_ICONS[category] || CATEGORY_ICONS['default'];
  };

  return (
    <div className="github-scanner">
      {/* Header */}
      <div className="github-scanner-header">
        <div className="header-title">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="github-icon">
            <defs>
              <linearGradient id="githubGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#ff5555" />
                <stop offset="100%" stopColor="#cc2222" />
              </linearGradient>
            </defs>
            <path d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.341-3.369-1.341-.454-1.155-1.11-1.462-1.11-1.462-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z" fill="url(#githubGrad)"/>
          </svg>
          <div className="title-text">
            <h1>GitHub Repository Scanner</h1>
            <span className="subtitle">Web3 & Blockchain Security Analysis</span>
          </div>
        </div>
        <div className="header-badges">
          <span className="badge web3">Web3</span>
          <span className="badge solidity">Solidity</span>
          <span className="badge rust">Rust</span>
        </div>
      </div>

      {/* Search Bar */}
      <div className="github-scanner-input">
        <div className="input-row">
          <div className="url-input-wrapper">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="input-icon">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
            </svg>
            <input
              type="text"
              className="repo-url-input"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repo or owner/repo"
              disabled={isScanning}
              list="recent-repos"
            />
            <datalist id="recent-repos">
              {recentRepos.map((repo, i) => (
                <option key={i} value={repo} />
              ))}
            </datalist>
          </div>
          <input
            type="text"
            className="branch-input"
            value={branch}
            onChange={(e) => setBranch(e.target.value)}
            placeholder="Branch (optional)"
            disabled={isScanning}
          />
          <button
            className="scan-btn"
            onClick={handleScan}
            disabled={isScanning || !repoUrl.trim()}
          >
            {isScanning ? (
              <>
                <span className="scan-spinner" />
                Scanning...
              </>
            ) : (
              <>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                Start Scan
              </>
            )}
          </button>
        </div>

        <div className="options-row">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={useDefaultRules}
              onChange={(e) => setUseDefaultRules(e.target.checked)}
              disabled={isScanning}
            />
            <span>Use Default Web3 Rules</span>
          </label>
          <button
            className="rules-btn"
            onClick={() => setShowRulesEditor(!showRulesEditor)}
            disabled={isScanning}
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
              <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
            </svg>
            {showRulesEditor ? 'Hide Rules' : 'Custom Rules'}
          </button>
        </div>

        {showRulesEditor && (
          <div className="custom-rules-editor">
            <div className="rules-header">
              <span>Custom Semgrep Rules (YAML)</span>
              <a href="https://semgrep.dev/docs/writing-rules/rule-syntax/" target="_blank" rel="noreferrer">
                Docs ↗
              </a>
            </div>
            <textarea
              className="rules-textarea"
              value={customRules}
              onChange={(e) => setCustomRules(e.target.value)}
              placeholder={`rules:
  - id: my-custom-rule
    message: "Description of the issue"
    severity: WARNING
    languages: [solidity]
    pattern: |
      // Your pattern here`}
              disabled={isScanning}
            />
          </div>
        )}
      </div>

      {/* Progress Bar */}
      {progress && (
        <div className={`scan-progress ${progress.stage}`}>
          <div className="progress-bar">
            <div 
              className="progress-fill" 
              style={{ width: `${progress.progress || 0}%` }}
            />
          </div>
          <div className="progress-info">
            <span className="progress-stage">{progress.stage.toUpperCase()}</span>
            <span className="progress-message">{progress.message}</span>
          </div>
        </div>
      )}

      {/* Results Section */}
      {results.length > 0 && (
        <div className="results-section">
          {/* Summary Bar */}
          <div className="results-summary">
            <div className="summary-title">
              <span className="count">{filteredResults.length}</span>
              <span className="label">Vulnerabilities Found</span>
            </div>
            {window.electronAPI.exportFindingsToSarifFile && (
              <button
                type="button"
                className="github-export-sarif-btn"
                onClick={async () => {
                  const exportSarif = window.electronAPI.exportFindingsToSarifFile;
                  if (!exportSarif) return;
                  try {
                    const res = await exportSarif(results, 'CleanTraffic GitHub Scanner');
                    if (res.success && res.filePath) {
                      // optional: show toast if you have toast in GitHubScanner
                    }
                  } catch {
                    // ignore
                  }
                }}
                title="Save SARIF for GitHub/GitLab CI"
              >
                Export SARIF
              </button>
            )}
            {window.electronAPI.exportFindingsToJunitFile && results.length > 0 && (
              <button
                type="button"
                className="github-export-junit-btn"
                onClick={async () => {
                  const exportJunit = window.electronAPI.exportFindingsToJunitFile;
                  if (!exportJunit) return;
                  try {
                    const res = await exportJunit(results, 'CleanTraffic GitHub Scanner');
                    if (res.success && res.filePath) { /* optional toast */ }
                  } catch {
                    // ignore
                  }
                }}
                title="Save JUnit XML for Jenkins/GitLab CI"
              >
                Export JUnit
              </button>
            )}
            <div className="severity-badges">
              {SEVERITY_ORDER.map(sev => (
                severityCounts[sev] > 0 && (
                  <button
                    key={sev}
                    className={`severity-badge ${sev.toLowerCase()} ${severityFilter.includes(sev) ? 'active' : ''}`}
                    onClick={() => {
                      setSeverityFilter(prev => 
                        prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
                      );
                    }}
                    style={{ borderColor: SEVERITY_COLORS[sev] }}
                  >
                    <span className="sev-count">{severityCounts[sev]}</span>
                    <span className="sev-label">{sev}</span>
                  </button>
                )
              ))}
            </div>
          </div>

          {/* Filters */}
          <div className="results-filters">
            <div className="filter-search">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" />
              </svg>
              <input
                type="text"
                placeholder="Search vulnerabilities..."
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
              />
            </div>
            <select
              className="category-filter"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
            >
              <option value="">All Categories</option>
              {categories.map(cat => (
                <option key={cat} value={cat}>{getCategoryIcon(cat)} {cat}</option>
              ))}
            </select>
          </div>

          {/* Split View */}
          <div className="results-split">
            {/* Results List */}
            <div className="results-list">
              {filteredResults.map(result => (
                <div
                  key={result.id}
                  className={`result-item ${selectedResult?.id === result.id ? 'selected' : ''}`}
                  onClick={() => setSelectedResult(result)}
                >
                  <div className="result-severity" style={{ background: SEVERITY_COLORS[result.severity] }}>
                    {result.severity.charAt(0)}
                  </div>
                  <div className="result-content">
                    <div className="result-header">
                      <span className="result-rule">{result.ruleId}</span>
                      <span className="result-category">{getCategoryIcon(result.category)} {result.category}</span>
                    </div>
                    <div className="result-message">{result.message}</div>
                    <div className="result-location">
                      <span className="file-path">{result.file}</span>
                      <span className="line-number">:{result.line}</span>
                    </div>
                  </div>
                </div>
              ))}
              {filteredResults.length === 0 && (
                <div className="no-results">
                  <span>No vulnerabilities match your filters</span>
                </div>
              )}
            </div>

            {/* Details Panel */}
            <div className="result-details">
              {selectedResult ? (
                <>
                  <div className="details-header">
                    <div className="details-severity" style={{ background: SEVERITY_COLORS[selectedResult.severity] }}>
                      {selectedResult.severity}
                    </div>
                    <div className="details-meta">
                      <span className="confidence">Confidence: {selectedResult.confidence}</span>
                      {selectedResult.cweIds?.map(cwe => (
                        <span key={cwe} className="cwe-badge">{cwe}</span>
                      ))}
                    </div>
                  </div>

                  <div className="details-section">
                    <h3>Rule</h3>
                    <code className="rule-id">{selectedResult.ruleId}</code>
                  </div>

                  <div className="details-section">
                    <h3>Message</h3>
                    <p className="message-text">{selectedResult.message}</p>
                  </div>

                  <div className="details-section">
                    <h3>Location</h3>
                    <div className="location-info">
                      <span className="file">{selectedResult.file}</span>
                      <span className="lines">Lines {selectedResult.line} - {selectedResult.endLine}</span>
                    </div>
                  </div>

                  <div className="details-section code-section">
                    <h3>Vulnerable Code</h3>
                    <div className="code-editor">
                      <Editor
                        height="200px"
                        language={getLanguage(selectedResult.file)}
                        value={selectedResult.code || '// No code available'}
                        theme="vs-dark"
                        options={{
                          readOnly: true,
                          minimap: { enabled: false },
                          fontSize: 12,
                          fontFamily: "'JetBrains Mono', monospace",
                          scrollBeyondLastLine: false,
                          wordWrap: 'on',
                          folding: false,
                          lineDecorationsWidth: 4,
                          renderLineHighlight: 'none',
                        }}
                      />
                    </div>
                  </div>

                  {selectedResult.fix && (
                    <div className="details-section">
                      <h3>Suggested Fix</h3>
                      <p className="fix-text">{selectedResult.fix}</p>
                    </div>
                  )}

                  {selectedResult.references && selectedResult.references.length > 0 && (
                    <div className="details-section">
                      <h3>References</h3>
                      <ul className="references-list">
                        {selectedResult.references.map((ref, i) => (
                          <li key={i}>
                            <a href={ref} target="_blank" rel="noreferrer">{ref}</a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              ) : (
                <div className="no-selection">
                  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    <path d="M12 8v4" />
                    <path d="M12 16h.01" />
                  </svg>
                  <p>Select a vulnerability to view details</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!isScanning && results.length === 0 && !progress && (
        <div className="empty-state">
          <div className="empty-icon">
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none">
              <defs>
                <linearGradient id="emptyGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#ff5555" stopOpacity="0.3" />
                  <stop offset="100%" stopColor="#cc2222" stopOpacity="0.1" />
                </linearGradient>
              </defs>
              <path d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.341-3.369-1.341-.454-1.155-1.11-1.462-1.11-1.462-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z" fill="url(#emptyGrad)" stroke="#ff4444" strokeWidth="0.5"/>
            </svg>
          </div>
          <h2>Web3 Repository Scanner</h2>
          <p>Analyze GitHub repositories for blockchain security vulnerabilities</p>
          <div className="features-grid">
            <div className="feature">
              <span className="feature-icon">🔐</span>
              <span className="feature-text">Smart Contract Auditing</span>
            </div>
            <div className="feature">
              <span className="feature-icon">🦀</span>
              <span className="feature-text">Solana/Anchor Support</span>
            </div>
            <div className="feature">
              <span className="feature-icon">⚡</span>
              <span className="feature-text">Solidity Analysis</span>
            </div>
            <div className="feature">
              <span className="feature-icon">🔍</span>
              <span className="feature-text">Custom Rules Support</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default GitHubScanner;
