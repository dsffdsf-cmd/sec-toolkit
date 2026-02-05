import React, { useState, useMemo } from 'react';
import { HttpRequest } from '../../main/proxy-server';
import './ResponseDiff.css';

interface ResponseDiffProps {
  request1: HttpRequest;
  request2: HttpRequest;
  onClose: () => void;
}

type DiffLine = { type: 'equal' | 'delete' | 'insert'; text: string };

function computeDiff(text1: string, text2: string): DiffLine[] {
  const lines1 = text1.split('\n');
  const lines2 = text2.split('\n');
  const out: DiffLine[] = [];
  const max = Math.max(lines1.length, lines2.length);
  for (let i = 0; i < max; i++) {
    const a = lines1[i] ?? '';
    const b = lines2[i] ?? '';
    if (a === b) {
      out.push({ type: 'equal', text: a });
    } else {
      if (a) out.push({ type: 'delete', text: a });
      if (b) out.push({ type: 'insert', text: b });
    }
  }
  return out;
}

const ResponseDiff: React.FC<ResponseDiffProps> = ({ request1, request2, onClose }) => {
  const [diffMode, setDiffMode] = useState<'unified' | 'split'>('split');
  const [showHeaders, setShowHeaders] = useState<boolean>(true);
  const [showBody, setShowBody] = useState<boolean>(true);

  const formatJSON = (text: string): string => {
    try {
      const parsed = JSON.parse(text);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return text;
    }
  };

  const getResponseBody1 = (): string => {
    const body = request1.responseBody || '';
    if (request1.contentType?.includes('json')) {
      return formatJSON(body);
    }
    return body;
  };

  const getResponseBody2 = (): string => {
    const body = request2.responseBody || '';
    if (request2.contentType?.includes('json')) {
      return formatJSON(body);
    }
    return body;
  };

  const bodyDiff = useMemo(
    () => computeDiff(getResponseBody1(), getResponseBody2()),
    [request1.responseBody, request1.contentType, request2.responseBody, request2.contentType]
  );
  const headers1 = request1.responseHeaders || {};
  const headers2 = request2.responseHeaders || {};
  
  const allHeaderKeys = new Set([...Object.keys(headers1), ...Object.keys(headers2)]);
  const headerDiffs = Array.from(allHeaderKeys).map(key => ({
    key,
    value1: headers1[key] || '',
    value2: headers2[key] || '',
    changed: headers1[key] !== headers2[key],
    onlyIn1: !headers2[key],
    onlyIn2: !headers1[key],
  }));

  const getStatusColor = (status?: number): string => {
    if (!status) return '#999999';
    if (status >= 200 && status < 300) return '#2ecc71';
    if (status >= 300 && status < 400) return '#3498db';
    if (status >= 400 && status < 500) return '#f39c12';
    if (status >= 500) return '#e74c3c';
    return '#999999';
  };

  return (
    <div className="response-diff">
      <div className="diff-header">
        <div className="diff-header-left">
          <h2>Response Comparison</h2>
          <div className="diff-requests-info">
            <div className="request-info">
              <span className="request-label">Request 1:</span>
              <span className="request-method">{request1.method}</span>
              <span className="request-url">{request1.url}</span>
            </div>
            <div className="request-info">
              <span className="request-label">Request 2:</span>
              <span className="request-method">{request2.method}</span>
              <span className="request-url">{request2.url}</span>
            </div>
          </div>
        </div>
        <div className="diff-header-right">
          <div className="diff-controls">
            <button
              className={`control-btn ${diffMode === 'split' ? 'active' : ''}`}
              onClick={() => setDiffMode('split')}
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <rect x="1" y="1" width="6" height="14" rx="1" stroke="currentColor" strokeWidth="1.5" fill="none"/>
                <rect x="9" y="1" width="6" height="14" rx="1" stroke="currentColor" strokeWidth="1.5" fill="none"/>
              </svg>
              Split
            </button>
            <button
              className={`control-btn ${diffMode === 'unified' ? 'active' : ''}`}
              onClick={() => setDiffMode('unified')}
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <rect x="1" y="1" width="14" height="14" rx="1" stroke="currentColor" strokeWidth="1.5" fill="none"/>
                <path d="M8 1V15" stroke="currentColor" strokeWidth="1.5"/>
              </svg>
              Unified
            </button>
          </div>
          <button className="close-btn" onClick={onClose}>
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
              <path d="M15 5L5 15M5 5L15 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
          </button>
        </div>
      </div>

      <div className="diff-content">
        {/* Status Comparison */}
        <div className="diff-section">
          <div className="section-title">
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <circle cx="9" cy="9" r="7" stroke="currentColor" strokeWidth="1.5" fill="none"/>
              <path d="M9 5V9L12 12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
            </svg>
            Status Codes
          </div>
          <div className="status-comparison">
            <div className={`status-item ${request1.status === request2.status ? 'same' : 'different'}`}>
              <span className="status-label">Request 1:</span>
              <span 
                className="status-code"
                style={{ color: getStatusColor(request1.status) }}
              >
                {request1.status || '—'}
              </span>
            </div>
            <div className={`status-item ${request1.status === request2.status ? 'same' : 'different'}`}>
              <span className="status-label">Request 2:</span>
              <span 
                className="status-code"
                style={{ color: getStatusColor(request2.status) }}
              >
                {request2.status || '—'}
              </span>
            </div>
          </div>
        </div>

        {/* Headers Comparison */}
        {showHeaders && (
          <div className="diff-section">
            <div className="section-title">
              <button
                className="toggle-btn"
                onClick={() => setShowHeaders(!showHeaders)}
              >
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <path d="M3.5 5.25L7 8.75L10.5 5.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
              </button>
              <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                <rect x="2" y="4" width="14" height="1.5" rx="0.75" fill="currentColor"/>
                <rect x="2" y="8" width="14" height="1.5" rx="0.75" fill="currentColor"/>
                <rect x="2" y="12" width="10" height="1.5" rx="0.75" fill="currentColor"/>
              </svg>
              Response Headers
            </div>
            <div className={`headers-diff ${diffMode}`}>
              {diffMode === 'split' ? (
                <div className="split-view">
                  <div className="diff-pane">
                    <div className="pane-header">Request 1 Headers</div>
                    <div className="pane-content">
                      {headerDiffs.map((header, index) => (
                        <div
                          key={index}
                          className={`header-row ${header.onlyIn2 ? 'removed' : header.changed ? 'modified' : ''}`}
                        >
                          <span className="header-key">{header.key}:</span>
                          <span className="header-value">{header.value1 || '(missing)'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="diff-pane">
                    <div className="pane-header">Request 2 Headers</div>
                    <div className="pane-content">
                      {headerDiffs.map((header, index) => (
                        <div
                          key={index}
                          className={`header-row ${header.onlyIn1 ? 'added' : header.changed ? 'modified' : ''}`}
                        >
                          <span className="header-key">{header.key}:</span>
                          <span className="header-value">{header.value2 || '(missing)'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="unified-view">
                  {headerDiffs.map((header, index) => (
                    <div
                      key={index}
                      className={`header-row-unified ${
                        header.onlyIn2 ? 'removed' : 
                        header.onlyIn1 ? 'added' : 
                        header.changed ? 'modified' : 'equal'
                      }`}
                    >
                      <span className="header-key">{header.key}:</span>
                      <div className="header-values">
                        <span className={`header-value ${header.onlyIn2 ? 'removed' : ''}`}>
                          {header.value1 || '(missing)'}
                        </span>
                        {header.changed && (
                          <>
                            <span className="arrow">→</span>
                            <span className={`header-value ${header.onlyIn1 ? 'added' : ''}`}>
                              {header.value2 || '(missing)'}
                            </span>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Body Comparison */}
        {showBody && (
          <div className="diff-section">
            <div className="section-title">
              <button
                className="toggle-btn"
                onClick={() => setShowBody(!showBody)}
              >
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <path d="M3.5 5.25L7 8.75L10.5 5.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
              </button>
              <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                <rect x="2" y="2" width="14" height="14" rx="2" stroke="currentColor" strokeWidth="1.5" fill="none"/>
                <path d="M5 6H13M5 10H13" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
              </svg>
              Response Body
            </div>
            <div className={`body-diff ${diffMode}`}>
              {diffMode === 'split' ? (
                <div className="split-view">
                  <div className="diff-pane">
                    <div className="pane-header">Request 1 Body</div>
                    <div className="pane-content code-content">
                      <pre>{getResponseBody1()}</pre>
                    </div>
                  </div>
                  <div className="diff-pane">
                    <div className="pane-header">Request 2 Body</div>
                    <div className="pane-content code-content">
                      <pre>{getResponseBody2()}</pre>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="unified-view code-content">
                  <pre>
                    {bodyDiff.map((line, index) => (
                      <div
                        key={index}
                        className={`diff-line ${line.type}`}
                      >
                        {line.type === 'delete' && <span className="line-marker">-</span>}
                        {line.type === 'insert' && <span className="line-marker">+</span>}
                        {line.type === 'equal' && <span className="line-marker"> </span>}
                        <span className="line-content">{line.text}</span>
                      </div>
                    ))}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ResponseDiff;

