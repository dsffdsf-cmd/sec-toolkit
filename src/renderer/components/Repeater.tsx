import React, { useState, useEffect, useMemo, useCallback, memo } from 'react';
import Editor from '@monaco-editor/react';
import { HttpRequest } from '../../main/proxy-server';
import { getContentTypeColor } from './DetailsView';
import { requestDetailEqual } from '../utils/requestEqual';
import { SendLoader } from './ToolIcons';
import { useToast } from '../context/ToastContext';
import './Repeater.css';

const MAX_BODY_DISPLAY = 512 * 1024; // 512KB max for Monaco
const MONACO_HEIGHT = 420;
const HEADER_VALUE_TRUNCATE = 200;

// Strip ANSI escape codes from error messages
const stripAnsiCodes = (text: string): string => {
  return text.replace(/\x1b\[[0-9;]*m/g, '').replace(/\[0m|\[31m|\[1m|\[22m|\[39m|\[90m|\[33m/g, '').trim();
};

const CHATGPT_URL = 'https://chat.openai.com/';
const PROMPT_PREFIX = `I'm debugging an HTTP request and need help understanding this response. Please analyze it and suggest what might be wrong or how to fix it.

`;
const PROMPT_SUFFIX = `

(End of HTTP request/response snippet.)`;

interface RepeaterProps {
  request: HttpRequest;
}

type ExtractedTokens = { bearer: string; csrf: string; cookie: string };

function extractTokens(res: { responseHeaders?: Record<string, string>; responseBody?: string }): ExtractedTokens {
  const out: ExtractedTokens = { bearer: '', csrf: '', cookie: '' };
  const h = res.responseHeaders || {};
  const key = (k: string) => Object.keys(h).find((x) => x.toLowerCase() === k.toLowerCase());
  const val = (k: string) => (key(k) ? h[key(k)!] : '');

  out.bearer = val('authorization') || '';
  out.csrf = val('x-csrf-token') || val('x-xsrf-token') || val('csrf-token') || '';
  if (!out.csrf && res.responseBody) {
    const m = res.responseBody.match(/(?:csrf|_csrf|authenticity_token|__RequestVerificationToken)["\s:=]+["']?([A-Za-z0-9_-]{8,})/i);
    if (m) out.csrf = m[1]!;
  }
  const setCookies = Object.entries(h)
    .filter(([k]) => /^set-cookie$/i.test(k))
    .map(([, v]) => v);
  if (setCookies.length) {
    const parts = setCookies
      .map((s) => s.split(';')[0]?.trim())
      .filter((p): p is string => !!p && p.includes('='));
    out.cookie = parts.join('; ');
  }
  return out;
}

function applyPlaceholders(
  s: string,
  tokens: ExtractedTokens
): string {
  return s
    .replace(/\{\{bearer\}\}/g, tokens.bearer)
    .replace(/\{\{csrf\}\}/g, tokens.csrf)
    .replace(/\{\{cookie\}\}/g, tokens.cookie);
}

function getHeader(headers: Record<string, string> | undefined, key: string): string {
  if (!headers) return '';
  const k = Object.keys(headers).find((x) => x.toLowerCase() === key.toLowerCase());
  return k ? (headers[k] ?? '') : '';
}

const ResponseHeadersList: React.FC<{ headers: Record<string, string> }> = ({ headers }) => {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const entries = useMemo(
    () => Object.entries(headers).sort(([a], [b]) => a.toLowerCase().localeCompare(b.toLowerCase())),
    [headers]
  );

  const toggleExpand = (key: string) => {
    const newExpanded = new Set(expanded);
    if (newExpanded.has(key)) {
      newExpanded.delete(key);
    } else {
      newExpanded.add(key);
    }
    setExpanded(newExpanded);
  };

  return (
    <div className="response-headers-kv">
      {entries.map(([key, value]) => {
        const isExpanded = expanded.has(key);
        const truncated = value.length > HEADER_VALUE_TRUNCATE;
        const display = truncated && !isExpanded ? value.slice(0, HEADER_VALUE_TRUNCATE) + '…' : value;
        return (
          <div key={key} className="response-header-row">
            <span className="response-header-key">{key}:</span>
            <span className="response-header-value" title={truncated && !isExpanded ? value : undefined}>
              {display}
            </span>
            {truncated && (
              <button
                className="header-expand-btn"
                onClick={() => toggleExpand(key)}
                title={isExpanded ? 'Collapse' : 'Expand'}
              >
                {isExpanded ? '−' : '+'}
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
};

const ResponseBodyView: React.FC<{ body: string; contentType?: string }> = ({ body, contentType }) => {
  const [value, setValue] = useState('');
  const [language, setLanguage] = useState<string>('plaintext');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    let cancelled = false;
    setError('');
    
    if (!body || typeof body !== 'string') {
      setValue('');
      setLanguage('plaintext');
      setLoading(false);
      return;
    }

    // Check for binary/truncated placeholders early
    if (body.startsWith('[Binary') || body.startsWith('[Truncated') || body.startsWith('[Response too large')) {
      setValue(body);
      setLanguage('plaintext');
      setLoading(false);
      return;
    }

    const ct = (contentType || '').toLowerCase();
    const peek = body.slice(0, 2000).trim();
    const isJson = ct.includes('json') || /^\s*[\{\[]/.test(peek);
    const isJs = ct.includes('javascript') || ct.includes('ecmascript') || ct.includes('application/javascript') || ct.includes('text/javascript');
    const isHtml = ct.includes('html') || /^\s*<!?DOCTYPE/i.test(peek) || /^\s*<html/i.test(peek);
    const isXml = ct.includes('xml') || /^\s*<\?xml/.test(peek);
    const isCss = ct.includes('css');
    const isSvg = ct.includes('svg');
    const isMinified = isJs && (body.split('\n').length < 5 && body.length > 500 || /^[^;\n]{200,}/.test(body.slice(0, 500)));

    const run = async () => {
      setLoading(true);
      let out = body;
      let lang = 'plaintext';
      
      try {
        if (isJson) {
          lang = 'json';
          try {
            const cleaned = body.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g, '');
            const parsed = JSON.parse(cleaned);
            out = JSON.stringify(parsed, null, 2);
          } catch (e1) {
            try {
              const cleaned = body.replace(/,\s*}/g, '}').replace(/,\s*]/g, ']');
              const parsed = JSON.parse(cleaned);
              out = JSON.stringify(parsed, null, 2);
            } catch (e2) {
              // Invalid JSON, keep raw
              setError('Invalid JSON format');
            }
          }
        } else if (isJs) {
          lang = 'javascript';
          // Skip formatting if body looks like an error message
          if (body.trim().startsWith('Error:') || body.includes('Requesting main frame')) {
            out = body;
            setError('');
          } else {
            // Always try to prettify JS, especially if minified
            try {
              const res = await (window as any).electronAPI.prettifyCode?.(body, 'javascript');
              if (res?.success && res.formatted) {
                out = res.formatted;
              } else if (res?.error) {
                const cleanError = stripAnsiCodes(res.error);
                setError(`Prettier: ${cleanError}`);
              }
            } catch (e: any) {
              setError(`Formatting failed: ${stripAnsiCodes(e?.message || 'Unknown error')}`);
            }
          }
        } else if (isHtml) {
          lang = 'html';
          // Skip formatting if body looks like an error message
          if (body.trim().startsWith('Error:')) {
            out = body;
            setError('');
          } else {
            try {
              const res = await (window as any).electronAPI.prettifyCode?.(body, 'html');
              if (res?.success && res.formatted) {
                out = res.formatted;
              } else if (res?.error) {
                const cleanError = stripAnsiCodes(res.error);
                setError(`Prettier: ${cleanError}`);
              }
            } catch (e: any) {
              setError(`Formatting failed: ${stripAnsiCodes(e?.message || 'Unknown error')}`);
            }
          }
        } else if (isXml) {
          lang = 'xml';
        } else if (isCss) {
          lang = 'css';
          try {
            const res = await (window as any).electronAPI.prettifyCode?.(body, 'css');
            if (res?.success && res.formatted) {
              out = res.formatted;
            }
          } catch {
            // Ignore CSS formatting errors
          }
        } else if (isSvg) {
          lang = 'xml';
        }

        // Truncate only after formatting to preserve structure
        if (out.length > MAX_BODY_DISPLAY) {
          const origLen = out.length;
          const truncated = out.slice(0, MAX_BODY_DISPLAY);
          out = truncated + `\n\n[Truncated – ${((origLen - MAX_BODY_DISPLAY) / 1024).toFixed(1)} KB omitted]`;
        }

        if (!cancelled) {
          setValue(out);
          setLanguage(lang);
        }
      } catch (e: any) {
        if (!cancelled) {
          setError(`Processing error: ${stripAnsiCodes(e?.message || 'Unknown error')}`);
          setValue(body.slice(0, MAX_BODY_DISPLAY));
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };
    
    run();
    return () => { cancelled = true; };
  }, [body, contentType]);

  if (!body || (typeof body !== 'string') || body.trim() === '')
    return <div className="empty-response">No response body</div>;
  
  if (body.startsWith('[Binary') || body.startsWith('[Binary Image Data') || body.startsWith('[Truncated') || body.startsWith('[Response too large'))
    return <div className="binary-data">{body}</div>;

  if (loading) return <div className="response-body-loading">Formatting…</div>;

  return (
    <div className="response-body-monaco">
      {error && (
        <div className="response-body-error" title={error}>
          ⚠ {error}
        </div>
      )}
      <Editor
        height={MONACO_HEIGHT}
        theme="vs-dark"
        language={language}
        value={value || body.slice(0, MAX_BODY_DISPLAY)}
        options={{
          readOnly: true,
          domReadOnly: true,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          wordWrap: 'on',
          fontSize: 12,
          lineNumbers: 'on',
          folding: true,
          renderLineHighlight: 'none',
          automaticLayout: true,
          fontFamily: 'ui-monospace, "Cascadia Code", "Fira Code", Consolas, "Courier New", monospace',
        }}
      />
    </div>
  );
};

const Repeater: React.FC<RepeaterProps> = ({ request }) => {
  const toast = useToast();
  const [method, setMethod] = useState(request.method);
  const [url, setUrl] = useState(request.url);
  const [headers, setHeaders] = useState<Record<string, string>>(request.headers);
  const [body, setBody] = useState(request.body || '');
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [tokens, setTokens] = useState<ExtractedTokens>({ bearer: '', csrf: '', cookie: '' });

  useEffect(() => {
    setMethod((request.method || 'GET').toUpperCase());
    setUrl(request.url);
    setHeaders(request.headers ? { ...request.headers } : {});
    setBody(request.body || '');
    setResponse(null);
  }, [request.id, request.method, request.headers]);

  const handleSend = async () => {
    setLoading(true);
    try {
      const u = applyPlaceholders(url, tokens);
      const h: Record<string, string> = {};
      for (const [k, v] of Object.entries(headers)) h[k] = applyPlaceholders(v, tokens);
      const b = applyPlaceholders(body, tokens);

      const modifiedRequest: HttpRequest = {
        ...request,
        method,
        url: u,
        headers: h,
        body: b,
      };

      const result = await window.electronAPI.repeatRequest(modifiedRequest);
      setResponse(result);
      if (result && !('error' in result && (result as { error?: string }).error)) setTokens(extractTokens(result));
    } catch (error) {
      setResponse({ error: String(error) });
    } finally {
      setLoading(false);
    }
  };

  const handleHeaderChange = (key: string, value: string) => {
    setHeaders((prev) => ({ ...prev, [key]: value }));
  };

  const handleAddHeader = () => {
    // Add a new header with a temporary unique key
    // User can edit the key and value inline
    const tempKey = `new-header-${Date.now()}`;
    setHeaders((prev) => ({ ...prev, [tempKey]: '' }));
  };

  const handleRemoveHeader = (key: string) => {
    setHeaders((prev) => {
      const newHeaders = { ...prev };
      delete newHeaders[key];
      return newHeaders;
    });
  };

  const askChatGPT = () => {
    if (!response) return;
    const status = response.status ?? '—';
    const err = response.error;
    const bodySnip = typeof response.responseBody === 'string'
      ? response.responseBody.slice(0, 3000).replace(/```/g, '[code]')
      : '';
    let block = `**Request:** ${method} ${url}\n**Response status:** ${status}`;
    if (err) block += `\n**Error:** ${err}`;
    if (bodySnip) block += `\n**Response body (excerpt):**\n${bodySnip}`;
    const prompt = PROMPT_PREFIX + block + PROMPT_SUFFIX;
    try {
      navigator.clipboard.writeText(prompt);
      window.electronAPI.openExternalUrl?.(CHATGPT_URL);
      toast.success('Prompt copied. Paste in ChatGPT to ask about this response.');
    } catch (e) {
      toast.error('Could not copy prompt or open ChatGPT.');
    }
  };

  const copyAsCurl = () => {
    const u = applyPlaceholders(url, tokens);
    const h = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, applyPlaceholders(v, tokens)]));
    const b = applyPlaceholders(body, tokens);

    let curl = `curl -X ${method} '${u}'`;
    Object.entries(h).forEach(([key, value]) => {
      if (key.toLowerCase() !== 'host' && key.toLowerCase() !== 'content-length') {
        curl += ` \\\n  -H '${key}: ${value.replace(/'/g, "'\\''")}'`;
      }
    });
    if (b) curl += ` \\\n  -d '${b.replace(/'/g, "'\\''")}'`;
    navigator.clipboard.writeText(curl);
  };

  const getStatusColor = (status?: number): string => {
    if (!status) return '#999999';
    if (status >= 200 && status < 300) return '#2ecc71';
    if (status >= 300 && status < 400) return '#3498db';
    if (status >= 400 && status < 500) return '#f39c12';
    if (status >= 500) return '#e74c3c';
    return '#999999';
  };

  const getMethodColor = (method: string): string => {
    switch (method.toUpperCase()) {
      case 'GET': return 'hsl(210, 12%, 65%)';
      case 'POST': return '#ff4444';
      case 'PUT': return '#cc7722';
      case 'DELETE': return '#cc2244';
      case 'PATCH': return '#884499';
      case 'HEAD': return 'hsl(210, 10%, 55%)';
      case 'OPTIONS': return 'hsl(210, 10%, 55%)';
      default: return 'hsl(210, 10%, 50%)';
    }
  };

  return (
    <div className="repeater">
      <div className="repeater-header">
        <div className="repeater-title-row">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" className="repeater-icon">
            <defs>
              <linearGradient id="repeaterHeaderGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#2ecc71" />
                <stop offset="100%" stopColor="#27ae60" />
              </linearGradient>
            </defs>
            <path d="M12 3L4 8L12 13L20 8L12 3Z" fill="url(#repeaterHeaderGrad)" opacity="0.9"/>
            <path d="M4 15L12 20L20 15" stroke="url(#repeaterHeaderGrad)" strokeWidth="2.5" fill="none" strokeLinecap="round"/>
            <circle cx="12" cy="8" r="2" fill="white" opacity="0.95"/>
            <path d="M8 12L16 12" stroke="url(#repeaterHeaderGrad)" strokeWidth="2.5" strokeLinecap="round"/>
          </svg>
          <span className="repeater-placeholder-hint" title="Replaced from last response when you Send">
            Placeholders: {'{{bearer}}'}, {'{{csrf}}'}, {'{{cookie}}'}
          </span>
        </div>
        <div className="repeater-actions">
          <button className="action-btn" onClick={copyAsCurl}>
            Copy as cURL
          </button>
          <button className="action-btn primary" onClick={handleSend} disabled={loading}>
            {loading ? (
              <>
                <SendLoader />
                Sending...
              </>
            ) : (
              'Send'
            )}
          </button>
        </div>
      </div>

      <div className="repeater-content">
        <div className="repeater-section">
          <div className="section-header">Request</div>
          
          <div className="request-line">
            <select
              className="method-select"
              value={method}
              onChange={(e) => setMethod(e.target.value)}
              style={{ 
                backgroundColor: getMethodColor(method),
                color: 'white',
                fontWeight: '600'
              }}
            >
              <option>GET</option>
              <option>POST</option>
              <option>PUT</option>
              <option>DELETE</option>
              <option>PATCH</option>
              <option>OPTIONS</option>
              <option>HEAD</option>
            </select>
            <input
              type="text"
              className="url-input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/api/endpoint"
            />
          </div>

          <div className="headers-section">
            <div className="section-subheader">
              Headers ({Object.keys(headers).length})
              <button className="add-btn" onClick={handleAddHeader}>+ Add</button>
            </div>
            {Object.keys(headers).length === 0 ? (
              <div className="empty-headers">
                <p>No headers found. Headers should be automatically detected from the request.</p>
                <p className="hint">If headers are missing, they may not have been captured properly by Puppeteer.</p>
              </div>
            ) : (
              <div className="headers-list">
                {Object.entries(headers).sort(([a], [b]) => a.toLowerCase().localeCompare(b.toLowerCase())).map(([key, value]) => (
                  <div key={key} className="header-row">
                    <input
                      type="text"
                      className="header-key-input"
                      value={key}
                      onChange={(e) => {
                        const newHeaders = { ...headers };
                        delete newHeaders[key];
                        newHeaders[e.target.value] = value;
                        setHeaders(newHeaders);
                      }}
                      placeholder="Header name"
                    />
                    <input
                      type="text"
                      className="header-value-input"
                      value={value}
                      onChange={(e) => handleHeaderChange(key, e.target.value)}
                      placeholder="Header value"
                    />
                    <button
                      className="remove-btn"
                      onClick={() => handleRemoveHeader(key)}
                      title="Remove header"
                    >
                      ×
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="body-section">
            <div className="section-subheader">Body</div>
            <textarea
              className="body-textarea"
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Request body (JSON, XML, etc.)"
            />
          </div>
        </div>

        {response && (
          <div className="repeater-section">
            <div className="response-section-header">
              <span className="section-header">Response</span>
              <button
                type="button"
                className="ask-chatgpt-btn"
                onClick={askChatGPT}
                title="Copy a prompt about this response and open ChatGPT"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" fill="currentColor"/>
                </svg>
                Ask ChatGPT
              </button>
            </div>
            <div className="response-status">
              <span 
                className="status-badge" 
                style={{ 
                  backgroundColor: getStatusColor(response.status),
                  color: 'white'
                }}
              >
                {response.status || '—'}
              </span>
            </div>
            {response.responseHeaders && Object.keys(response.responseHeaders).length > 0 && (
              <div className="response-headers">
                <div className="section-subheader">Headers</div>
                <ResponseHeadersList headers={response.responseHeaders} />
              </div>
            )}
            {response.responseBody !== undefined && (
              <div className="response-body">
                <div className="section-subheader">
                  Body
                  {getHeader(response.responseHeaders, 'content-type') && (
                    <span
                      className="content-type-badge"
                      style={{ backgroundColor: getContentTypeColor(getHeader(response.responseHeaders, 'content-type')) }}
                    >
                      {getHeader(response.responseHeaders, 'content-type')}
                    </span>
                  )}
                </div>
                <div className="response-body-content">
                  <ResponseBodyView body={response.responseBody} contentType={getHeader(response.responseHeaders, 'content-type')} />
                </div>
              </div>
            )}
            {response.error && (
              <div className="error-message">{response.error}</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default memo(Repeater, (prev, next) => requestDetailEqual(prev.request, next.request));

