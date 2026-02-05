import React, { useState, useEffect, memo } from 'react';
import { HttpRequest } from '../../main/proxy-server';
import { requestDetailEqual } from '../utils/requestEqual';
import './DetailsView.css';

interface DetailsViewProps {
  request: HttpRequest;
  onCompareRequest?: (request: HttpRequest) => void;
}

// Component to prettify and display JavaScript code with truncation
const JavaScriptCode: React.FC<{ code: string }> = ({ code }) => {
  const [prettifiedCode, setPrettifiedCode] = React.useState<string>(code);
  const [isPrettifying, setIsPrettifying] = React.useState<boolean>(true);
  const [showFull, setShowFull] = React.useState<boolean>(false);
  
  // Limit: 50KB or 1000 lines
  const MAX_DISPLAY_SIZE = 50 * 1024; // 50KB
  const MAX_DISPLAY_LINES = 1000;

  useEffect(() => {
    const prettify = async () => {
      // Check if code is minified (single line, very long)
      const isMinified = code.split('\n').length < 10 && code.length > 1000;
      
      if (isMinified || code.length > 500) {
        try {
          setIsPrettifying(true);
          const result = await (window as any).electronAPI.prettifyCode(code, 'javascript');
          if (result.success) {
            setPrettifiedCode(result.formatted);
          } else {
            setPrettifiedCode(code);
          }
        } catch (error) {
          // avoid noisy logs in UI
          setPrettifiedCode(code);
        } finally {
          setIsPrettifying(false);
        }
      } else {
        setPrettifiedCode(code);
        setIsPrettifying(false);
      }
    };

    prettify();
  }, [code]);

  if (isPrettifying) {
    return <div className="prettifying">Prettifying JavaScript...</div>;
  }

  // Check if we need to truncate
  const lines = prettifiedCode.split('\n');
  const isLarge = prettifiedCode.length > MAX_DISPLAY_SIZE || lines.length > MAX_DISPLAY_LINES;
  const shouldTruncate = isLarge && !showFull;
  
  let displayCode = prettifiedCode;
  let remainingLines = 0;
  let remainingKB = 0;
  
  if (shouldTruncate) {
    // Truncate to first MAX_DISPLAY_LINES lines or MAX_DISPLAY_SIZE chars
    if (lines.length > MAX_DISPLAY_LINES) {
      displayCode = lines.slice(0, MAX_DISPLAY_LINES).join('\n');
      remainingLines = lines.length - MAX_DISPLAY_LINES;
    } else if (prettifiedCode.length > MAX_DISPLAY_SIZE) {
      displayCode = prettifiedCode.substring(0, MAX_DISPLAY_SIZE);
      remainingKB = (prettifiedCode.length - MAX_DISPLAY_SIZE) / 1024;
    }
  }

  return (
    <div className="javascript-code-container">
      <SyntaxHighlightedCode code={displayCode} language="javascript" />
      {shouldTruncate && (
        <div className="show-more-container">
          <button 
            className="show-more-button"
            onClick={() => setShowFull(true)}
          >
            {remainingLines > 0 
              ? `Show more (${remainingLines} more lines)` 
              : `Show more (${remainingKB.toFixed(1)} KB remaining)`}
          </button>
        </div>
      )}
      {showFull && isLarge && (
        <div className="show-more-container">
          <button 
            className="show-more-button"
            onClick={() => setShowFull(false)}
          >
            Show less
          </button>
        </div>
      )}
    </div>
  );
};

const DetailsView: React.FC<DetailsViewProps> = ({ request, onCompareRequest }) => {
  const getHost = (url: string): string => {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  };

  const getPath = (url: string): string => {
    try {
      const urlObj = new URL(url);
      return urlObj.pathname + urlObj.search;
    } catch {
      return url;
    }
  };
  const [requestFormat, setRequestFormat] = useState<'auto' | 'raw' | 'json' | 'html' | 'xml'>('auto');
  const [responseFormat, setResponseFormat] = useState<'auto' | 'raw' | 'json' | 'html' | 'xml'>('auto');

  // Helper to extract base content type (remove charset, etc.)
  const getBaseContentType = (contentType?: string): string => {
    if (!contentType) return '';
    return contentType.toLowerCase().split(';')[0].trim();
  };

  const detectContentType = (body: string | undefined, contentType?: string): 'json' | 'html' | 'xml' | 'css' | 'js' | 'image' | 'binary' | 'text' => {
    if (!body || body === '') return 'text';
    
    const ct = getBaseContentType(contentType);
    const content = body;
    
    // Check if it's binary data placeholder
    if (content.startsWith('[Binary data') || content.startsWith('[Binary Image Data')) {
      return 'binary';
    }

    // Check content type header first - handle application/json; charset=UTF-8
    const baseCt = ct.split(';')[0].trim();
    if (baseCt === 'application/json' || baseCt.includes('json') || content.trim().startsWith('{') || content.trim().startsWith('[')) {
      try {
        JSON.parse(content);
        return 'json';
      } catch {}
    }
    
    if (ct.includes('html') || content.trim().startsWith('<!DOCTYPE') || content.trim().startsWith('<html')) {
      return 'html';
    }
    
    if (ct.includes('xml') || content.trim().startsWith('<?xml') || content.trim().startsWith('<')) {
      return 'xml';
    }
    
    if (ct.includes('css')) {
      return 'css';
    }
    
    if (ct.includes('javascript') || ct.includes('ecmascript')) {
      return 'js';
    }
    
    return 'text';
  };

  const formatBody = (body: string | undefined, contentType?: string, format?: 'auto' | 'raw' | 'json' | 'html' | 'xml'): { content: string; type: string; formatted: JSX.Element } => {
    // Check if body is truly empty
    if (!body || body === '' || body.trim() === '') {
      return { content: '', type: 'empty', formatted: <></> };
    }
    
    const content = body;
    const bodyLength = new Blob([body]).size;
    
    // Check if it's binary data placeholder
    if (content.startsWith('[Binary data') || content.startsWith('[Binary Image Data')) {
      return { 
        content: '', 
        type: 'binary', 
        formatted: <div className="binary-data">{content}</div> 
      };
    }
    
    // Check if it's an image (base64 data URL)
    if (contentType?.includes('image/') && content.startsWith('data:')) {
      return {
        content: '',
        type: 'image',
        formatted: <img src={content} alt="Response image" className="response-image" />
      };
    }

    const detectedType = format === 'auto' ? detectContentType(body, contentType) : format;
    
    // Format based on type
    switch (detectedType) {
      case 'json':
        try {
          // Always prettify JSON
          const parsed = JSON.parse(content);
          const formatted = JSON.stringify(parsed, null, 2);
          return {
            content: formatted,
            type: 'json',
            formatted: <SyntaxHighlightedCode code={formatted} language="json" />
          };
        } catch (e) {
          // If JSON parsing fails, try to format as best as possible
          try {
            // Try to fix common JSON issues (trailing commas, etc.)
            const cleaned = content.trim()
              .replace(/,\s*}/g, '}')
              .replace(/,\s*]/g, ']');
            const parsed = JSON.parse(cleaned);
            const formatted = JSON.stringify(parsed, null, 2);
            return {
              content: formatted,
              type: 'json',
              formatted: <SyntaxHighlightedCode code={formatted} language="json" />
            };
          } catch {
            return { content, type: 'text', formatted: <SyntaxHighlightedCode code={content} language="text" /> };
          }
        }
      
      case 'html':
        return {
          content,
          type: 'html',
          formatted: <SyntaxHighlightedCode code={content} language="html" />
        };
      
      case 'xml':
        try {
          // Try to format XML
          const formatted = formatXML(content);
          return {
            content: formatted,
            type: 'xml',
            formatted: <SyntaxHighlightedCode code={formatted} language="xml" />
          };
        } catch {
          return { content, type: 'xml', formatted: <SyntaxHighlightedCode code={content} language="xml" /> };
        }
      
      case 'css':
        return {
          content,
          type: 'css',
          formatted: <SyntaxHighlightedCode code={content} language="css" />
        };
      
      case 'js':
        // JavaScript will be prettified via useEffect hook
        return {
          content,
          type: 'js',
          formatted: <JavaScriptCode code={content} />
        };
      
      default:
        return {
          content,
          type: 'text',
          formatted: <SyntaxHighlightedCode code={content} language="text" />
        };
    }
  };

  const formatXML = (xml: string): string => {
    let formatted = '';
    let indent = 0;
    const tab = '  ';
    xml.split(/>\s*</).forEach(node => {
      if (node.match(/^\//)) {
        indent--;
      }
      formatted += indent > 0 ? tab.repeat(indent) : '';
      formatted += '<' + node + '>\r\n';
      if (node.match(/^<?\w[^>]*[^\/]$/) && !node.startsWith('input')) {
        indent++;
      }
    });
    return formatted.substring(1, formatted.length - 2);
  };

  const getStatusColor = (status?: number): string => {
    if (!status) return '#999999';
    if (status >= 200 && status < 300) return '#2ecc71'; // Green
    if (status >= 300 && status < 400) return '#3498db'; // Blue
    if (status >= 400 && status < 500) return '#f39c12'; // Orange
    if (status >= 500) return '#e74c3c'; // Red
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

  const getBodySize = (body: string | undefined): number => {
    if (!body) return 0;
    return new Blob([body]).size;
  };

  const copyText = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // ignore
    }
  };

  // Format headers with special handling for cookies
  const formatHeaders = (
    headers: Record<string, string>
  ): Array<{ key: string; rawValue: string; formattedValue: JSX.Element }> => {
    // Sort headers: common ones first, then alphabetically
    const commonHeaders = ['host', 'user-agent', 'accept', 'accept-language', 'accept-encoding', 'content-type', 'content-length', 'cookie', 'referer', 'origin', 'authorization'];
    const sortedEntries = Object.entries(headers).sort(([a], [b]) => {
      const aIndex = commonHeaders.indexOf(a.toLowerCase());
      const bIndex = commonHeaders.indexOf(b.toLowerCase());
      if (aIndex !== -1 && bIndex !== -1) return aIndex - bIndex;
      if (aIndex !== -1) return -1;
      if (bIndex !== -1) return 1;
      return a.toLowerCase().localeCompare(b.toLowerCase());
    });

    return sortedEntries.map(([key, value]) => {
      if (key.toLowerCase() === 'cookie') {
        return {
          key,
          rawValue: value,
          formattedValue: formatCookieHeader(value)
        };
      }
      return {
        key,
        rawValue: value,
        formattedValue: <span className="header-value-text">{value}</span>
      };
    });
  };

  // Format cookie header with colorful parameter/value separation
  const formatCookieHeader = (cookieString: string): JSX.Element => {
    const cookies = cookieString.split(';').map(c => c.trim()).filter(c => c);
    const parts: JSX.Element[] = [];

    cookies.forEach((cookie, index) => {
      if (index > 0) {
        parts.push(<span key={`sep-${index}`} className="cookie-separator">; </span>);
      }

      const equalIndex = cookie.indexOf('=');
      if (equalIndex === -1) {
        // No value, just the name
        parts.push(<span key={`name-${index}`} className="cookie-name">{cookie}</span>);
      } else {
        const name = cookie.substring(0, equalIndex).trim();
        const value = cookie.substring(equalIndex + 1).trim();
        
        // Check if value is JSON-encoded (Base64 or URL-encoded)
        let decodedValue: string | null = null;
        let isJson = false;
        
        try {
          // Try URL decode first
          const urlDecoded = decodeURIComponent(value);
          // Try to parse as JSON
          JSON.parse(urlDecoded);
          decodedValue = urlDecoded;
          isJson = true;
        } catch {
          try {
            // Try Base64 decode
            const base64Decoded = atob(value);
            JSON.parse(base64Decoded);
            decodedValue = base64Decoded;
            isJson = true;
          } catch {
            // Not JSON, use as-is
          }
        }

        parts.push(
          <span key={`cookie-${index}`} className="cookie-pair">
            <span className="cookie-name">{name}</span>
            <span className="cookie-equals">=</span>
            {isJson && decodedValue ? (
              <span className="cookie-value-json-wrapper">
                {formatCookieJsonValue(decodedValue)}
              </span>
            ) : (
              <span className="cookie-value">{value}</span>
            )}
          </span>
        );
      }
    });

    return <span className="cookie-header">{parts}</span>;
  };

  // Format JSON cookie values with syntax highlighting
  const formatCookieJsonValue = (jsonString: string): JSX.Element => {
    try {
      const parsed = JSON.parse(jsonString);
      const formatted = JSON.stringify(parsed, null, 2);
      const lines = formatted.split('\n');
      
      return (
        <span className="cookie-json">
          {lines.map((line, i) => (
            <span key={i} className="cookie-json-line">
              {highlightCookieJsonLine(line)}
              {i < lines.length - 1 && '\n'}
            </span>
          ))}
        </span>
      );
    } catch {
      return <span className="cookie-value">{jsonString}</span>;
    }
  };

  // Highlight JSON line for cookies - improved version
  const highlightCookieJsonLine = (line: string): JSX.Element => {
    const parts: JSX.Element[] = [];
    let current = '';
    let inString = false;
    let stringChar = '';
    let escapeNext = false;
    let isKey = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      
      if (escapeNext) {
        current += char;
        escapeNext = false;
        continue;
      }
      
      if (char === '\\' && inString) {
        escapeNext = true;
        current += char;
        continue;
      }
      
      if ((char === '"' || char === "'") && !escapeNext) {
        if (inString) {
          // Closing quote
          if (isKey) {
            parts.push(<span key={`key-${i}`} className="cookie-json-key">{current}</span>);
          } else {
            parts.push(<span key={`str-${i}`} className="cookie-json-string">{current}</span>);
          }
          parts.push(<span key={`quote-close-${i}`} className={isKey ? "cookie-json-key" : "cookie-json-string"}>{char}</span>);
          current = '';
          inString = false;
          const rest = line.substring(i + 1).trim();
          isKey = rest.startsWith(':');
        } else {
          // Opening quote
          if (current.trim()) {
            const trimmed = current.trim();
            if (trimmed.match(/^(true|false|null)$/)) {
              parts.push(<span key={`bool-${i}`} className="cookie-json-keyword">{trimmed}</span>);
            } else if (trimmed.match(/^-?\d+\.?\d*$/)) {
              parts.push(<span key={`num-${i}`} className="cookie-json-number">{trimmed}</span>);
            } else {
              parts.push(<span key={`text-${i}`}>{trimmed}</span>);
            }
            current = '';
          }
          isKey = line.substring(i).match(/^["'][^"']*["']\s*:/) !== null;
          inString = true;
          stringChar = char;
          parts.push(<span key={`quote-open-${i}`} className={isKey ? "cookie-json-key" : "cookie-json-string"}>{char}</span>);
          current = '';
        }
      } else if (inString) {
        current += char;
      } else if (char.match(/[{}[\],:]/)) {
        if (current.trim()) {
          const trimmed = current.trim();
          if (trimmed.match(/^(true|false|null)$/)) {
            parts.push(<span key={`bool-${i}`} className="cookie-json-keyword">{trimmed}</span>);
          } else if (trimmed.match(/^-?\d+\.?\d*$/)) {
            parts.push(<span key={`num-${i}`} className="cookie-json-number">{trimmed}</span>);
          } else {
            parts.push(<span key={`text-${i}`}>{trimmed}</span>);
          }
          current = '';
        }
        parts.push(<span key={`punc-${i}`} className="cookie-json-punctuation">{char}</span>);
        if (char === '{' || char === ',') {
          isKey = true;
        } else if (char === ':') {
          isKey = false;
        }
      } else if (char.match(/\s/)) {
        if (current.trim()) {
          const trimmed = current.trim();
          if (trimmed.match(/^(true|false|null)$/)) {
            parts.push(<span key={`bool-${i}`} className="cookie-json-keyword">{trimmed}</span>);
          } else if (trimmed.match(/^-?\d+\.?\d*$/)) {
            parts.push(<span key={`num-${i}`} className="cookie-json-number">{trimmed}</span>);
          } else {
            parts.push(<span key={`text-${i}`}>{trimmed}</span>);
          }
        }
        parts.push(<span key={`space-${i}`}>{char}</span>);
        current = '';
      } else {
        current += char;
      }
    }
    
    if (current.trim()) {
      const trimmed = current.trim();
      if (trimmed.match(/^(true|false|null)$/)) {
        parts.push(<span key="final-bool" className="cookie-json-keyword">{trimmed}</span>);
      } else if (trimmed.match(/^-?\d+\.?\d*$/)) {
        parts.push(<span key="final-num" className="cookie-json-number">{trimmed}</span>);
      } else if (inString) {
        parts.push(<span key="final-str" className={isKey ? "cookie-json-key" : "cookie-json-string"}>{trimmed}</span>);
      } else {
        parts.push(<span key="final">{trimmed}</span>);
      }
    }

    return <>{parts}</>;
  };

  const formatSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const requestFormatted = formatBody(request.body, request.contentType, requestFormat);
  const responseFormatted = formatBody(request.responseBody, request.responseHeaders?.['content-type'], responseFormat);

  return (
    <div className="details-view">
      <div className="details-content">
        {/* Request Section */}
        <div className="request-section">
          <div className="request-section-header" style={{ borderLeft: `4px solid ${getMethodColor(request.method)}` }}>
            <div className="request-header-left">
              <span className="http-version">HTTP/1.1</span>
              <span className="method-name" style={{ color: getMethodColor(request.method) }}>
                {request.method}
              </span>
              <span className="section-label">REQUEST</span>
              <div className="url-display">
                <span className="url-host">{getHost(request.url)}</span>
                <span className="url-path">{getPath(request.url)}</span>
              </div>
            </div>
            <div className="header-meta">
              <span className="size-badge">{formatSize(getBodySize(request.body))}</span>
              <select 
                className="format-select" 
                value={requestFormat}
                onChange={(e) => setRequestFormat(e.target.value as any)}
              >
                <option value="auto">Auto</option>
                <option value="json">JSON</option>
                <option value="html">HTML</option>
                <option value="xml">XML</option>
                <option value="raw">Raw</option>
              </select>
              <span className="content-type-badge" style={{ backgroundColor: getContentTypeColor(request.contentType) }}>
                {request.contentType || 'text/plain'}
              </span>
            </div>
          </div>
          
          {/* Request Headers */}
          <div className="headers-section">
            <div className="headers-title">Headers</div>
            <div className="headers-list">
              {formatHeaders(request.headers).map((header, index) => (
                <div key={index} className="header-item">
                  <span className="header-key">{header.key}:</span>
                  <span className="header-value">{header.formattedValue}</span>
                  <button
                    type="button"
                    className="header-copy-btn"
                    title="Copy header value"
                    onClick={() => copyText(header.rawValue)}
                  >
                    <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
                      <rect x="4" y="4" width="8" height="8" rx="1" stroke="currentColor" strokeWidth="1.5" />
                      <path d="M3 2H1C0.45 2 0 2.45 0 3V11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                    </svg>
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="section-content request-body-content">
            {requestFormatted.type === 'empty' ? (
              <div className="empty-response">No request body</div>
            ) : (
              requestFormatted.formatted
            )}
          </div>
        </div>

        {/* Response Section */}
        <div className="response-section">
          <div 
            className="response-section-header" 
            style={{ borderLeft: `4px solid ${getStatusColor(request.status)}` }}
          >
            <span className="status-code" style={{ color: getStatusColor(request.status) }}>
              {request.status || '—'}
            </span>
            <span className="section-label">RESPONSE</span>
            <div className="header-meta">
              <span className="size-badge">{formatSize(getBodySize(request.responseBody))}</span>
              <select 
                className="format-select" 
                value={responseFormat}
                onChange={(e) => setResponseFormat(e.target.value as any)}
              >
                <option value="auto">Auto</option>
                <option value="json">JSON</option>
                <option value="html">HTML</option>
                <option value="xml">XML</option>
                <option value="raw">Raw</option>
              </select>
              <span className="content-type-badge" style={{ backgroundColor: getContentTypeColor(request.responseHeaders?.['content-type']) }}>
                {request.responseHeaders?.['content-type'] || 'text/plain'}
              </span>
            </div>
          </div>

          {/* Response Headers */}
          {request.responseHeaders && (
            <div className="headers-section">
              <div className="headers-title">Headers</div>
              <div className="headers-list">
                {formatHeaders(request.responseHeaders).map((header, index) => (
                  <div key={index} className="header-item">
                    <span className="header-key">{header.key}:</span>
                    <span className="header-value">{header.formattedValue}</span>
                    <button
                      type="button"
                      className="header-copy-btn"
                      title="Copy header value"
                      onClick={() => copyText(header.rawValue)}
                    >
                      <svg width="14" height="14" viewBox="0 0 14 14" fill="none" aria-hidden="true">
                        <rect x="4" y="4" width="8" height="8" rx="1" stroke="currentColor" strokeWidth="1.5" />
                        <path d="M3 2H1C0.45 2 0 2.45 0 3V11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                      </svg>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="section-content response-body-content">
            {responseFormatted.formatted}
          </div>
        </div>
      </div>
    </div>
  );
};

const SyntaxHighlightedCode: React.FC<{ code: string; language: string }> = ({ code, language }) => {
  const highlightCode = (text: string, lang: string): JSX.Element => {
    const lines = text.split('\n');
    
    return (
      <pre className={`code-block language-${lang}`}>
        {lines.map((line, index) => (
          <div key={index} className="code-line">
            <span className="line-number">{index + 1}</span>
            <span className="code-content">{highlightLine(line, lang)}</span>
          </div>
        ))}
      </pre>
    );
  };

  const highlightLine = (line: string, lang: string): JSX.Element => {
    if (lang === 'json') {
      return highlightJSON(line);
    } else if (lang === 'html' || lang === 'xml') {
      return highlightHTML(line);
    } else if (lang === 'css') {
      return highlightCSS(line);
    } else if (lang === 'javascript') {
      return highlightJS(line);
    }
    return <span>{escapeHtml(line)}</span>;
  };

  const highlightJSON = (line: string): JSX.Element => {
    const parts: JSX.Element[] = [];
    let current = '';
    let inString = false;
    let stringChar = '';
    let escapeNext = false;
    let isKey = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      const prevChar = i > 0 ? line[i - 1] : '';
      
      if (escapeNext) {
        current += '\\' + char;
        escapeNext = false;
        continue;
      }
      
      if (char === '\\' && inString) {
        escapeNext = true;
        current += char;
        continue;
      }
      
      if ((char === '"' || char === "'") && !escapeNext) {
        if (inString) {
          // Closing quote - end of string
          if (isKey) {
            parts.push(<span key={`key-${i}`} className="json-key">{current}</span>);
          } else {
            parts.push(<span key={`str-${i}`} className="json-string">{current}</span>);
          }
          parts.push(<span key={`quote-close-${i}`} className={isKey ? "json-key" : "json-string"}>{char}</span>);
          current = '';
          inString = false;
          // Check if next non-whitespace is colon (making it a key)
          const rest = line.substring(i + 1).trim();
          isKey = rest.startsWith(':');
        } else {
          // Opening quote - start of string
          // Check if this will be a key (followed by colon)
          const rest = line.substring(i).match(/^["']([^"']*)["']\s*:/);
          isKey = rest !== null;
          
          // Add any accumulated content before the quote
          if (current.trim()) {
            const trimmed = current.trim();
            if (trimmed.match(/^(true|false|null)$/)) {
              parts.push(<span key={`bool-${i}`} className="json-keyword">{trimmed}</span>);
            } else if (trimmed.match(/^-?\d+\.?\d*(e[+-]?\d+)?$/i)) {
              parts.push(<span key={`num-${i}`} className="json-number">{trimmed}</span>);
            } else {
              parts.push(<span key={`text-${i}`}>{trimmed}</span>);
            }
            current = '';
          }
          
          parts.push(<span key={`quote-open-${i}`} className={isKey ? "json-key" : "json-string"}>{char}</span>);
          inString = true;
          stringChar = char;
          current = '';
        }
      } else if (inString) {
        // Inside string - accumulate content
        current += char;
      } else if (char.match(/[{}[\],:]/)) {
        // Punctuation outside string
        if (current.trim()) {
          const trimmed = current.trim();
          if (trimmed.match(/^(true|false|null)$/)) {
            parts.push(<span key={`bool-${i}`} className="json-keyword">{trimmed}</span>);
          } else if (trimmed.match(/^-?\d+\.?\d*(e[+-]?\d+)?$/i)) {
            parts.push(<span key={`num-${i}`} className="json-number">{trimmed}</span>);
          } else {
            parts.push(<span key={`text-${i}`}>{trimmed}</span>);
          }
          current = '';
        }
        parts.push(<span key={`punc-${i}`} className="json-punctuation">{char}</span>);
        if (char === ':') {
          isKey = false; // After colon, next value is not a key
        }
      } else {
        current += char;
      }
    }
    
    // Handle remaining content
    if (current) {
      if (inString) {
        // Unclosed string
        parts.push(<span key="final-str" className={isKey ? "json-key" : "json-string"}>{current}</span>);
      } else {
        const trimmed = current.trim();
        if (trimmed) {
          if (trimmed.match(/^(true|false|null)$/)) {
            parts.push(<span key="final-bool" className="json-keyword">{trimmed}</span>);
          } else if (trimmed.match(/^-?\d+\.?\d*(e[+-]?\d+)?$/i)) {
            parts.push(<span key="final-num" className="json-number">{trimmed}</span>);
          } else {
            parts.push(<span key="final">{trimmed}</span>);
          }
        }
      }
    }

    return <>{parts}</>;
  };

  const highlightHTML = (line: string): JSX.Element => {
    const parts: JSX.Element[] = [];
    const tagRegex = /(&lt;\/?[\w\s="'-]+&gt;)/g;
    const matches = line.match(/(&lt;\/?[\w\s="'-]+&gt;)|([^<]+)/g) || [];
    
    matches.forEach((match, i) => {
      if (match.startsWith('&lt;')) {
        parts.push(<span key={i} className="html-tag">{match}</span>);
      } else {
        parts.push(<span key={i}>{match}</span>);
      }
    });
    
    return <>{parts}</>;
  };

  const highlightCSS = (line: string): JSX.Element => {
    const parts: JSX.Element[] = [];
    const selectorRegex = /([^{}]+)(\{[^}]*\})/g;
    let match;
    
    while ((match = selectorRegex.exec(line)) !== null) {
      parts.push(<span key={`sel-${match.index}`} className="css-selector">{match[1]}</span>);
      parts.push(<span key={`prop-${match.index}`} className="css-property">{match[2]}</span>);
    }
    
    if (parts.length === 0) {
      return <span>{line}</span>;
    }
    
    return <>{parts}</>;
  };

  const highlightJS = (line: string): JSX.Element => {
    const parts: JSX.Element[] = [];
    const keywords = ['function', 'const', 'let', 'var', 'if', 'else', 'for', 'while', 'return', 'async', 'await', 'class', 'extends', 'import', 'export'];
    const words = line.split(/(\s+|\(|\)|{|}|;|,)/);
    
    words.forEach((word, i) => {
      if (keywords.includes(word.trim())) {
        parts.push(<span key={i} className="js-keyword">{word}</span>);
      } else if (word.match(/^['"].*['"]$/)) {
        parts.push(<span key={i} className="js-string">{word}</span>);
      } else if (word.match(/^\d+$/)) {
        parts.push(<span key={i} className="js-number">{word}</span>);
      } else {
        parts.push(<span key={i}>{word}</span>);
      }
    });
    
    return <>{parts}</>;
  };

  const escapeHtml = (text: string): string => {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  };

  return highlightCode(code, language);
};

const getContentTypeColor = (contentType?: string): string => {
  if (!contentType) return '#95a5a6';
  const ct = contentType.toLowerCase();
  
  if (ct.includes('json')) return '#3498db';
  if (ct.includes('html')) return '#e74c3c';
  if (ct.includes('xml')) return '#9b59b6';
  if (ct.includes('javascript') || ct.includes('ecmascript')) return '#f39c12';
  if (ct.includes('css')) return '#3498db';
  if (ct.includes('image')) return '#2ecc71';
  if (ct.includes('video')) return '#e67e22';
  if (ct.includes('audio')) return '#1abc9c';
  if (ct.includes('text')) return '#34495e';
  if (ct.includes('application')) return '#16a085';
  
  return '#95a5a6';
};

// Export for use in other components
export { getContentTypeColor };

export default memo(DetailsView, (prev, next) => requestDetailEqual(prev.request, next.request));
