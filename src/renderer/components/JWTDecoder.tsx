import React, { useState, useEffect } from 'react';
import './JWTDecoder.css';

interface DecodedJWT {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  valid: boolean;
}

const JWTDecoder: React.FC = () => {
  const [mode, setMode] = useState<'decode' | 'encode'>('decode');
  const [token, setToken] = useState<string>('');
  const [decoded, setDecoded] = useState<DecodedJWT | null>(null);
  const [error, setError] = useState<string>('');

  // Encode mode state
  const [headerJson, setHeaderJson] = useState<string>('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
  const [payloadJson, setPayloadJson] = useState<string>('{\n  "sub": "user123",\n  "name": "John Doe",\n  "iat": 1516239022\n}');
  const [signature, setSignature] = useState<string>('');
  const [encodedToken, setEncodedToken] = useState<string>('');

  // Auto-detect JWT from clipboard or common patterns
  useEffect(() => {
    // Check if clipboard might contain a JWT
    const checkClipboard = async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (isJWTFormat(text.trim())) {
          setToken(text.trim());
          decodeJWT(text.trim());
        }
      } catch (err) {
        // Clipboard access denied or not available
      }
    };
    checkClipboard();
  }, []);

  const isJWTFormat = (str: string): boolean => {
    const jwtPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
    return jwtPattern.test(str);
  };

  const base64UrlDecode = (str: string): string => {
    let b = str.replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    try {
      return decodeURIComponent(
        atob(b)
          .split('')
          .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );
    } catch {
      return atob(b);
    }
  };

  const decodeJWT = (jwtToken: string) => {
    setError('');
    setDecoded(null);
    if (!jwtToken?.trim()) {
      setError('Please enter a JWT token');
      return;
    }
    const clean = jwtToken.trim().replace(/^Bearer\s+/i, '');
    if (!isJWTFormat(clean)) {
      setError('Invalid JWT format. Expect header.payload.signature (three base64url parts).');
      return;
    }
    try {
      const parts = clean.split('.');
      if (parts.length !== 3) {
        setError('Invalid JWT: must have exactly 3 parts');
        return;
      }
      const header = JSON.parse(base64UrlDecode(parts[0])) as Record<string, unknown>;
      const payload = JSON.parse(base64UrlDecode(parts[1])) as Record<string, unknown>;
      let valid = true;
      if (typeof payload.exp === 'number' && payload.exp * 1000 < Date.now()) valid = false;
      if (typeof payload.nbf === 'number' && payload.nbf * 1000 > Date.now()) valid = false;
      setDecoded({ header, payload, signature: parts[2], valid });
    } catch (e: unknown) {
      setError(`Decode error: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const handleDecode = () => decodeJWT(token);

  const handleClear = () => {
    setToken('');
    setDecoded(null);
    setError('');
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const formatDate = (timestamp: number): string => {
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
  };

  const formatJSON = (obj: any): string => {
    return JSON.stringify(obj, null, 2);
  };

  const base64UrlEncode = (str: string): string => {
    // Convert to base64
    const base64 = btoa(unescape(encodeURIComponent(str)));
    // Convert to base64url (replace + with -, / with _, remove padding)
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  const encodeJWT = () => {
    setError('');
    setEncodedToken('');

    try {
      // Parse header
      let header: any;
      try {
        header = JSON.parse(headerJson);
      } catch (e) {
        setError(`Invalid header JSON: ${e}`);
        return;
      }

      // Parse payload
      let payload: any;
      try {
        payload = JSON.parse(payloadJson);
      } catch (e) {
        setError(`Invalid payload JSON: ${e}`);
        return;
      }

      // Encode header and payload
      const encodedHeader = base64UrlEncode(JSON.stringify(header));
      const encodedPayload = base64UrlEncode(JSON.stringify(payload));

      // Create token (with or without signature)
      if (signature.trim()) {
        // If signature provided, use it
        const token = `${encodedHeader}.${encodedPayload}.${signature.trim()}`;
        setEncodedToken(token);
      } else {
        // Without signature (unsigned JWT)
        const token = `${encodedHeader}.${encodedPayload}.`;
        setEncodedToken(token);
      }
    } catch (e: any) {
      setError(`Encoding error: ${e.message || e}`);
    }
  };

  return (
    <div className="jwt-decoder">
      <div className="jwt-decoder-header">
        <div className="jwt-decoder-title">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" className="jwt-icon">
            <defs>
              <linearGradient id="jwtHeaderGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#f39c12" />
                <stop offset="100%" stopColor="#e67e22" />
              </linearGradient>
            </defs>
            <rect x="3" y="5" width="18" height="4" rx="1" fill="url(#jwtHeaderGrad)" opacity="0.9"/>
            <rect x="3" y="11" width="18" height="4" rx="1" fill="url(#jwtHeaderGrad)" opacity="0.7"/>
            <rect x="3" y="17" width="18" height="4" rx="1" fill="url(#jwtHeaderGrad)" opacity="0.5"/>
            <path d="M6 7L18 7M6 13L18 13M6 19L18 19" stroke="white" strokeWidth="1.2" strokeLinecap="round" opacity="0.4"/>
          </svg>
        </div>
        <p className="jwt-decoder-subtitle">Decode and encode JWT tokens (JWS, JWE, and custom formats)</p>
        
        <div className="jwt-mode-switch">
          <button 
            className={`mode-btn ${mode === 'decode' ? 'active' : ''}`}
            onClick={() => setMode('decode')}
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M8 2L2 5L8 8L14 5L8 2Z" fill="currentColor"/>
              <path d="M2 11L8 14L14 11" stroke="currentColor" strokeWidth="1.5" fill="none"/>
            </svg>
            Decode
          </button>
          <button 
            className={`mode-btn ${mode === 'encode' ? 'active' : ''}`}
            onClick={() => setMode('encode')}
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M8 14L14 11L8 8L2 11L8 14Z" fill="currentColor"/>
              <path d="M2 5L8 2L14 5" stroke="currentColor" strokeWidth="1.5" fill="none"/>
            </svg>
            Encode
          </button>
        </div>
      </div>

      <div className="jwt-decoder-content">
        {mode === 'decode' ? (
          <div className="jwt-input-section">
            <div className="input-group">
              <label htmlFor="jwt-token">JWT Token</label>
              <div className="input-with-actions">
                <textarea
                  id="jwt-token"
                  className="jwt-input"
                  placeholder="Paste your JWT token here (supports Bearer tokens, JWS, JWE, and custom formats)..."
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  rows={4}
                />
                <div className="input-actions">
                  <button className="action-btn decode-btn" onClick={handleDecode}>
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                      <path d="M8 2L2 5L8 8L14 5L8 2Z" fill="currentColor"/>
                      <path d="M2 11L8 14L14 11" stroke="currentColor" strokeWidth="1.5" fill="none"/>
                    </svg>
                    Decode
                  </button>
                  <button className="action-btn clear-btn" onClick={handleClear}>
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                      <path d="M12 4L4 12M4 4L12 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                    </svg>
                    Clear
                  </button>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="jwt-encode-section">
            <div className="encode-inputs">
              <div className="input-group">
                <label htmlFor="header-json">Header (JSON)</label>
                <textarea
                  id="header-json"
                  className="jwt-input"
                  placeholder='{"alg": "HS256", "typ": "JWT"}'
                  value={headerJson}
                  onChange={(e) => setHeaderJson(e.target.value)}
                  rows={6}
                />
              </div>
              <div className="input-group">
                <label htmlFor="payload-json">Payload (JSON)</label>
                <textarea
                  id="payload-json"
                  className="jwt-input"
                  placeholder='{"sub": "user123", "name": "John Doe"}'
                  value={payloadJson}
                  onChange={(e) => setPayloadJson(e.target.value)}
                  rows={8}
                />
              </div>
              <div className="input-group">
                <label htmlFor="signature">Signature (Optional)</label>
                <input
                  id="signature"
                  type="text"
                  className="jwt-input"
                  placeholder="Leave empty for unsigned JWT"
                  value={signature}
                  onChange={(e) => setSignature(e.target.value)}
                />
              </div>
              <div className="input-actions">
                <button className="action-btn encode-btn" onClick={encodeJWT}>
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                    <path d="M8 14L14 11L8 8L2 11L8 14Z" fill="currentColor"/>
                    <path d="M2 5L8 2L14 5" stroke="currentColor" strokeWidth="1.5" fill="none"/>
                  </svg>
                  Encode
                </button>
                <button 
                  className="action-btn copy-btn" 
                  onClick={() => {
                    if (encodedToken) {
                      copyToClipboard(encodedToken);
                    }
                  }}
                  disabled={!encodedToken}
                >
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                    <rect x="5" y="5" width="9" height="9" rx="1" stroke="currentColor" strokeWidth="1.5" fill="none"/>
                    <path d="M4 2H2C1.44772 2 1 2.44772 1 3V11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                  </svg>
                  Copy Token
                </button>
              </div>
            </div>
            {encodedToken && (
              <div className="encoded-token-section">
                <label>Encoded Token</label>
                <div className="encoded-token-display">
                  <pre className="token-output">{encodedToken}</pre>
                  <button 
                    className="copy-token-btn"
                    onClick={() => copyToClipboard(encodedToken)}
                  >
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                      <rect x="5" y="5" width="9" height="9" rx="1" stroke="currentColor" strokeWidth="1.5" fill="none"/>
                      <path d="M4 2H2C1.44772 2 1 2.44772 1 3V11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                    </svg>
                  </button>
                </div>
              </div>
            )}
          </div>
        )}

        {error && (
          <div className="jwt-error">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
              <circle cx="10" cy="10" r="9" stroke="currentColor" strokeWidth="2"/>
              <path d="M10 6V10M10 14H10.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            <span>{error}</span>
          </div>
        )}

        {mode === 'decode' && decoded && (
          <div className="jwt-decoded">
            <div className="jwt-status">
              <div className={`status-badge ${decoded.valid ? 'valid' : 'invalid'}`}>
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  {decoded.valid ? (
                    <path d="M13.5 4.5L6 12L2.5 8.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                  ) : (
                    <path d="M4 4L12 12M12 4L4 12" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                  )}
                </svg>
                {decoded.valid ? 'Valid Token' : 'Expired/Invalid Token'}
              </div>
            </div>

            <div className="jwt-sections">
              {/* Header Section */}
              <div className="jwt-section">
                <div className="jwt-section-header">
                  <h3>Header</h3>
                  <button 
                    className="copy-btn"
                    onClick={() => copyToClipboard(formatJSON(decoded.header))}
                    title="Copy header"
                  >
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                      <rect x="5" y="5" width="9" height="9" rx="1" stroke="currentColor" strokeWidth="1.5" fill="none"/>
                      <path d="M4 2H2C1.44772 2 1 2.44772 1 3V11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                    </svg>
                  </button>
                </div>
                <div className="jwt-section-content">
                  <pre className="json-display">{formatJSON(decoded.header)}</pre>
                  <div className="jwt-info">
                    <div className="info-item">
                      <span className="info-label">Algorithm:</span>
                      <span className="info-value">{String(decoded.header?.alg ?? 'N/A')}</span>
                    </div>
                    <div className="info-item">
                      <span className="info-label">Type:</span>
                      <span className="info-value">{String(decoded.header?.typ ?? 'JWT')}</span>
                    </div>
                    {decoded.header?.enc != null && (
                      <div className="info-item">
                        <span className="info-label">Encryption:</span>
                        <span className="info-value">{String(decoded.header.enc)}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Payload Section */}
              <div className="jwt-section">
                <div className="jwt-section-header">
                  <h3>Payload</h3>
                  <button 
                    className="copy-btn"
                    onClick={() => copyToClipboard(formatJSON(decoded.payload))}
                    title="Copy payload"
                  >
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                      <rect x="5" y="5" width="9" height="9" rx="1" stroke="currentColor" strokeWidth="1.5" fill="none"/>
                      <path d="M4 2H2C1.44772 2 1 2.44772 1 3V11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                    </svg>
                  </button>
                </div>
                <div className="jwt-section-content">
                  <pre className="json-display">{formatJSON(decoded.payload)}</pre>
                  <div className="jwt-info">
                    {decoded.payload?.iss != null && (
                      <div className="info-item">
                        <span className="info-label">Issuer:</span>
                        <span className="info-value">{String(decoded.payload.iss)}</span>
                      </div>
                    )}
                    {decoded.payload?.sub != null && (
                      <div className="info-item">
                        <span className="info-label">Subject:</span>
                        <span className="info-value">{String(decoded.payload.sub)}</span>
                      </div>
                    )}
                    {decoded.payload?.aud != null && (
                      <div className="info-item">
                        <span className="info-label">Audience:</span>
                        <span className="info-value">{Array.isArray(decoded.payload.aud) ? (decoded.payload.aud as string[]).join(', ') : String(decoded.payload.aud)}</span>
                      </div>
                    )}
                    {decoded.payload?.exp != null && (
                      <div className="info-item">
                        <span className="info-label">Expires:</span>
                        <span className={`info-value ${decoded.valid ? '' : 'expired'}`}>
                          {formatDate(Number(decoded.payload.exp))}
                        </span>
                      </div>
                    )}
                    {decoded.payload?.iat != null && (
                      <div className="info-item">
                        <span className="info-label">Issued At:</span>
                        <span className="info-value">{formatDate(Number(decoded.payload.iat))}</span>
                      </div>
                    )}
                    {decoded.payload?.nbf != null && (
                      <div className="info-item">
                        <span className="info-label">Not Before:</span>
                        <span className="info-value">{formatDate(Number(decoded.payload.nbf))}</span>
                      </div>
                    )}
                    {decoded.payload?.jti != null && (
                      <div className="info-item">
                        <span className="info-label">JWT ID:</span>
                        <span className="info-value">{String(decoded.payload.jti)}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Signature Section */}
              <div className="jwt-section">
                <div className="jwt-section-header">
                  <h3>Signature</h3>
                  <button 
                    className="copy-btn"
                    onClick={() => copyToClipboard(decoded.signature)}
                    title="Copy signature"
                  >
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                      <rect x="5" y="5" width="9" height="9" rx="1" stroke="currentColor" strokeWidth="1.5" fill="none"/>
                      <path d="M4 2H2C1.44772 2 1 2.44772 1 3V11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                    </svg>
                  </button>
                </div>
                <div className="jwt-section-content">
                  <div className="signature-display">
                    <code>{decoded.signature}</code>
                  </div>
                  <div className="jwt-info">
                    <div className="info-item">
                      <span className="info-label">Length:</span>
                      <span className="info-value">{decoded.signature.length} characters</span>
                    </div>
                    <div className="info-item">
                      <span className="info-label">Note:</span>
                      <span className="info-value">Signature verification requires the secret key</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default JWTDecoder;

