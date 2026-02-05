import React, { useState, useEffect, memo } from 'react';
import { HttpRequest } from '../../main/proxy-server';
import { requestDetailEqual } from '../utils/requestEqual';
import { EmptyState } from './EmptyState';
import { SequencerHeaderIcon } from './ToolIcons';
import './Sequencer.css';

interface SequencerProps {
  request: HttpRequest | null;
}

interface TokenAnalysis {
  token: string;
  source: 'cookie' | 'header' | 'body' | 'url';
  name: string;
  entropy: number;
  length: number;
  characterDistribution: Record<string, number>;
  patterns: string[];
  randomness: 'high' | 'medium' | 'low' | 'very-low';
  recommendations: string[];
}

const Sequencer: React.FC<SequencerProps> = ({ request }) => {
  const [analyses, setAnalyses] = useState<TokenAnalysis[]>([]);
  const [selectedToken, setSelectedToken] = useState<string | null>(null);

  // Calculate Shannon entropy
  const calculateEntropy = (str: string): number => {
    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  };

  // Analyze character distribution
  const analyzeDistribution = (str: string): Record<string, number> => {
    const dist: Record<string, number> = {};
    for (const char of str) {
      dist[char] = (dist[char] || 0) + 1;
    }
    return dist;
  };

  // Detect patterns
  const detectPatterns = (str: string): string[] => {
    const patterns: string[] = [];

    // Check for sequential patterns
    if (/012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i.test(str)) {
      patterns.push('Sequential characters detected');
    }

    // Check for repeating patterns
    if (/(.)\1{2,}/.test(str)) {
      patterns.push('Repeating characters detected');
    }

    // Check for base64-like
    if (/^[A-Za-z0-9+/=]+$/.test(str) && str.length % 4 === 0) {
      patterns.push('Base64-like encoding');
    }

    // Check for hex-like
    if (/^[0-9a-fA-F]+$/.test(str)) {
      patterns.push('Hexadecimal-like encoding');
    }

    // Check for UUID-like
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(str)) {
      patterns.push('UUID format');
    }

    // Check for timestamp-like
    if (/^\d{10,13}$/.test(str)) {
      patterns.push('Possible timestamp');
    }

    // Check for predictable increments
    const numbers = str.match(/\d+/g);
    if (numbers && numbers.length > 1) {
      const diffs = numbers.slice(1).map((n, i) => parseInt(n) - parseInt(numbers[i]));
      if (diffs.every(d => d === diffs[0])) {
        patterns.push('Predictable numeric increments');
      }
    }

    return patterns;
  };

  // Determine randomness level
  const getRandomness = (entropy: number, length: number): 'high' | 'medium' | 'low' | 'very-low' => {
    const maxEntropy = Math.log2(62); // alphanumeric + some special chars
    const normalizedEntropy = entropy / maxEntropy;
    const score = normalizedEntropy * (length / 32); // Normalize by length

    if (score > 0.8) return 'high';
    if (score > 0.6) return 'medium';
    if (score > 0.4) return 'low';
    return 'very-low';
  };

  // Get recommendations
  const getRecommendations = (analysis: TokenAnalysis): string[] => {
    const recs: string[] = [];

    if (analysis.randomness === 'very-low' || analysis.randomness === 'low') {
      recs.push('Low entropy – token may be predictable');
      recs.push('Consider using cryptographically secure random generators');
    }

    if (analysis.entropy < 3) {
      recs.push('Very low entropy – easily brute-forced');
    }

    if (analysis.patterns.some(p => p.includes('Sequential') || p.includes('Repeating'))) {
      recs.push('Predictable patterns detected');
    }

    if (analysis.patterns.some(p => p.includes('timestamp'))) {
      recs.push('Timestamp-based tokens are predictable');
    }

    if (analysis.length < 16) {
      recs.push('Short token length – consider longer tokens');
    }

    if (analysis.randomness === 'high' && analysis.entropy > 4) {
      recs.push('Good entropy – token appears cryptographically secure');
    }

    return recs;
  };

  // Extract tokens from request
  const extractTokens = (req: HttpRequest): TokenAnalysis[] => {
    const tokens: TokenAnalysis[] = [];

    const looksTokenishValue = (v: string): boolean => {
      const s = String(v || '').trim();
      if (s.length < 12) return false;
      if (/\s/.test(s)) return false;
      if (/^\d+(\.\d+){1,3}$/.test(s)) return false; // versions like 537.36 / 121.0.0.0
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return true; // UUID
      if (/^eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/.test(s)) return true; // JWT
      if (/^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}$/i.test(s)) return true; // GitHub
      if (/^glpat-[A-Za-z0-9_-]{20,}$/i.test(s)) return true; // GitLab
      if (/^xox[baprs]-[A-Za-z0-9-]{10,}$/i.test(s)) return true; // Slack
      if (/^SG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/i.test(s)) return true; // SendGrid
      if (/^[A-Za-z0-9+/_-]{24,}={0,2}$/.test(s)) return true; // base64-ish
      if (/^[0-9a-f]{24,}$/i.test(s)) return true; // hex-ish
      return calculateEntropy(s) >= 3.2;
    };

    const nameLooksTokenish = (n: string): boolean =>
      /(token|auth|bearer|session|sess|sid|csrf|xsrf|jwt|access|refresh|secret|key|api[_-]?key|id_token|client_secret)/i.test(
        n || ''
      );

    // Extract from cookies
    const cookieHeader = req.headers['cookie'] || req.headers['Cookie'] || '';
    if (cookieHeader) {
      const cookies = cookieHeader.split(';').map(c => c.trim());
      for (const cookie of cookies) {
        const [name, value] = cookie.split('=').map(s => s.trim());
        if (value && (nameLooksTokenish(name) || looksTokenishValue(value))) {
          const entropy = calculateEntropy(value);
          const distribution = analyzeDistribution(value);
          const patterns = detectPatterns(value);
          const randomness = getRandomness(entropy, value.length);
          const analysis: TokenAnalysis = {
            token: value,
            source: 'cookie',
            name: name,
            entropy,
            length: value.length,
            characterDistribution: distribution,
            patterns,
            randomness,
            recommendations: [],
          };
          analysis.recommendations = getRecommendations(analysis);
          tokens.push(analysis);
        }
      }
    }

    // Extract from headers (session tokens, CSRF tokens, etc.)
    const tokenHeaders = ['x-session-token', 'x-csrf-token', 'authorization', 'x-api-key', 'x-auth-token'];
    for (const headerName of tokenHeaders) {
      const headerValue = req.headers[headerName.toLowerCase()] || req.headers[headerName];
      if (headerValue && headerValue.length > 8) {
        // Extract Bearer token if present
        const token = headerValue.startsWith('Bearer ') ? headerValue.substring(7) : headerValue;
        if (looksTokenishValue(token)) {
          const entropy = calculateEntropy(token);
          const distribution = analyzeDistribution(token);
          const patterns = detectPatterns(token);
          const randomness = getRandomness(entropy, token.length);
          const analysis: TokenAnalysis = {
            token: token,
            source: 'header',
            name: headerName,
            entropy,
            length: token.length,
            characterDistribution: distribution,
            patterns,
            randomness,
            recommendations: [],
          };
          analysis.recommendations = getRecommendations(analysis);
          tokens.push(analysis);
        }
      }
    }

    // Extract from URL parameters
    try {
      const url = new URL(req.url);
      for (const [key, value] of url.searchParams.entries()) {
        if (value && (nameLooksTokenish(key) || looksTokenishValue(value))) {
          const entropy = calculateEntropy(value);
          const distribution = analyzeDistribution(value);
          const patterns = detectPatterns(value);
          const randomness = getRandomness(entropy, value.length);
          const analysis: TokenAnalysis = {
            token: value,
            source: 'url',
            name: key,
            entropy,
            length: value.length,
            characterDistribution: distribution,
            patterns,
            randomness,
            recommendations: [],
          };
          analysis.recommendations = getRecommendations(analysis);
          tokens.push(analysis);
        }
      }
    } catch {}

    // Extract from body (JSON)
    if (req.body) {
      try {
        const body = JSON.parse(req.body);
        const extractFromObject = (obj: any, prefix = '') => {
          for (const [key, value] of Object.entries(obj)) {
            if (typeof value === 'string' && (nameLooksTokenish(key) || looksTokenishValue(value))) {
              const entropy = calculateEntropy(value);
              const distribution = analyzeDistribution(value);
              const patterns = detectPatterns(value);
              const randomness = getRandomness(entropy, value.length);
              const analysis: TokenAnalysis = {
                token: value,
                source: 'body',
                name: prefix ? `${prefix}.${key}` : key,
                entropy,
                length: value.length,
                characterDistribution: distribution,
                patterns,
                randomness,
                recommendations: [],
              };
              analysis.recommendations = getRecommendations(analysis);
              tokens.push(analysis);
            } else if (typeof value === 'object' && value !== null) {
              extractFromObject(value, prefix ? `${prefix}.${key}` : key);
            }
          }
        };
        extractFromObject(body);
      } catch {}
    }

    return tokens;
  };

  useEffect(() => {
    if (request) {
      const extracted = extractTokens(request);
      setAnalyses(extracted);
      if (extracted.length > 0) {
        setSelectedToken(extracted[0].token);
      }
    } else {
      setAnalyses([]);
      setSelectedToken(null);
    }
  }, [request]);

  const getRandomnessColor = (randomness: string): string => {
    switch (randomness) {
      case 'high': return '#2ecc71';
      case 'medium': return '#f39c12';
      case 'low': return '#e74c3c';
      case 'very-low': return '#9b59b6';
      default: return '#858585';
    }
  };

  const selectedAnalysis = analyses.find(a => a.token === selectedToken);

  if (!request) {
    return (
      <div className="sequencer-view">
        <EmptyState icon="sequencer" title="Select a request to analyze token randomness" brandName="CleanTraffic" />
      </div>
    );
  }

  if (analyses.length === 0) {
    return (
      <div className="sequencer-view">
        <EmptyState
          icon="sequencer"
          title="No tokens found in this request"
          subtitle="Tokens are extracted from cookies, headers, URL parameters, and request body"
          brandName="CleanTraffic"
        />
      </div>
    );
  }

  return (
    <div className="sequencer-view">
      <div className="sequencer-header">
        <div className="sequencer-title">
          <SequencerHeaderIcon />
        </div>
        <p className="sequencer-subtitle">Analyze randomness and entropy of tokens and session IDs</p>
      </div>

      <div className="sequencer-content">
        <div className="tokens-list">
          <h3>Detected Tokens ({analyses.length})</h3>
          {analyses.map((analysis, index) => (
            <div
              key={index}
              className={`token-item ${selectedToken === analysis.token ? 'selected' : ''}`}
              onClick={() => setSelectedToken(analysis.token)}
            >
              <div className="token-header">
                <span className="token-name">{analysis.name}</span>
                <span className="token-source">{analysis.source}</span>
              </div>
              <div className="token-preview">{analysis.token.substring(0, 40)}{analysis.token.length > 40 ? '...' : ''}</div>
              <div className="token-stats">
                <span className="stat-badge" style={{ backgroundColor: getRandomnessColor(analysis.randomness) }}>
                  {analysis.randomness.toUpperCase()}
                </span>
                <span className="stat-text">Entropy: {analysis.entropy.toFixed(2)}</span>
                <span className="stat-text">Length: {analysis.length}</span>
              </div>
            </div>
          ))}
        </div>

        {selectedAnalysis && (
          <div className="token-analysis">
            <div className="analysis-header">
              <h3>Analysis: {selectedAnalysis.name}</h3>
              <span className="source-badge">{selectedAnalysis.source}</span>
            </div>

            <div className="analysis-sections">
              <div className="analysis-section">
                <h4>Entropy Analysis</h4>
                <div className="entropy-display">
                  <div className="entropy-value">{selectedAnalysis.entropy.toFixed(4)}</div>
                  <div className="entropy-bar">
                    <div
                      className="entropy-fill"
                      style={{
                        width: `${(selectedAnalysis.entropy / 8) * 100}%`,
                        backgroundColor: getRandomnessColor(selectedAnalysis.randomness),
                      }}
                    />
                  </div>
                  <div className="entropy-label">
                    Randomness: <strong>{selectedAnalysis.randomness.toUpperCase()}</strong>
                  </div>
                </div>
              </div>

              <div className="analysis-section">
                <h4>Token Details</h4>
                <div className="details-grid">
                  <div className="detail-item">
                    <span className="detail-label">Full Token:</span>
                    <code className="detail-value">{selectedAnalysis.token}</code>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">Length:</span>
                    <span className="detail-value">{selectedAnalysis.length} characters</span>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">Source:</span>
                    <span className="detail-value">{selectedAnalysis.source}</span>
                  </div>
                </div>
              </div>

              {selectedAnalysis.patterns.length > 0 && (
                <div className="analysis-section">
                  <h4>Detected Patterns</h4>
                  <div className="patterns-list">
                    {selectedAnalysis.patterns.map((pattern, idx) => (
                      <span key={idx} className="pattern-badge">{pattern}</span>
                    ))}
                  </div>
                </div>
              )}

              <div className="analysis-section">
                <h4>Character Distribution</h4>
                <div className="distribution-chart">
                  {Object.entries(selectedAnalysis.characterDistribution)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 20)
                    .map(([char, count]) => (
                      <div key={char} className="dist-item">
                        <span className="dist-char">{char === ' ' ? 'SPACE' : char}</span>
                        <div className="dist-bar">
                          <div
                            className="dist-fill"
                            style={{
                              width: `${(count / selectedAnalysis.length) * 100}%`,
                            }}
                          />
                        </div>
                        <span className="dist-count">{count} ({((count / selectedAnalysis.length) * 100).toFixed(1)}%)</span>
                      </div>
                    ))}
                </div>
              </div>

              {selectedAnalysis.recommendations.length > 0 && (
                <div className="analysis-section">
                  <h4>Security Recommendations</h4>
                  <div className="recommendations-list">
                    {selectedAnalysis.recommendations.map((rec, idx) => (
                      <div key={idx} className="recommendation-item">{rec}</div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default memo(Sequencer, (prev, next) => requestDetailEqual(prev.request, next.request));

