import React, { useState, useEffect, memo } from 'react';
import { HttpRequest } from '../../main/proxy-server';
import { requestDetailEqual } from '../utils/requestEqual';
import { getInvestigationSignals, findReflectedParams } from '../../shared/investigation-signals';
import { EmptyState } from './EmptyState';
import { AnalyzerHeaderIcon } from './ToolIcons';
import './ResponseAnalyzer.css';

interface ResponseAnalyzerProps {
  request: HttpRequest | null;
}

interface SecurityAnalysis {
  category: string;
  checks: {
    name: string;
    status: 'pass' | 'fail' | 'warning' | 'info';
    message: string;
    recommendation?: string;
  }[];
}

const ResponseAnalyzer: React.FC<ResponseAnalyzerProps> = ({ request }) => {
  const [analysis, setAnalysis] = useState<SecurityAnalysis[]>([]);

  useEffect(() => {
    if (request) {
      analyzeResponse(request);
    } else {
      setAnalysis([]);
    }
  }, [request]);

  const analyzeResponse = (req: HttpRequest) => {
    const headers = req.responseHeaders || {};
    const body = req.responseBody || '';
    const status = req.status || 0;

    const results: SecurityAnalysis[] = [];

    // Investigation points (pentest / bug-hunt)
    const inv = getInvestigationSignals(req);
    const reflected = findReflectedParams(req);
    const invSection: SecurityAnalysis = {
      category: 'Investigation points',
      checks: [],
    };
    invSection.checks.push({
      name: 'Risk',
      status: inv.risk === 'high' ? 'fail' : inv.risk === 'medium' ? 'warning' : 'info',
      message: inv.reasons.length
        ? `${inv.risk === 'high' ? 'High' : inv.risk === 'medium' ? 'Medium' : 'Low'}-value. ${inv.reasons.slice(0, 2).join('; ')}`
        : inv.risk === 'info' ? 'No high-signal pentest findings' : `Assessed ${inv.risk}-value.`,
    });
    if (inv.sensitiveParams.length) {
      invSection.checks.push({
        name: 'Sensitive params',
        status: 'warning',
        message: inv.sensitiveParams.join(', '),
        recommendation: 'Fuzz redirect, file, id, callback, etc. for XSS/SSRF/IDOR',
      });
    }
    if (inv.idorCandidates.length) {
      invSection.checks.push({
        name: 'IDOR candidates',
        status: 'warning',
        message: inv.idorCandidates.join(', '),
        recommendation: 'Try other user/resource IDs; check authz',
      });
    }
    if (reflected.length) {
      invSection.checks.push({
        name: 'Input reflection',
        status: 'fail',
        message: reflected.map((r) => `${r.param}=… reflected`).join('; '),
        recommendation: 'Check for XSS, SSTI, or injection',
      });
    }
    if (inv.tags.includes('no-auth')) {
      invSection.checks.push({
        name: 'No auth',
        status: 'warning',
        message: 'High-value path without auth headers',
        recommendation: 'Verify access control; test unauthenticated access',
      });
    }
    if (inv.tags.includes('cache-poisoning-candidate')) {
      invSection.checks.push({
        name: 'Cache-poisoning candidate',
        status: 'warning',
        message: 'Request uses cache-key–related headers (X-Forwarded-Host, etc.)',
        recommendation: 'Test cache key normalization and unkeyed headers',
      });
    }
    if (inv.tags.includes('websocket')) {
      invSection.checks.push({
        name: 'WebSocket',
        status: 'info',
        message: 'WebSocket upgrade or ws/wss URL',
        recommendation: 'Inspect frames for auth tokens and fuzzable messages',
      });
    }
    if (invSection.checks.length <= 1 && inv.tags.length) {
      invSection.checks.push({
        name: 'Signals',
        status: 'info',
        message: inv.tags.slice(0, 5).join(', '),
      });
    }
    if (invSection.checks.length) results.push(invSection);

    // Security Headers Analysis
    const securityHeaders: SecurityAnalysis = {
      category: 'Security Headers',
      checks: [],
    };

    // Content-Security-Policy
    if (headers['content-security-policy'] || headers['Content-Security-Policy']) {
      const csp = (headers['content-security-policy'] || headers['Content-Security-Policy']).toLowerCase();
      if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
        securityHeaders.checks.push({
          name: 'Content-Security-Policy',
          status: 'warning',
          message: 'CSP contains unsafe directives',
          recommendation: 'Remove unsafe-inline and unsafe-eval, use nonces or hashes instead',
        });
      } else {
        securityHeaders.checks.push({
          name: 'Content-Security-Policy',
          status: 'pass',
          message: 'CSP is configured',
        });
      }
    } else {
      securityHeaders.checks.push({
        name: 'Content-Security-Policy',
        status: 'fail',
        message: 'CSP header is missing',
        recommendation: 'Add Content-Security-Policy header to prevent XSS attacks',
      });
    }

    // X-Frame-Options
    if (headers['x-frame-options'] || headers['X-Frame-Options']) {
      const xfo = (headers['x-frame-options'] || headers['X-Frame-Options']).toLowerCase();
      if (xfo === 'deny' || xfo === 'sameorigin') {
        securityHeaders.checks.push({
          name: 'X-Frame-Options',
          status: 'pass',
          message: `X-Frame-Options is set to ${xfo}`,
        });
      } else {
        securityHeaders.checks.push({
          name: 'X-Frame-Options',
          status: 'warning',
          message: `X-Frame-Options is set to ${xfo}`,
          recommendation: 'Use "DENY" or "SAMEORIGIN" for better protection',
        });
      }
    } else {
      securityHeaders.checks.push({
        name: 'X-Frame-Options',
        status: 'fail',
        message: 'X-Frame-Options header is missing',
        recommendation: 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking',
      });
    }

    // X-Content-Type-Options
    if (headers['x-content-type-options'] || headers['X-Content-Type-Options']) {
      const xcto = (headers['x-content-type-options'] || headers['X-Content-Type-Options']).toLowerCase();
      if (xcto === 'nosniff') {
        securityHeaders.checks.push({
          name: 'X-Content-Type-Options',
          status: 'pass',
          message: 'X-Content-Type-Options is set to nosniff',
        });
      } else {
        securityHeaders.checks.push({
          name: 'X-Content-Type-Options',
          status: 'warning',
          message: `X-Content-Type-Options is set to ${xcto}`,
          recommendation: 'Set to "nosniff" to prevent MIME type sniffing',
        });
      }
    } else {
      securityHeaders.checks.push({
        name: 'X-Content-Type-Options',
        status: 'fail',
        message: 'X-Content-Type-Options header is missing',
        recommendation: 'Add X-Content-Type-Options: nosniff',
      });
    }

    // Strict-Transport-Security (HSTS)
    if (headers['strict-transport-security'] || headers['Strict-Transport-Security']) {
      const hsts = headers['strict-transport-security'] || headers['Strict-Transport-Security'];
      if (hsts.includes('max-age') && parseInt(hsts.match(/max-age=(\d+)/)?.[1] || '0') >= 31536000) {
        securityHeaders.checks.push({
          name: 'Strict-Transport-Security',
          status: 'pass',
          message: 'HSTS is properly configured',
        });
      } else {
        securityHeaders.checks.push({
          name: 'Strict-Transport-Security',
          status: 'warning',
          message: 'HSTS max-age is less than 1 year',
          recommendation: 'Set max-age to at least 31536000 (1 year)',
        });
      }
    } else {
      securityHeaders.checks.push({
        name: 'Strict-Transport-Security',
        status: 'info',
        message: 'HSTS header is missing (only applicable for HTTPS)',
        recommendation: 'Add Strict-Transport-Security header for HTTPS sites',
      });
    }

    // Referrer-Policy
    if (headers['referrer-policy'] || headers['Referrer-Policy']) {
      securityHeaders.checks.push({
        name: 'Referrer-Policy',
        status: 'pass',
        message: 'Referrer-Policy is configured',
      });
    } else {
      securityHeaders.checks.push({
        name: 'Referrer-Policy',
        status: 'warning',
        message: 'Referrer-Policy header is missing',
        recommendation: 'Add Referrer-Policy to control referrer information',
      });
    }

    // Permissions-Policy
    if (headers['permissions-policy'] || headers['Permissions-Policy']) {
      securityHeaders.checks.push({
        name: 'Permissions-Policy',
        status: 'pass',
        message: 'Permissions-Policy is configured',
      });
    } else {
      securityHeaders.checks.push({
        name: 'Permissions-Policy',
        status: 'info',
        message: 'Permissions-Policy header is missing',
        recommendation: 'Add Permissions-Policy to restrict browser features',
      });
    }

    results.push(securityHeaders);

    // Cookie Security Analysis
    const cookieAnalysis: SecurityAnalysis = {
      category: 'Cookie Security',
      checks: [],
    };

    const setCookieHeaders = Object.entries(headers)
      .filter(([key]) => key.toLowerCase() === 'set-cookie')
      .map(([, value]) => value);

    if (setCookieHeaders.length === 0) {
      cookieAnalysis.checks.push({
        name: 'Cookies',
        status: 'info',
        message: 'No Set-Cookie headers found',
      });
    } else {
      setCookieHeaders.forEach((cookie, idx) => {
        const cookieLower = cookie.toLowerCase();
        const issues: string[] = [];

        if (!cookieLower.includes('httponly')) {
          issues.push('Missing HttpOnly flag');
        }
        if (!cookieLower.includes('secure')) {
          issues.push('Missing Secure flag');
        }
        if (!cookieLower.includes('samesite')) {
          issues.push('Missing SameSite attribute');
        } else {
          const sameSite = cookie.match(/samesite=(\w+)/i)?.[1]?.toLowerCase();
          if (sameSite !== 'strict' && sameSite !== 'lax') {
            issues.push(`SameSite is set to ${sameSite} (should be Strict or Lax)`);
          }
        }

        if (issues.length === 0) {
          cookieAnalysis.checks.push({
            name: `Cookie ${idx + 1}`,
            status: 'pass',
            message: 'Cookie has all security flags',
          });
        } else {
          cookieAnalysis.checks.push({
            name: `Cookie ${idx + 1}`,
            status: 'fail',
            message: issues.join(', '),
            recommendation: 'Add HttpOnly, Secure, and SameSite=Strict flags',
          });
        }
      });
    }

    results.push(cookieAnalysis);

    // Information Disclosure
    const infoDisclosure: SecurityAnalysis = {
      category: 'Information Disclosure',
      checks: [],
    };

    // Server header
    if (headers['server'] || headers['Server']) {
      infoDisclosure.checks.push({
        name: 'Server Header',
        status: 'warning',
        message: `Server information disclosed: ${headers['server'] || headers['Server']}`,
        recommendation: 'Remove or obfuscate Server header',
      });
    } else {
      infoDisclosure.checks.push({
        name: 'Server Header',
        status: 'pass',
        message: 'Server header is not disclosed',
      });
    }

    // X-Powered-By header
    if (headers['x-powered-by'] || headers['X-Powered-By']) {
      infoDisclosure.checks.push({
        name: 'X-Powered-By Header',
        status: 'warning',
        message: `Technology stack disclosed: ${headers['x-powered-by'] || headers['X-Powered-By']}`,
        recommendation: 'Remove X-Powered-By header',
      });
    } else {
      infoDisclosure.checks.push({
        name: 'X-Powered-By Header',
        status: 'pass',
        message: 'X-Powered-By header is not disclosed',
      });
    }

    // Error messages in body
    const errorPatterns = [
      /error\s*:\s*/i,
      /exception\s*:\s*/i,
      /stack\s*trace/i,
      /at\s+\w+\.\w+/i,
      /file:\/\/\//i,
      /c:\/.*\\.(php|jsp|asp|aspx)/i,
    ];
    const hasErrorInfo = errorPatterns.some(pattern => pattern.test(body));
    if (hasErrorInfo) {
      infoDisclosure.checks.push({
        name: 'Error Information',
        status: 'warning',
        message: 'Potential error information found in response body',
        recommendation: 'Ensure error messages do not expose sensitive information',
      });
    } else {
      infoDisclosure.checks.push({
        name: 'Error Information',
        status: 'pass',
        message: 'No obvious error information in response',
      });
    }

    results.push(infoDisclosure);

    // HTTPS and TLS
    const tlsAnalysis: SecurityAnalysis = {
      category: 'HTTPS & TLS',
      checks: [],
    };

    const isHttps = (req.url || '').startsWith('https://');
    if (isHttps) {
      tlsAnalysis.checks.push({
        name: 'HTTPS',
        status: 'pass',
        message: 'Connection is using HTTPS',
      });
    } else {
      tlsAnalysis.checks.push({
        name: 'HTTPS',
        status: 'fail',
        message: 'Connection is not using HTTPS',
        recommendation: 'Use HTTPS for all sensitive communications',
      });
    }

    results.push(tlsAnalysis);

    // Advanced CSP Analysis
    const cspAnalysis: SecurityAnalysis = {
      category: 'CSP Deep Analysis',
      checks: [],
    };

    const cspHeader = headers['content-security-policy'] || headers['Content-Security-Policy'] || '';
    if (cspHeader) {
      const csp = cspHeader.toLowerCase();
      
      // Check for missing directives
      if (!csp.includes('default-src')) {
        cspAnalysis.checks.push({
          name: 'Default-Src Directive',
          status: 'warning',
          message: 'default-src directive is missing',
          recommendation: 'Add default-src directive as a fallback for all fetch directives',
        });
      }
      
      // Check script-src
      if (csp.includes('script-src')) {
        if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
          cspAnalysis.checks.push({
            name: 'Script-Src Security',
            status: 'fail',
            message: 'script-src contains unsafe directives',
            recommendation: 'Use nonces or hashes instead of unsafe-inline/unsafe-eval',
          });
        } else if (csp.includes("'nonce-") || csp.includes("'sha256-") || csp.includes("'sha384-") || csp.includes("'sha512-")) {
          cspAnalysis.checks.push({
            name: 'Script-Src Security',
            status: 'pass',
            message: 'script-src uses nonces or hashes (secure)',
          });
        }
      } else {
        cspAnalysis.checks.push({
          name: 'Script-Src Directive',
          status: 'warning',
          message: 'script-src directive is missing',
          recommendation: 'Add script-src directive to control script execution',
        });
      }
      
      // Check style-src
      if (csp.includes('style-src')) {
        if (csp.includes("'unsafe-inline'")) {
          cspAnalysis.checks.push({
            name: 'Style-Src Security',
            status: 'warning',
            message: 'style-src contains unsafe-inline',
            recommendation: 'Consider using nonces for inline styles',
          });
        }
      }
      
      // Check for frame-ancestors (replaces X-Frame-Options in CSP)
      if (csp.includes('frame-ancestors')) {
        if (csp.includes("'none'")) {
          cspAnalysis.checks.push({
            name: 'Frame-Ancestors',
            status: 'pass',
            message: 'frame-ancestors is set to none (prevents clickjacking)',
          });
        } else if (csp.includes("'self'")) {
          cspAnalysis.checks.push({
            name: 'Frame-Ancestors',
            status: 'pass',
            message: 'frame-ancestors is set to self',
          });
        }
      }
      
      // Check for upgrade-insecure-requests
      if (csp.includes('upgrade-insecure-requests')) {
        cspAnalysis.checks.push({
          name: 'Upgrade Insecure Requests',
          status: 'pass',
          message: 'upgrade-insecure-requests is enabled',
        });
      } else {
        cspAnalysis.checks.push({
          name: 'Upgrade Insecure Requests',
          status: 'info',
          message: 'upgrade-insecure-requests is not set',
          recommendation: 'Consider adding upgrade-insecure-requests to automatically upgrade HTTP to HTTPS',
        });
      }
    }

    if (cspAnalysis.checks.length > 0) {
      results.push(cspAnalysis);
    }

    // CORS Analysis
    const corsAnalysis: SecurityAnalysis = {
      category: 'CORS Configuration',
      checks: [],
    };

    const acao = headers['access-control-allow-origin'] || headers['Access-Control-Allow-Origin'] || '';
    const acac = headers['access-control-allow-credentials'] || headers['Access-Control-Allow-Credentials'] || '';
    
    if (acao) {
      if (acao === '*') {
        if (acac && acac.toLowerCase() === 'true') {
          corsAnalysis.checks.push({
            name: 'CORS Configuration',
            status: 'fail',
            message: 'CORS allows all origins with credentials - CRITICAL security issue',
            recommendation: 'Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true',
          });
        } else {
          corsAnalysis.checks.push({
            name: 'CORS Configuration',
            status: 'warning',
            message: 'CORS allows all origins (*)',
            recommendation: 'Restrict Access-Control-Allow-Origin to specific trusted domains',
          });
        }
      } else {
        corsAnalysis.checks.push({
          name: 'CORS Configuration',
          status: 'pass',
          message: `CORS is restricted to: ${acao}`,
        });
      }
    } else {
      corsAnalysis.checks.push({
        name: 'CORS Configuration',
        status: 'info',
        message: 'No CORS headers found',
      });
    }

    if (corsAnalysis.checks.length > 0) {
      results.push(corsAnalysis);
    }

    // Cache Control Analysis
    const cacheAnalysis: SecurityAnalysis = {
      category: 'Cache Control',
      checks: [],
    };

    const cacheControl = headers['cache-control'] || headers['Cache-Control'] || '';
    const pragma = headers['pragma'] || headers['Pragma'] || '';
    
    if (cacheControl) {
      if (cacheControl.toLowerCase().includes('no-store') || cacheControl.toLowerCase().includes('no-cache')) {
        cacheAnalysis.checks.push({
          name: 'Cache Control',
          status: 'pass',
          message: 'Cache control prevents caching of sensitive data',
        });
      } else if (cacheControl.toLowerCase().includes('private')) {
        cacheAnalysis.checks.push({
          name: 'Cache Control',
          status: 'warning',
          message: 'Cache control allows private caching',
          recommendation: 'For sensitive data, use no-store or no-cache',
        });
      } else {
        cacheAnalysis.checks.push({
          name: 'Cache Control',
          status: 'warning',
          message: 'Cache control may allow caching of sensitive data',
          recommendation: 'Review cache-control directives for sensitive endpoints',
        });
      }
    } else {
      cacheAnalysis.checks.push({
        name: 'Cache Control',
        status: 'info',
        message: 'No cache-control header found',
        recommendation: 'Add appropriate cache-control headers',
      });
    }

    results.push(cacheAnalysis);

    // Response Status Analysis
    const statusAnalysis: SecurityAnalysis = {
      category: 'Response Status',
      checks: [],
    };

    if (status >= 200 && status < 300) {
      statusAnalysis.checks.push({
        name: 'HTTP Status',
        status: 'pass',
        message: `Status: ${status} (Success)`,
      });
    } else if (status >= 300 && status < 400) {
      statusAnalysis.checks.push({
        name: 'HTTP Status',
        status: 'warning',
        message: `Status: ${status} (Redirect)`,
        recommendation: 'Ensure redirects do not expose sensitive information in URLs',
      });
    } else if (status >= 400 && status < 500) {
      statusAnalysis.checks.push({
        name: 'HTTP Status',
        status: 'info',
        message: `Status: ${status} (Client Error)`,
      });
    } else if (status >= 500) {
      statusAnalysis.checks.push({
        name: 'HTTP Status',
        status: 'warning',
        message: `Status: ${status} (Server Error)`,
        recommendation: 'Ensure error responses do not leak sensitive information',
      });
    }

    results.push(statusAnalysis);

    setAnalysis(results);
  };

  const getStatusIcon = (status: string): string => {
    switch (status) {
      case 'pass': return '✅';
      case 'fail': return '❌';
      case 'warning': return '⚠️';
      case 'info': return 'ℹ️';
      default: return '•';
    }
  };

  const getStatusColor = (status: string): string => {
    switch (status) {
      case 'pass': return '#2ecc71';
      case 'fail': return '#e74c3c';
      case 'warning': return '#f39c12';
      case 'info': return '#3498db';
      default: return '#858585';
    }
  };

  // Calculate security score
  const calculateSecurityScore = (): { score: number; maxScore: number; percentage: number } => {
    let score = 0;
    let maxScore = 0;

    analysis.forEach(category => {
      category.checks.forEach(check => {
        maxScore += 1;
        if (check.status === 'pass') score += 1;
        else if (check.status === 'warning') score += 0.5;
        else if (check.status === 'info') score += 0.25;
      });
    });

    return {
      score,
      maxScore,
      percentage: maxScore > 0 ? Math.round((score / maxScore) * 100) : 0,
    };
  };

  if (!request) {
    return (
      <div className="response-analyzer-view empty-state">
        <EmptyState icon="analyzer" title="Select a request to analyze security headers" brandName="CleanTraffic" />
      </div>
    );
  }

  const securityScore = calculateSecurityScore();
  const failCount = analysis.reduce((n, c) => n + c.checks.filter(ch => ch.status === 'fail').length, 0);
  const warnCount = analysis.reduce((n, c) => n + c.checks.filter(ch => ch.status === 'warning').length, 0);
  const summaryLine = failCount || warnCount
    ? [
        failCount ? `${failCount} critical` : '',
        warnCount ? `${warnCount} warning${warnCount !== 1 ? 's' : ''}` : '',
      ].filter(Boolean).join(' · ')
    : null;

  return (
    <div className="response-analyzer-view">
      <div className="analyzer-header">
        <div className="analyzer-title">
          <AnalyzerHeaderIcon />
        </div>
        <p className="analyzer-subtitle">Security headers and response security analysis</p>
      </div>

      <div className="analyzer-content">
        <div className="security-score-card">
          <div className="score-header">
            <h3>Security Score</h3>
            <div className="score-value" style={{ color: securityScore.percentage >= 80 ? '#2ecc71' : securityScore.percentage >= 60 ? '#f39c12' : '#e74c3c' }}>
              {securityScore.percentage}%
            </div>
          </div>
          <div className="score-details">
            <div className="score-bar">
              <div
                className="score-fill"
                style={{
                  width: `${securityScore.percentage}%`,
                  backgroundColor: securityScore.percentage >= 80 ? '#2ecc71' : securityScore.percentage >= 60 ? '#f39c12' : '#e74c3c',
                }}
              />
            </div>
            <div className="score-breakdown">
              <span>{securityScore.score.toFixed(1)} / {securityScore.maxScore} checks passed</span>
              {summaryLine && <><span className="score-sep"> · </span><span className="score-summary">{summaryLine}</span></>}
            </div>
          </div>
        </div>

        {analysis.map((category, idx) => (
          <div key={idx} className="analysis-category">
            <h3>{category.category}</h3>
            <div className="checks-list">
              {category.checks.map((check, checkIdx) => (
                <div key={checkIdx} className="check-item">
                  <div className="check-header">
                    <span className="check-icon" style={{ color: getStatusColor(check.status) }}>
                      {getStatusIcon(check.status)}
                    </span>
                    <span className="check-name">{check.name}</span>
                    <span className="check-status" style={{ color: getStatusColor(check.status) }}>
                      {check.status.toUpperCase()}
                    </span>
                  </div>
                  <div className="check-message">{check.message}</div>
                  {check.recommendation && (
                    <div className="check-recommendation">
                      <strong>Recommendation:</strong> {check.recommendation}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default memo(ResponseAnalyzer, (prev, next) => requestDetailEqual(prev.request, next.request));

