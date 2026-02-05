import React, { useState, useEffect, memo } from 'react';
import { HttpRequest } from '../../main/proxy-server';
import { requestDetailEqual } from '../utils/requestEqual';
import { EmptyState } from './EmptyState';
import { ExtractorHeaderIcon } from './ToolIcons';
import './Extractor.css';

interface ExtractorProps {
  request: HttpRequest | null;
}

interface ExtractedData {
  type: string;
  value: string;
  context: string;
  count: number;
}

const PRIORITIZED_TYPES = ['domains', 'urls', 'apiKeys', 'secrets', 'jwt', 'tokens', 'cookies', 'headers', 'emails', 'ipAddresses', 'apiEndpoints'];

const Extractor: React.FC<ExtractorProps> = ({ request }) => {
  const [extractedData, setExtractedData] = useState<Record<string, ExtractedData[]>>({});
  const [selectedType, setSelectedType] = useState<string>('all');
  const [viewSearch, setViewSearch] = useState<string>('');

  useEffect(() => {
    if (request) {
      extractData(request);
    } else {
      setExtractedData({});
    }
  }, [request]);

  const extractData = (req: HttpRequest) => {
    const data: Record<string, ExtractedData[]> = {
      emails: [],
      urls: [],
      tokens: [],
      apiKeys: [],
      ipAddresses: [],
      phoneNumbers: [],
      creditCards: [],
      base64: [],
      jwt: [],
      filePaths: [],
      apiEndpoints: [],
      secrets: [],
      domains: [],
      endpoints: [],
      cookies: [],
      headers: [],
    };

    // Combine all text sources
    const text = JSON.stringify({
      url: req.url,
      headers: req.headers,
      body: req.body,
      responseHeaders: req.responseHeaders,
      responseBody: req.responseBody,
    });

    const rawText = [
      req.url || '',
      JSON.stringify(req.headers || {}),
      req.body || '',
      JSON.stringify(req.responseHeaders || {}),
      req.responseBody || '',
    ].join('\n');

    // Extract emails - Advanced pattern with false positive reduction
    const emailRegex = /\b([a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})\b/g;
    const emailMatches = rawText.matchAll(emailRegex);
    const emailBlacklist = ['example.com', 'test.com', 'localhost', 'domain.com', 'email.com', 'user@domain', 'admin@test'];
    const codeExtensions = ['js', 'ts', 'json', 'xml', 'html', 'css', 'py', 'java', 'cpp', 'go', 'rs', 'php'];
    
    for (const match of emailMatches) {
      const email = match[1].toLowerCase();
      const domain = email.split('@')[1];
      const tld = domain?.split('.').pop() || '';
      
      // Exclude common false positives
      if (emailBlacklist.some(b => email.includes(b))) continue;
      if (codeExtensions.includes(tld)) continue; // Exclude code file extensions
      if (email.includes('..') || email.includes('@@')) continue; // Invalid format
      if (email.startsWith('.') || email.endsWith('.')) continue; // Invalid
      if (domain && (domain.startsWith('.') || domain.endsWith('.'))) continue;
      
      // Validate TLD is not a common code extension or too short
      if (tld.length < 2 || tld.length > 6) continue;
      
      // Check context - exclude if in code comments or examples
      const context = getContext(rawText, match[0], 30);
      if (/\/\/|#|\/\*|\*\/|example|test|sample|placeholder/i.test(context)) continue;
      
      if (!data.emails.find(e => e.value.toLowerCase() === email)) {
        data.emails.push({
          type: 'email',
          value: match[1], // Use original case
          context: getContext(rawText, match[0]),
          count: 1,
        });
      }
    }

    // Extract URLs
    const urlRegex = /https?:\/\/[^\s"'<>{}|\\^`\[\]]+/gi;
    const urls = text.match(urlRegex) || [];
    urls.forEach((url, idx) => {
      if (!data.urls.find(u => u.value === url)) {
        data.urls.push({
          type: 'url',
          value: url,
          context: getContext(text, url),
          count: urls.filter(u => u === url).length,
        });
      }
    });

    // Extract API keys and tokens - Exclude process.env, config, examples
    const apiKeyPatterns = [
      { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?/gi, minLength: 20 },
      { pattern: /(?:secret|secret[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?/gi, minLength: 20 },
      { pattern: /(?:token|access[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?/gi, minLength: 20 },
      { pattern: /(?:bearer)\s+([a-zA-Z0-9_\-\.]{20,})/gi, minLength: 20 },
    ];
    
    apiKeyPatterns.forEach(({ pattern, minLength }) => {
      const matches = rawText.matchAll(pattern);
      for (const match of matches) {
        const key = match[1] || match[0];
        if (key.length < minLength) continue;
        
        // Exclude common false positives
        const context = getContext(rawText, match[0], 50);
        
        // Exclude process.env, config variables, examples
        if (/process\.env|config\[|CONFIG\[|\.env|getenv|getenv\(/i.test(context)) continue;
        if (/example|test|sample|placeholder|dummy|fake|your[_-]?key|your[_-]?token|your[_-]?secret/i.test(context)) continue;
        if (/\/\/|#|\/\*|\*\/|console\.log|print\(|System\.out/.test(context)) continue; // Code comments
        
        // Exclude if key looks like a variable name (all caps with underscores)
        if (/^[A-Z_]{10,}$/.test(key)) continue;
        
        // Exclude common test patterns
        if (/^(test|example|demo|sample|placeholder|your_key|your_token|your_secret)/i.test(key)) continue;
        
        if (!data.apiKeys.find(k => k.value === key)) {
          data.apiKeys.push({
            type: 'apiKey',
            value: key,
            context: getContext(rawText, match[0]),
            count: 1,
          });
        }
      }
    });

    // Extract JWT tokens - Validate structure more strictly
    const jwtRegex = /\b(eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)\b/g;
    const isValidJWT = (token: string): boolean => {
      const parts = token.split('.');
      if (parts.length < 2 || parts.length > 3) return false;
      
      // Validate header and payload are base64url
      try {
        const header = parts[0].replace(/-/g, '+').replace(/_/g, '/');
        const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
        
        // Add padding if needed
        const headerPadded = header + '='.repeat((4 - header.length % 4) % 4);
        const payloadPadded = payload + '='.repeat((4 - payload.length % 4) % 4);
        
        const headerJson = JSON.parse(atob(headerPadded));
        const payloadJson = JSON.parse(atob(payloadPadded));
        
        // Validate JWT structure
        return headerJson.typ === 'JWT' || headerJson.alg !== undefined;
      } catch {
        return false;
      }
    };
    
    const jwtMatches = rawText.matchAll(jwtRegex);
    for (const match of jwtMatches) {
      const jwt = match[1];
      
      // Basic length check
      if (jwt.length < 20) continue;
      
      // Validate JWT structure
      if (!isValidJWT(jwt)) continue;
      
      // Check context - exclude examples
      const context = getContext(rawText, match[0], 30);
      if (/example|test|sample|placeholder|dummy|jwt\s*[:=]/i.test(context)) continue;
      if (/\/\/|#|\/\*|\*\/|console\.log/.test(context)) continue;
      
      if (!data.jwt.find(j => j.value === jwt)) {
        data.jwt.push({
          type: 'jwt',
          value: jwt,
          context: getContext(rawText, match[0]),
          count: 1,
        });
      }
    }

    // Extract IP addresses - Validate octets and exclude false positives
    const ipRegex = /\b((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b/g;
    const ipMatches = rawText.matchAll(ipRegex);
    const ipBlacklist = ['0.0.0.0', '255.255.255.255'];
    
    for (const match of ipMatches) {
      const ip = match[1];
      
      // Exclude blacklisted IPs
      if (ipBlacklist.includes(ip)) continue;
      
      // Check context - exclude version numbers, timestamps, etc.
      const context = getContext(rawText, match[0], 20);
      if (/version|v\d|timestamp|time|date|build|release/i.test(context)) continue;
      if (/\d{4}-\d{2}-\d{2}|\d{2}:\d{2}:\d{2}/.test(context)) continue; // Timestamp patterns
      
      // Exclude if part of URL (already extracted as URL)
      if (/https?:\/\/|ftp:\/\/|:\d{4,5}/.test(context)) continue;
      
      if (!data.ipAddresses.find(i => i.value === ip)) {
        data.ipAddresses.push({
          type: 'ip',
          value: ip,
          context: getContext(rawText, match[0]),
          count: 1,
        });
      }
    }

    // Extract phone numbers - More strict patterns to reduce false positives
    const phonePatterns = [
      /\b\+?1[-.\s]?\(?([2-9][0-9]{2})\)?[-.\s]?([2-9][0-9]{2})[-.\s]?([0-9]{4})\b/g, // US format (excludes 0/1 start)
      /\b\+[1-9]\d{1,3}[-.\s]?[2-9]\d{1,4}[-.\s]?[2-9]\d{1,4}[-.\s]?\d{4,}\b/g, // International format
    ];
    
    phonePatterns.forEach(pattern => {
      const matches = rawText.matchAll(pattern);
      for (const match of matches) {
        const phone = match[0].replace(/\s+/g, ' ').trim();
        
        // Exclude common false positives
        if (/^0{3,}|^1{3,}|^2{3,}|^3{3,}|^4{3,}|^5{3,}|^6{3,}|^7{3,}|^8{3,}|^9{3,}/.test(phone.replace(/\D/g, ''))) continue; // All same digits
        if (phone.replace(/\D/g, '').length < 10) continue; // Too short
        
        // Check context - exclude if in code, examples, or test data
        const context = getContext(rawText, match[0], 30);
        if (/example|test|sample|placeholder|dummy|fake|phone\s*[:=]|tel\s*[:=]/i.test(context)) continue;
        if (/\/\/|#|\/\*|\*\/|console\.log|print\(|System\.out/.test(context)) continue; // Code comments
        
        if (!data.phoneNumbers.find(p => p.value === phone)) {
          data.phoneNumbers.push({
            type: 'phone',
            value: phone,
            context: getContext(rawText, match[0]),
            count: 1,
          });
        }
      }
    });

    // Extract credit cards with Luhn algorithm validation
    const ccRegex = /\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b/g;
    const luhnCheck = (num: string): boolean => {
      const digits = num.replace(/\D/g, '');
      if (digits.length < 13 || digits.length > 19) return false;
      
      let sum = 0;
      let isEven = false;
      for (let i = digits.length - 1; i >= 0; i--) {
        let digit = parseInt(digits[i]);
        if (isEven) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
        isEven = !isEven;
      }
      return sum % 10 === 0;
    };
    
    const testNumbers = ['4111111111111111', '4242424242424242', '5555555555554444', '378282246310005', '6011111111111117'];
    
    const ccMatches = rawText.matchAll(ccRegex);
    for (const match of ccMatches) {
      const cc = match[1];
      const digits = cc.replace(/\D/g, '');
      
      // Exclude test numbers
      if (testNumbers.includes(digits)) continue;
      
      // Validate with Luhn algorithm
      if (!luhnCheck(digits)) continue;
      
      // Check context - exclude examples, test data
      const context = getContext(rawText, match[0], 30);
      if (/example|test|sample|placeholder|dummy|fake|card\s*[:=]|credit\s*[:=]/i.test(context)) continue;
      if (/\/\/|#|\/\*|\*\/|console\.log/.test(context)) continue;
      
      if (!data.creditCards.find(c => c.value === cc)) {
        data.creditCards.push({
          type: 'creditCard',
          value: cc,
          context: getContext(rawText, match[0]),
          count: 1,
        });
      }
    }

    // Extract Base64 strings - Validate format and exclude false positives
    const base64Regex = /(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?:[^A-Za-z0-9+/]|$)/g;
    const isValidBase64 = (str: string): boolean => {
      const clean = str.replace(/[^A-Za-z0-9+/=]/g, '');
      if (clean.length < 40) return false;
      
      // Check padding is valid (0, 1, or 2 = signs at the end)
      const paddingMatch = clean.match(/=+$/);
      if (paddingMatch && paddingMatch[0].length > 2) return false;
      
      // Check for invalid characters
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) return false;
      
      // Try to decode (basic validation)
      try {
        const decoded = atob(clean);
        // If it decodes to mostly printable characters, it's likely valid
        const printableRatio = decoded.split('').filter(c => 
          (c >= ' ' && c <= '~') || c === '\n' || c === '\r' || c === '\t'
        ).length / decoded.length;
        return printableRatio > 0.7; // At least 70% printable
      } catch {
        return false;
      }
    };
    
    const base64Matches = rawText.matchAll(base64Regex);
    for (const match of base64Matches) {
      const b64 = match[1];
      const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '');
      
      if (clean.length < 40) continue;
      
      // Validate base64 format
      if (!isValidBase64(clean)) continue;
      
      // Check context - exclude if in code examples or test data
      const context = getContext(rawText, match[0], 30);
      if (/example|test|sample|placeholder|dummy|base64\s*[:=]/i.test(context)) continue;
      if (/\/\/|#|\/\*|\*\/|console\.log/.test(context)) continue;
      
      if (!data.base64.find(b => b.value === clean)) {
        data.base64.push({
          type: 'base64',
          value: clean,
          context: getContext(rawText, match[0]),
          count: 1,
        });
      }
    }

    // Extract file paths - Exclude URLs and common false positives
    const pathPatterns = [
      /(?:^|[^\/])((?:\/[a-zA-Z0-9_\-\.]+){2,})/g, // Unix paths
      /(?:^|[^A-Z])([A-Z]:\\(?:[a-zA-Z0-9_\-\.]+\\)+[a-zA-Z0-9_\-\.]+)/g, // Windows paths
    ];
    
    const pathBlacklist = ['/api/', '/v1/', '/v2/', '/rest/', '/graphql/', '/rpc/', '/static/', '/assets/', '/css/', '/js/', '/img/'];
    const pathExtensions = ['.js', '.ts', '.json', '.xml', '.html', '.css', '.png', '.jpg', '.gif', '.svg', '.ico'];
    
    pathPatterns.forEach(pattern => {
      const matches = rawText.matchAll(pattern);
      for (const match of matches) {
        let path = match[1].trim();
        if (path.length < 4) continue;
        
        // Exclude if it's a URL
        if (/^https?:\/\//i.test(path)) continue;
        if (path.includes('://')) continue;
        
        // Exclude common API paths
        if (pathBlacklist.some(b => path.toLowerCase().includes(b))) continue;
        
        // Exclude if it's just a domain or common web path
        if (/^\/[a-z]{1,3}$/i.test(path)) continue; // Too short
        if (/^\/[a-z]+\/[a-z]+$/i.test(path) && !pathExtensions.some(ext => path.includes(ext))) continue;
        
        // Check context - exclude if in code examples
        const context = getContext(rawText, match[0], 30);
        if (/example|test|sample|placeholder|path\s*[:=]/i.test(context)) continue;
        if (/\/\/|#|\/\*|\*\/|console\.log|require\(|import\s/.test(context)) continue;
        
        if (!data.filePaths.find(p => p.value === path)) {
          data.filePaths.push({
            type: 'filePath',
            value: path,
            context: getContext(rawText, match[0]),
            count: 1,
          });
        }
      }
    });

    // Extract API Endpoints
    const apiEndpointRegex = /(?:https?:\/\/[^\/]+)?(\/(?:api|v\d+|rest|graphql|rpc)\/[^\s"'<>{}|\\^`\[\]]+)/gi;
    const apiEndpoints = rawText.match(apiEndpointRegex) || [];
    apiEndpoints.forEach(endpoint => {
      const clean = endpoint.replace(/^https?:\/\/[^\/]+/, '').split('?')[0];
      if (clean.length > 3 && !data.apiEndpoints.find(e => e.value === clean)) {
        data.apiEndpoints.push({
          type: 'apiEndpoint',
          value: clean,
          context: getContext(rawText, endpoint),
          count: 1,
        });
      }
    });

    // Extract Advanced Secrets (using same patterns as scanner)
    const secretPatterns = [
      { pattern: /(?:AWS|aws|Aws)_?(?:ACCESS|access|Access)_?(?:KEY|key|Key)[^"']{0,10}["']([A-Z0-9]{20})["']/gi, name: 'AWS Access Key' },
      { pattern: /(?:AWS|aws|Aws)_?(?:SECRET|secret|Secret)_?(?:KEY|key|Key)[^"']{0,10}["']([A-Za-z0-9/+=]{40})["']/gi, name: 'AWS Secret Key' },
      { pattern: /(?:mongodb|mongo):\/\/[^"']*["']/gi, name: 'MongoDB Connection String' },
      { pattern: /(?:mysql|postgresql|postgres):\/\/[^"']*["']/gi, name: 'SQL Connection String' },
      { pattern: /(?:JWT|jwt|Jwt)_?(?:SECRET|secret|Secret)[^"']{0,10}["']([A-Za-z0-9\-_]{20,})["']/gi, name: 'JWT Secret' },
      { pattern: /(?:DISCORD|discord|Discord)_?(?:TOKEN|token|Token)[^"']{0,10}["']([A-Za-z0-9\-_]{20,})["']/gi, name: 'Discord Token' },
      { pattern: /(?:GITHUB|github|Github)_?(?:TOKEN|token|Token)[^"']{0,10}["']([A-Za-z0-9\-_]{20,})["']/gi, name: 'GitHub Token' },
      { pattern: /(?:STRIPE|stripe|Stripe)_?(?:SECRET|secret|Secret)_?(?:KEY|key|Key)[^"']{0,10}["']([A-Za-z0-9\-_]{20,})["']/gi, name: 'Stripe Secret' },
      { pattern: /(?:PRIVATE|private|Private)_?(?:KEY|key|Key)[^"']{0,10}["'](-----BEGIN[^-]+-----[\s\S]+?-----END[^-]+-----)["']/gi, name: 'Private Key' },
    ];

    secretPatterns.forEach(secretPattern => {
      const matches = rawText.matchAll(secretPattern.pattern);
      for (const match of matches) {
        const secret = match[1] || match[0];
        if (secret.length >= 20 && !data.secrets.find(s => s.value === secret)) {
          data.secrets.push({
            type: 'secret',
            value: secret.substring(0, 100) + (secret.length > 100 ? '...' : ''),
            context: getContext(rawText, match[0]),
            count: 1,
          });
        }
      }
    });

    // Extract Domains – source-specific only. No generic regex over raw JS/HTML
    // (avoids false positives like this.md5.substr, document.cookie.split, f.substring)
    const domainBlacklist = new Set([
      'localhost', '127.0.0.1', '0.0.0.0', 'example.com', 'test.com', 'domain.com',
      'example.org', 'test.org', 'example.net', 'test.net', 'localhost.localdomain',
      'example.local', 'test.local', 'local', 'localdomain', 'example.co', 'test.co',
    ]);
    const codeTlds = new Set(['js', 'ts', 'json', 'xml', 'html', 'css', 'py', 'java', 'cpp', 'go', 'rs', 'php', 'rb', 'sh', 'bat', 'cmd', 'substr', 'split', 'length', 'charat', 'indexof', 'substring', 'replace', 'slice', 'trim', 'toLowerCase', 'toUpperCase']);
    const codeMethodPatterns = /\.(substr|split|substring|slice|replace|trim|charAt|indexOf|length|toLowerCase|toUpperCase|match|search|replaceAll|startsWith|endsWith)\s*\(/i;
    const addDomain = (value: string, context: string) => {
      // Skip if context looks like code (method calls, variable assignments)
      if (codeMethodPatterns.test(context)) return;
      // Skip if value appears to be part of a method chain or property access
      if (/\.(substr|split|substring|slice|replace|trim|charAt|indexOf|length|toLowerCase|toUpperCase|match|search|replaceAll|startsWith|endsWith)\s*\(/i.test(context)) return;
      // Skip if context contains common code patterns
      if (/(?:var|let|const|function|return|if|else|for|while|this\.|document\.|window\.|\.prototype\.|\.call\(|\.apply\(|new\s+\w+\(|typeof\s+\w+|instanceof)/i.test(context)) return;
      
      const domain = value.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].toLowerCase().trim();
      if (domain.length < 5 || !domain.includes('.')) return;
      if (domainBlacklist.has(domain)) return;
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) return;
      const tld = domain.split('.').pop() || '';
      if (!/^[a-z]{2,24}$/i.test(tld) || codeTlds.has(tld.toLowerCase())) return;
      // Additional validation: domain should have valid structure (not just method names)
      if (/^(substr|split|substring|slice|replace|trim|charat|indexof|length|tolowercase|touppercase|match|search|replaceall|startswith|endswith)$/i.test(domain.split('.')[0])) return;
      if (data.domains.some(d => d.value === domain)) return;
      data.domains.push({ type: 'domain', value: domain, context, count: 1 });
    };

    // 1) From URLs – hostname only
    const urlHostRegex = /https?:\/\/([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})(?:\/|$|[?#:\s])/g;
    let urlM;
    while ((urlM = urlHostRegex.exec(rawText)) !== null) {
      addDomain(urlM[1], getContext(rawText, urlM[0], 40));
    }

    // 2) From emails – @domain
    data.emails.forEach(e => {
      const d = e.value.split('@')[1];
      if (d) addDomain(d, e.context);
    });

    // 3) Explicit domain/host keys (JSON, config)
    const domainKeyRegex = /(?:["']?(?:domain|host|hostname|origin|baseUrl|apiUrl)["']?\s*[:=]\s*["'])([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})/gi;
    let keyM;
    while ((keyM = domainKeyRegex.exec(rawText)) !== null) {
      const ctx = getContext(rawText, keyM[0], 40);
      if (/example|test|sample|placeholder|dummy/i.test(ctx)) continue;
      addDomain(keyM[1], ctx);
    }

    // 4) Set-Cookie Domain= attribute
    const domainAttrRegex = /Domain\s*=\s*\.?([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})/gi;
    let attrM;
    while ((attrM = domainAttrRegex.exec(rawText)) !== null) {
      addDomain(attrM[1], getContext(rawText, attrM[0], 40));
    }

    // Extract Cookies
    const cookieRegex = /(?:Set-Cookie|Cookie|set-cookie|cookie):\s*([^;]+)/gi;
    const cookies = rawText.match(cookieRegex) || [];
    cookies.forEach(cookie => {
      const clean = cookie.replace(/^(?:Set-Cookie|Cookie|set-cookie|cookie):\s*/i, '').split(';')[0].trim();
      if (clean && !data.cookies.find(c => c.value === clean)) {
        data.cookies.push({
          type: 'cookie',
          value: clean,
          context: getContext(rawText, cookie),
          count: 1,
        });
      }
    });

    // Extract Interesting Headers
    const interestingHeaders = ['authorization', 'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-requested-with', 'x-forwarded-for', 'x-real-ip'];
    interestingHeaders.forEach(headerName => {
      const headerValue = req.headers[headerName] || req.headers[headerName.toLowerCase()] || req.responseHeaders?.[headerName] || req.responseHeaders?.[headerName.toLowerCase()];
      if (headerValue) {
        data.headers.push({
          type: 'header',
          value: `${headerName}: ${headerValue}`,
          context: `Found in ${req.headers[headerName] ? 'request' : 'response'} headers`,
          count: 1,
        });
      }
    });

    // Filter out empty arrays
    Object.keys(data).forEach(key => {
      if (data[key].length === 0) {
        delete data[key];
      }
    });

    setExtractedData(data);
  };

  const getContext = (text: string, value: string, contextLength = 50): string => {
    const index = text.indexOf(value);
    if (index === -1) return '';
    const start = Math.max(0, index - contextLength);
    const end = Math.min(text.length, index + value.length + contextLength);
    return text.substring(start, end).replace(/\s+/g, ' ').trim();
  };

  const formatContext = (ctx: string, maxLen = 180): string => {
    if (!ctx) return '';
    let s = ctx.replace(/\s+/g, ' ').trim();
    if (s.length <= maxLen) return s;
    return s.slice(0, maxLen) + '…';
  };

  const parseUrl = (raw: string): { scheme: string; host: string; path: string; query: string } | null => {
    try {
      const u = new URL(raw);
      return {
        scheme: u.protocol.replace(/:$/, ''),
        host: u.hostname,
        path: u.pathname || '/',
        query: u.search ? u.search.slice(1) : '',
      };
    } catch {
      return null;
    }
  };

  const UrlParts: React.FC<{ url: string }> = ({ url }) => {
    const parsed = parseUrl(url);
    if (!parsed) {
      return <code className="item-value item-value-url">{url}</code>;
    }
    return (
      <code className="item-value item-value-url url-parts">
        <span className="url-scheme">{parsed.scheme}</span>
        <span className="url-sep">://</span>
        <span className="url-host">{parsed.host}</span>
        <span className="url-path">{parsed.path}</span>
        {parsed.query ? (
          <>
            <span className="url-sep">?</span>
            <span className="url-query">{parsed.query}</span>
          </>
        ) : null}
      </code>
    );
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const exportData = (type: string) => {
    const items = extractedData[type] || [];
    const text = items.map(item => item.value).join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${type}-extracted.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const TypeIcon: React.FC<{ type: string }> = ({ type }) => {
    const iconColor = '#9cdcfe';
    const common = { width: 14, height: 14, viewBox: '0 0 16 16', fill: 'none' as const };
    const strokeProps = { stroke: iconColor, strokeWidth: 1.6, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const };

    switch (type) {
      case 'urls':
      case 'url':
        return (
          <svg {...common} aria-hidden="true">
            <path d="M6.2 5.2l-1.7 1.7a3 3 0 104.2 4.2l1.7-1.7" {...strokeProps} />
            <path d="M9.8 10.8l1.7-1.7a3 3 0 10-4.2-4.2L5.6 6.6" {...strokeProps} />
          </svg>
        );
      case 'ipAddresses':
      case 'ip':
      case 'domains':
      case 'domain':
        return (
          <svg {...common} aria-hidden="true">
            <circle cx="8" cy="8" r="6" {...strokeProps} />
            <path d="M2.5 8h11" {...strokeProps} />
            <path d="M8 2c2.2 2.1 2.2 9.9 0 12" {...strokeProps} />
            <path d="M8 2c-2.2 2.1-2.2 9.9 0 12" {...strokeProps} />
          </svg>
        );
      case 'jwt':
      case 'tokens':
      case 'token':
      case 'apiKeys':
      case 'apiKey':
      case 'secrets':
      case 'secret':
        return (
          <svg {...common} aria-hidden="true">
            <path d="M6.5 9.5l-2 2v2h2l2-2" {...strokeProps} />
            <path d="M9 7a3 3 0 106 0 3 3 0 00-6 0z" {...strokeProps} />
            <path d="M11.7 7h.01" {...strokeProps} />
          </svg>
        );
      case 'emails':
      case 'email':
        return (
          <svg {...common} aria-hidden="true">
            <path d="M2.5 4.5h11v7h-11z" {...strokeProps} />
            <path d="M2.7 5l5.3 4 5.3-4" {...strokeProps} />
          </svg>
        );
      case 'cookies':
      case 'cookie':
        return (
          <svg {...common} aria-hidden="true">
            <path d="M8 2.5a5.5 5.5 0 105.5 5.5c-1.7 0-3-1.3-3-3-1.7 0-3-1.3-3-3z" {...strokeProps} />
            <path d="M6 8h.01M9.5 10h.01M9 6.2h.01" {...strokeProps} />
          </svg>
        );
      case 'headers':
      case 'header':
        return (
          <svg {...common} aria-hidden="true">
            <path d="M4 3.5h8M4 6.5h8M4 9.5h6" {...strokeProps} />
            <path d="M3 2.5h10v11H3z" {...strokeProps} />
          </svg>
        );
      default:
        return (
          <svg {...common} aria-hidden="true">
            <path d="M4 3h6l2 2v8H4z" {...strokeProps} />
            <path d="M10 3v2h2" {...strokeProps} />
          </svg>
        );
    }
  };

  const getTypeName = (type: string): string => {
    switch (type) {
      case 'emails': return 'Email Addresses';
      case 'urls': return 'URLs';
      case 'apiKeys': return 'API Keys & Tokens';
      case 'jwt': return 'JWT Tokens';
      case 'ipAddresses': return 'IP Addresses';
      case 'phoneNumbers': return 'Phone Numbers';
      case 'creditCards': return 'Credit Cards';
      case 'base64': return 'Base64 Strings';
      case 'filePaths': return 'File Paths';
      case 'apiEndpoints': return 'API Endpoints';
      case 'secrets': return 'Advanced Secrets';
      case 'domains': return 'Domains';
      case 'endpoints': return 'Endpoints';
      case 'cookies': return 'Cookies';
      case 'headers': return 'Interesting Headers';
      default: return type.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase()).trim() || type;
    }
  };

  const allTypes = [...Object.keys(extractedData)].sort((a, b) => {
    const c = (extractedData[b]?.length ?? 0) - (extractedData[a]?.length ?? 0);
    if (c !== 0) return c;
    const pa = PRIORITIZED_TYPES.indexOf(a);
    const pb = PRIORITIZED_TYPES.indexOf(b);
    if (pa >= 0 && pb >= 0) return pa - pb;
    if (pa >= 0) return -1;
    if (pb >= 0) return 1;
    return a.localeCompare(b);
  });
  const totalItems = allTypes.reduce((sum, type) => sum + (extractedData[type]?.length ?? 0), 0);
  const filterItem = (item: ExtractedData) => {
    if (!viewSearch.trim()) return true;
    const q = viewSearch.trim().toLowerCase();
    return item.value.toLowerCase().includes(q) || (item.context && item.context.toLowerCase().includes(q));
  };

  if (!request) {
    return (
      <div className="extractor-view">
        <EmptyState icon="extractor" title="Select a request to extract sensitive data" brandName="CleanTraffic" />
      </div>
    );
  }

  if (totalItems === 0) {
    return (
      <div className="extractor-view">
        <EmptyState icon="extractor" title="No sensitive data found in this request" brandName="CleanTraffic" />
      </div>
    );
  }

  return (
    <div className="extractor-view">
      <div className="extractor-header">
        <div className="extractor-title">
          <ExtractorHeaderIcon />
        </div>
        <p className="extractor-subtitle">Extract sensitive data from requests and responses</p>
      </div>

      <div className="extractor-content">
        <div className="extractor-sidebar">
          <div className="sidebar-header">
            <h3>Data Types ({totalItems})</h3>
            <input
              type="text"
              className="view-search-input"
              placeholder="Filter by value or context…"
              value={viewSearch}
              onChange={(e) => setViewSearch(e.target.value)}
              aria-label="Filter extracted items"
            />
          </div>
          <div className="types-list">
            <div
              className={`type-item ${selectedType === 'all' ? 'active' : ''}`}
              onClick={() => setSelectedType('all')}
            >
              <span>All Types</span>
              <span className="type-count">{totalItems}</span>
            </div>
            {allTypes.map(type => (
              <div
                key={type}
                className={`type-item ${selectedType === type ? 'active' : ''}`}
                onClick={() => setSelectedType(type)}
              >
                <span className="type-label">
                  <span className="type-icon">
                    <TypeIcon type={type} />
                  </span>
                  {getTypeName(type)}
                </span>
                <span className="type-count">{extractedData[type].length}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="extractor-main">
          <div className="extracted-items">
            {(selectedType === 'all' ? allTypes : [selectedType])
              .filter(type => !viewSearch.trim() || extractedData[type].some(filterItem))
              .map(type => {
                const items = extractedData[type].filter(filterItem);
                return (
              <div key={type} className="data-section">
                <div className="section-header">
                  <h3>
                    <span className="type-icon">
                      <TypeIcon type={type} />
                    </span>
                    {getTypeName(type)} ({viewSearch.trim() ? `${items.length} of ${extractedData[type].length}` : extractedData[type].length})
                  </h3>
                  <button className="export-btn" onClick={() => exportData(type)}>
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                      <path d="M8 2V12M8 12L4 8M8 12L12 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      <path d="M2 14H14" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                    </svg>
                    Export
                  </button>
                </div>
                <div className="items-list">
                  {items.map((item, idx) => (
                     <div key={idx} className={`extracted-item ${type === 'urls' ? 'extracted-item-url' : ''}`}>
                      <div className="item-header">
                        {type === 'urls' ? (
                          <UrlParts url={item.value} />
                        ) : (
                          <code className="item-value">{item.value}</code>
                        )}
                        <button
                          className="copy-btn"
                          onClick={() => copyToClipboard(item.value)}
                          title="Copy to clipboard"
                        >
                          <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                            <rect x="4" y="4" width="8" height="8" rx="1" stroke="currentColor" strokeWidth="1.5" fill="none"/>
                            <path d="M3 2H1C0.447715 2 0 2.44772 0 3V11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
                          </svg>
                        </button>
                      </div>
                      {item.context ? (
                        <div className="item-context">
                          <span className="context-label">Context</span>
                          <span className="context-text" title={item.context}>{formatContext(item.context)}</span>
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
              </div>
                );
              })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default memo(Extractor, (prev, next) => requestDetailEqual(prev.request, next.request));

