/**
 * Pentest / bug-hunt investigation signals.
 * Detects high-value endpoints, sensitive params, IDOR candidates, auth signals.
 */

import type { HttpRequest } from '../main/proxy-server';

export type RiskLevel = 'high' | 'medium' | 'low' | 'info';

export interface InvestigationSignals {
  tags: string[];
  risk: RiskLevel;
  reasons: string[];
  sensitiveParams: string[];
  idorCandidates: string[];
  /** Param keys that appear in URL or body (for reflection/fuzz hints) */
  paramNames: string[];
}

const HIGH_VALUE_PATH = [
  'login', 'signin', 'sign-in', 'auth', 'oauth', 'sso', 'saml',
  'password', 'reset', 'forgot', '2fa', 'mfa', 'verify', 'confirm', 'register',
  'upload', 'import', 'webhook', 'callback', 'export', 'admin', 'dashboard',
  'graphql', 'gql', 'api/key', 'api/token', 'secret', 'config', 'settings',
  'user', 'users', 'account', 'profile', 'payment', 'checkout', 'order',
];
const SENSITIVE_PARAMS = [
  'redirect', 'redirect_uri', 'redirect_url', 'next', 'return', 'returnurl', 'return_url',
  'url', 'continue', 'destination', 'goto', 'redir', 'file', 'path', 'document',
  'template', 'include', 'page', 'folder', 'cmd', 'command', 'exec', 'query',
  'q', 'search', 'id', 'user_id', 'account_id', 'org_id', 'order_id', 'uuid',
  'token', 'key', 'session', 'csrf', 'state', 'code', 'callback', 'jsonp',
];
const AUTH_HEADERS = ['authorization', 'x-api-key', 'x-auth-token', 'x-csrf-token', 'cookie'];
const CACHE_POISON_HEADERS = ['x-forwarded-host', 'x-original-url', 'x-host', 'x-forwarded-server', 'x-rewrite-url'];

function parseQuery(url: string): Record<string, string> {
  const out: Record<string, string> = {};
  try {
    const u = new URL(url);
    u.searchParams.forEach((v, k) => { out[k.toLowerCase()] = v; });
  } catch {
    const q = url.includes('?') ? url.split('?')[1]?.split('#')[0] : '';
    if (q) {
      for (const p of q.split('&')) {
        const [k, v] = p.split('=');
        if (k) out[decodeURIComponent(k).toLowerCase()] = decodeURIComponent(v || '');
      }
    }
  }
  return out;
}

function parsePath(path: string): string[] {
  return path.replace(/^\/+/, '').split('/').filter(Boolean).map(s => s.toLowerCase());
}

function bodyParamNames(body: string, contentType?: string): string[] {
  const names: string[] = [];
  if (!body || typeof body !== 'string') return names;
  const ct = (contentType || '').toLowerCase();

  if (ct.includes('application/json')) {
    try {
      const o = JSON.parse(body) as Record<string, unknown>;
      const collect = (obj: Record<string, unknown>, prefix = '') => {
        for (const k of Object.keys(obj)) {
          const key = (prefix ? `${prefix}.` : '') + k.toLowerCase();
          names.push(key);
          const v = obj[k];
          if (v && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Date)) {
            collect(v as Record<string, unknown>, key);
          }
        }
      };
      collect(o);
    } catch {
      // non-JSON
    }
  } else if (ct.includes('application/x-www-form-urlencoded') || !ct) {
    for (const p of body.split('&')) {
      const [k] = p.split('=');
      if (k) names.push(decodeURIComponent(k).trim().toLowerCase());
    }
  }
  return names;
}

function paramValuesFromUrl(url: string): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = [];
  try {
    const u = new URL(url);
    u.searchParams.forEach((v, k) => out.push({ name: k, value: v }));
  } catch {
    const q = url.includes('?') ? url.split('?')[1]?.split('#')[0] : '';
    if (q) {
      for (const p of q.split('&')) {
        const [k, v] = p.split('=').map(s => decodeURIComponent(s || ''));
        if (k) out.push({ name: k, value: v });
      }
    }
  }
  return out;
}

/** Check if any param value is reflected in response body (simple substring). */
export function findReflectedParams(req: HttpRequest): Array<{ param: string; value: string }> {
  const body = req.responseBody || '';
  if (!body || body.length > 500_000) return [];
  const reflected: Array<{ param: string; value: string }> = [];
  const urlParams = paramValuesFromUrl(req.url);
  for (const { name, value } of urlParams) {
    if (value.length < 2 || value.length > 200) continue;
    if (/^[\d]+$/.test(value)) continue;
    try {
      if (body.includes(value)) reflected.push({ param: name, value });
    } catch {
      // ignore
    }
  }
  if (req.body && (req.contentType || '').toLowerCase().includes('application/x-www-form-urlencoded')) {
    for (const p of req.body.split('&')) {
      const [k, v] = p.split('=').map(s => decodeURIComponent(s || ''));
      if (!k || !v || v.length < 2 || v.length > 200 || /^[\d]+$/.test(v)) continue;
      try {
        if (body.includes(v)) reflected.push({ param: k, value: v });
      } catch {
        // ignore
      }
    }
  }
  return reflected;
}

export function getInvestigationSignals(req: HttpRequest): InvestigationSignals {
  const tags: string[] = [];
  const reasons: string[] = [];
  const sensitiveParams: string[] = [];
  const idorCandidates: string[] = [];
  const paramNames: string[] = [];

  const url = req.url || '';
  const path = url.includes('?') ? url.split('?')[0] : url;
  const pathSegments = parsePath(path);
  const query = parseQuery(url);
  const method = (req.method || 'GET').toLowerCase();
  const headers = req.headers || {};
  const headerKeys = Object.keys(headers).map(h => h.toLowerCase());
  const headersLower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) headersLower[k.toLowerCase()] = v;
  const body = req.body || '';
  const ct = (req.contentType || '').toLowerCase();

  for (const k of Object.keys(query)) {
    paramNames.push(k);
    const kNorm = k.toLowerCase().replace(/[-_]/g, '');
    if (SENSITIVE_PARAMS.some(s => kNorm.includes(s) || s.includes(kNorm))) {
      if (!sensitiveParams.includes(k)) sensitiveParams.push(k);
    }
  }

  const bodyParams = bodyParamNames(body, req.contentType);
  for (const k of bodyParams) {
    const base = k.split('.')[0];
    if (!paramNames.includes(base)) paramNames.push(base);
    const kNorm = base.toLowerCase().replace(/[-_]/g, '');
    if (SENSITIVE_PARAMS.some(s => kNorm.includes(s) || s.includes(kNorm))) {
      if (!sensitiveParams.includes(base)) sensitiveParams.push(base);
    }
  }

  const pathStr = pathSegments.join('/');
  for (const p of HIGH_VALUE_PATH) {
    if (pathStr.includes(p)) {
      tags.push('high-value');
      if (p.includes('graphql') || p === 'gql') tags.push('graphql');
      if (/api|v\d|rest|rpc/.test(pathStr)) tags.push('api');
      reasons.push(`High-value path: ${p}`);
      break;
    }
  }

  if (/\/api\/|\/v\d+\/|\/rest\/|\/graphql\/|\/gql\b|\/rpc\//i.test(path)) {
    if (!tags.includes('api')) tags.push('api');
    reasons.push('API-like path');
  }

  let hasAuth = false;
  for (const h of AUTH_HEADERS) {
    if (headerKeys.some(k => k === h || k.includes(h))) {
      tags.push('auth');
      hasAuth = true;
      reasons.push(`Auth-related header: ${h}`);
      break;
    }
  }

  if (tags.includes('high-value') && !hasAuth) {
    tags.push('no-auth');
    reasons.push('High-value path without auth headers – check access control');
  }

  const upgrade = (headersLower['upgrade'] || '').toLowerCase();
  if (upgrade === 'websocket' || /wss?:/i.test(path)) {
    tags.push('websocket');
    reasons.push('WebSocket upgrade or ws/wss URL');
  }

  for (const ch of CACHE_POISON_HEADERS) {
    if (headerKeys.some(k => k.toLowerCase() === ch)) {
      tags.push('cache-poisoning-candidate');
      reasons.push(`Cache-key–related header: ${ch}`);
      break;
    }
  }

  if (sensitiveParams.length) {
    tags.push('sensitive-params');
    reasons.push(`Sensitive params: ${sensitiveParams.join(', ')}`);
  }

  const seqIdPath = /\/\d{2,}\b|\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
  if (seqIdPath.test(path)) {
    const m = path.match(/\/\d{2,}\b/);
    if (m) idorCandidates.push(`path:${m[0].slice(1)}`);
    tags.push('idor-candidate');
    reasons.push('Sequential or UUID-like ID in path');
  }
  if (query.id || query.user_id || query.account_id || query.order_id) {
    const k = query.id ? 'id' : query.user_id ? 'user_id' : query.account_id ? 'account_id' : 'order_id';
    idorCandidates.push(`query:${k}`);
    if (!tags.includes('idor-candidate')) {
      tags.push('idor-candidate');
      reasons.push('ID-like query param');
    }
  }

  if (method === 'post' && (ct.includes('json') || ct.includes('form'))) {
    tags.push('state-changing');
    reasons.push('POST with JSON/form body');
  }

  if (/upload|import|file|multipart/i.test(ct) || /upload|import|file/i.test(pathStr)) {
    tags.push('upload');
    reasons.push('Upload or file-related');
  }

  const status = req.status || 0;
  if (status >= 400 && status < 500) {
    tags.push('client-error');
  }
  if (status >= 500) {
    tags.push('server-error');
  }

  let risk: RiskLevel = 'info';
  if (tags.includes('high-value') || tags.includes('upload') || (tags.includes('auth') && tags.includes('sensitive-params'))) {
    risk = 'high';
  } else if (tags.includes('api') || tags.includes('sensitive-params') || tags.includes('idor-candidate')) {
    risk = 'medium';
  } else if (tags.includes('auth') || tags.includes('state-changing')) {
    risk = 'low';
  }

  return {
    tags: [...new Set(tags)],
    risk,
    reasons,
    sensitiveParams: [...new Set(sensitiveParams)],
    idorCandidates: [...new Set(idorCandidates)],
    paramNames: [...new Set(paramNames)],
  };
}

/** Whether a request is "interesting" for pentest: APIs or auth endpoints only. */
export function isInterestingForPentest(req: HttpRequest): boolean {
  const url = req.url || '';
  const path = (url.includes('?') ? url.split('?')[0] : url).toLowerCase();
  const apiLike = /\/api\/|\/v\d+\/|\/rest\/|\/graphql\/|\/gql\b|\/rpc\//.test(path);
  const authLike = /\/(?:login|signin|sign-in|auth|oauth|sso|saml|token|2fa|mfa|password|reset|forgot|verify|confirm|register|callback|logout)\b/.test(path);
  return apiLike || authLike;
}
