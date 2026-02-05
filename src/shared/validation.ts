/**
 * Centralized input validation for proxy, store, and IPC.
 * Enforces limits to prevent OOM, abuse, and malformed data.
 */

export const LIMITS = {
  URL_MAX_LENGTH: 8192,
  BODY_MAX_LENGTH: 10 * 1024 * 1024, // 10MB
  HEADERS_MAX_COUNT: 128,
  HEADER_NAME_MAX_LENGTH: 256,
  HEADER_VALUE_MAX_LENGTH: 8192,
  REQUEST_STORE_BODY_TRUNCATE: 100 * 1024, // 100KB
  REQUEST_STORE_RESPONSE_TRUNCATE: 100 * 1024, // 100KB
  SCAN_CODE_MAX_LENGTH: 2 * 1024 * 1024, // 2MB
  NOTES_MAX_LENGTH: 32 * 1024, // 32KB
  TAGS_MAX_COUNT: 32,
  TAG_MAX_LENGTH: 64,
} as const;

export interface ValidationResult<T = unknown> {
  ok: true;
  value: T;
}

export interface ValidationError {
  ok: false;
  error: string;
  field?: string;
}

export type Validation<T = unknown> = ValidationResult<T> | ValidationError;

export function validateUrl(url: string): Validation<string> {
  if (typeof url !== 'string') return { ok: false, error: 'URL must be a string', field: 'url' };
  const t = url.trim();
  if (!t) return { ok: false, error: 'URL is empty', field: 'url' };
  if (t.length > LIMITS.URL_MAX_LENGTH) {
    return { ok: false, error: `URL exceeds ${LIMITS.URL_MAX_LENGTH} characters`, field: 'url' };
  }
  try {
    new URL(t);
    return { ok: true, value: t };
  } catch {
    return { ok: false, error: 'Invalid URL format', field: 'url' };
  }
}

export function validateBodySize(body: string | undefined, maxBytes = LIMITS.BODY_MAX_LENGTH): Validation<string> {
  if (body == null || body === '') return { ok: true, value: '' };
  const s = typeof body === 'string' ? body : String(body);
  if (s.length > maxBytes) {
    return {
      ok: false,
      error: `Body exceeds ${maxBytes} bytes (got ${s.length})`,
      field: 'body',
    };
  }
  return { ok: true, value: s };
}

export function validateHeaders(
  headers: Record<string, string> | undefined
): Validation<Record<string, string>> {
  if (!headers || typeof headers !== 'object') return { ok: true, value: {} };
  const keys = Object.keys(headers);
  if (keys.length > LIMITS.HEADERS_MAX_COUNT) {
    return {
      ok: false,
      error: `Too many headers (max ${LIMITS.HEADERS_MAX_COUNT}, got ${keys.length})`,
      field: 'headers',
    };
  }
  const out: Record<string, string> = {};
  for (const k of keys) {
    if (k.length > LIMITS.HEADER_NAME_MAX_LENGTH) continue;
    const v = headers[k];
    const vs = typeof v === 'string' ? v : String(v ?? '');
    if (vs.length > LIMITS.HEADER_VALUE_MAX_LENGTH) continue;
    out[k] = vs;
  }
  return { ok: true, value: out };
}

export function validateNotes(notes: string): Validation<string> {
  if (typeof notes !== 'string') return { ok: false, error: 'Notes must be a string', field: 'notes' };
  if (notes.length > LIMITS.NOTES_MAX_LENGTH) {
    return { ok: false, error: `Notes exceed ${LIMITS.NOTES_MAX_LENGTH} characters`, field: 'notes' };
  }
  return { ok: true, value: notes };
}

export function validateTags(tags: string[]): Validation<string[]> {
  if (!Array.isArray(tags)) return { ok: false, error: 'Tags must be an array', field: 'tags' };
  if (tags.length > LIMITS.TAGS_MAX_COUNT) {
    return { ok: false, error: `Max ${LIMITS.TAGS_MAX_COUNT} tags allowed`, field: 'tags' };
  }
  const out: string[] = [];
  for (const t of tags) {
    const s = typeof t === 'string' ? t.trim() : String(t).trim();
    if (!s) continue;
    if (s.length > LIMITS.TAG_MAX_LENGTH) continue;
    out.push(s);
  }
  return { ok: true, value: out };
}

export function truncateForStore(
  body: string,
  maxBytes: number
): string {
  if (body.length <= maxBytes) return body;
  return body.substring(0, maxBytes) + '\n\n[Truncated - exceeded size limit]';
}
