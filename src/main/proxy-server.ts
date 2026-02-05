import { Browser, Page, CDPSession } from 'puppeteer';
import { getPuppeteerCacheDir, launchBrowser } from './browser-launcher';
import { RequestStore } from '../shared/request-store';
import {
  validateUrl,
  validateHeaders,
  validateNotes,
  validateTags,
  truncateForStore,
  LIMITS,
} from '../shared/validation';
import { Scanner, ScanResult } from './scanner';
import { SourceMapManager, SourceMapInfo } from './source-map-manager';
import * as zlib from 'zlib';
import { promisify } from 'util';
// @ts-ignore - brotli doesn't have types
import * as brotliLib from 'brotli';
import axios from 'axios';

export interface HttpRequest {
  id: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  timestamp: number;
  source: string;
  host?: string;
  status?: number;
  responseHeaders?: Record<string, string>;
  responseBody?: string;
  contentType?: string;
  notes?: string;
  tags?: string[];
  intercepted?: boolean;
  modified?: boolean;
  blocked?: boolean;
  mocked?: boolean;
}

export interface RequestModification {
  url?: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface MockResponse {
  status: number;
  headers?: Record<string, string>;
  body?: string;
}

export interface InterceptRule {
  id: string;
  enabled: boolean;
  type: 'block' | 'modify' | 'mock';
  match: {
    urlPattern?: string;
    method?: string;
    headerMatch?: { name: string; value: string };
  };
  action?: RequestModification | MockResponse;
}

export type InterceptMode = 'forward' | 'intercept';

interface PendingRequest {
  request: any; // Puppeteer request
  httpRequest: HttpRequest;
  page: any;
  resolve: (action: 'continue' | 'block' | 'mock') => void;
  modification?: RequestModification;
  mockResponse?: MockResponse;
}

// Maximum response body size to store (reduced for performance)
const MAX_RESPONSE_SIZE = 2 * 1024 * 1024; // 2MB (reduced from 5MB)
// Maximum size for JS files (1MB - truncate larger ones)
const MAX_JS_SIZE = 1 * 1024 * 1024; // 1MB (reduced from 2MB)
// Maximum size to fully display (200KB)
const MAX_DISPLAY_SIZE = 200 * 1024; // 200KB (reduced from 500KB)
// Maximum request body size to store
const MAX_REQUEST_BODY_SIZE = 100 * 1024; // 100KB
const MAX_REQUESTS_PER_SECOND = 200;

// Domains/patterns to exclude from interception
const EXCLUDED_PATTERNS = [
  /^.*\.google\.com$/i,
  /^.*\.googleapis\.com$/i,
  /^.*\.gstatic\.com$/i,
  /^.*\.google-analytics\.com$/i,
  /^.*\.googletagmanager\.com$/i,
  /^.*\.doubleclick\.net$/i,
  /^.*\.googlesyndication\.com$/i,
  /^.*\.googleadservices\.com$/i,
  /^.*\.facebook\.net$/i,
  /^.*\.facebook\.com$/i,
  /^.*\.fbcdn\.net$/i,
  /^.*\.scorecardresearch\.com$/i,
  /^.*\.quantserve\.com$/i,
  /^.*\.outbrain\.com$/i,
  /^.*\.adsrvr\.org$/i,
  /^.*\.adnxs\.com$/i,
  /^.*\.advertising\.com$/i,
  /^.*\.criteo\.com$/i,
  /^.*\.amazon-adsystem\.com$/i,
  /^.*\.ads\.amazon\.com$/i,
  /^.*\.cookielaw\.org$/i,
  /^.*\.cookiebot\.com$/i,
  /^.*\.onetrust\.com$/i,
  /^.*\.trustarc\.com$/i,
  /^.*\.quantcast\.com$/i,
  /^.*\.doubleclick\.net$/i,
  /^.*\.googlesyndication\.com$/i,
  /^.*\.google-analytics\.com$/i,
  /^.*\.analytics\.google\.com$/i,
  /^.*\.googletagmanager\.com$/i,
  /^.*\.hotjar\.com$/i,
  /^.*\.segment\.io$/i,
  /^.*\.mixpanel\.com$/i,
  /^.*\.amplitude\.com$/i,
  /^.*\.newrelic\.com$/i,
  /^.*\.sentry\.io$/i,
  /^.*\.bugsnag\.com$/i,
  /^.*\.adroll\.com$/i,
  /^.*\.adform\.net$/i,
  /^.*\.rubiconproject\.com$/i,
  /^.*\.pubmatic\.com$/i,
  /^.*\.openx\.net$/i,
  /^.*\.adsrvr\.org$/i,
  /^.*\.adtechus\.com$/i,
  /^.*\.tiktokw\.us$/i,
  /^.*\.tiktok\.com$/i,
  /^.*\.tiktokv\.com$/i,
  /^.*\.clarity\.ms$/i,
  /^.*\.clarity\.com$/i,
  /^.*\.bing\.com$/i,
  /^.*\.bingapis\.com$/i,
  /^.*\.reddit\.com$/i,
  /^.*\.redditstatic\.com$/i,
  /^.*\.redd\.it$/i,
  /^.*\.redditmedia\.com$/i,
  /^.*\.microsoft\.com\/clarity/i,
  // Twitter/X
  /^.*\.twitter\.com$/i,
  /^.*\.twimg\.com$/i,
  /^.*\.twitter\.com$/i,
  /^.*\.x\.com$/i,
  /^.*\.ads-twitter\.com$/i,
  /^.*\.ads\.twitter\.com$/i,
  // LinkedIn
  /^.*\.linkedin\.com$/i,
  /^.*\.licdn\.com$/i,
  /^.*\.linkedin\.com$/i,
  // Instagram
  /^.*\.instagram\.com$/i,
  /^.*\.cdninstagram\.com$/i,
  // YouTube
  /^.*\.youtube\.com$/i,
  /^.*\.ytimg\.com$/i,
  /^.*\.googlevideo\.com$/i,
  /^.*\.youtube-nocookie\.com$/i,
  // Pinterest
  /^.*\.pinterest\.com$/i,
  /^.*\.pinimg\.com$/i,
  // Snapchat
  /^.*\.snapchat\.com$/i,
  /^.*\.snap\.com$/i,
  // Amazon
  /^.*\.amazon\.com$/i,
  /^.*\.amazonaws\.com$/i,
  /^.*\.cloudfront\.net$/i,
  // Microsoft
  /^.*\.microsoft\.com$/i,
  /^.*\.microsoftonline\.com$/i,
  /^.*\.live\.com$/i,
  /^.*\.office\.com$/i,
  /^.*\.office365\.com$/i,
  /^.*\.officeapps\.live\.com$/i,
  // Adobe
  /^.*\.adobe\.com$/i,
  /^.*\.adobedtm\.com$/i,
  /^.*\.omtrdc\.net$/i,
  // Cloudflare
  /^.*\.cloudflare\.com$/i,
  /^.*\.cloudflareinsights\.com$/i,
  // Akamai
  /^.*\.akamai\.net$/i,
  /^.*\.akamaized\.net$/i,
  // Fastly
  /^.*\.fastly\.com$/i,
  /^.*\.fastlylb\.net$/i,
  // More analytics
  /^.*\.fullstory\.com$/i,
  /^.*\.logrocket\.com$/i,
  /^.*\.datadoghq\.com$/i,
  /^.*\.heap\.io$/i,
  /^.*\.pendo\.io$/i,
  /^.*\.launchdarkly\.com$/i,
  // More ad networks
  /^.*\.media\.net$/i,
  /^.*\.advertising\.com$/i,
  /^.*\.adtech\.com$/i,
  /^.*\.casalemedia\.com$/i,
  /^.*\.indexexchange\.com$/i,
  /^.*\.33across\.com$/i,
  /^.*\.bidswitch\.net$/i,
  /^.*\.brightcom\.com$/i,
  // CDNs and static hosts
  /^.*\.jsdelivr\.net$/i,
  /^.*\.cdnjs\.com$/i,
  /^.*\.unpkg\.com$/i,
  /^.*\.bootstrapcdn\.com$/i,
  /^.*\.jquery\.com$/i,
  /^.*\.fontawesome\.com$/i,
  /^.*\.googleusercontent\.com$/i,
  // Note: g2g.com is intentionally NOT excluded
];

function shouldIntercept(url: string): boolean {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    
    for (const pattern of EXCLUDED_PATTERNS) {
      if (pattern.test(hostname)) {
        return false;
      }
    }
    return true;
  } catch {
    return true;
  }
}

export class ProxyServer {
  private browser: Browser | null = null;
  private pages: Set<Page> = new Set();
  private requestStore: RequestStore;
  private scanner: Scanner;
  private sourceMapManager: SourceMapManager;
  private requestMap: Map<string, HttpRequest> = new Map();
  private requestTimestamps: number[] = [];
  private lastCleanup: number = Date.now();
  /** Pending responses: url -> requests not yet matched (FIFO). Avoids getAllRequests() per response. */
  private pendingByUrl: Map<string, HttpRequest[]> = new Map();
  private onStoreChange: (() => void) | null = null;
  private storeChangeTimeout: NodeJS.Timeout | null = null;
  private readonly STORE_CHANGE_DEBOUNCE_MS = 0; // Notify main immediately; main does leading-edge batching

  // Request/Response modification capabilities
  private interceptMode: InterceptMode = 'forward';
  private pendingInterceptedRequests: Map<string, PendingRequest> = new Map();
  private interceptRules: InterceptRule[] = [];
  private onInterceptedRequest: ((request: HttpRequest) => void) | null = null;
  private interceptTimeout: number = 30000; // 30 seconds default timeout for intercepted requests

  setStoreChangeHandler(fn: (() => void) | null): void {
    this.onStoreChange = fn;
  }

  private notifyStoreChange(): void {
    if (!this.onStoreChange) return;
    if (this.storeChangeTimeout) {
      clearTimeout(this.storeChangeTimeout);
    }
    if (this.STORE_CHANGE_DEBOUNCE_MS <= 0) {
      this.onStoreChange();
      return;
    }
    this.storeChangeTimeout = setTimeout(() => {
      this.onStoreChange?.();
      this.storeChangeTimeout = null;
    }, this.STORE_CHANGE_DEBOUNCE_MS);
  }

  constructor() {
    this.requestStore = new RequestStore();
    this.scanner = new Scanner();
    this.sourceMapManager = new SourceMapManager();
    
    setInterval(() => {
      const now = Date.now();
      this.requestTimestamps = this.requestTimestamps.filter(ts => now - ts < 1000);
      const maxPendingAge = 60_000;
      for (const [u, list] of this.pendingByUrl) {
        const kept = list.filter(r => now - r.timestamp < maxPendingAge);
        if (kept.length === 0) this.pendingByUrl.delete(u);
        else if (kept.length !== list.length) this.pendingByUrl.set(u, kept);
      }
    }, 60_000);
  }

  private shouldThrottleRequest(): boolean {
    const now = Date.now();
    // Remove timestamps older than 1 second
    this.requestTimestamps = this.requestTimestamps.filter(ts => now - ts < 1000);
    
    // Check if we're exceeding rate limit
    if (this.requestTimestamps.length >= MAX_REQUESTS_PER_SECOND) {
      return true;
    }
    
    this.requestTimestamps.push(now);
    return false;
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // REQUEST/RESPONSE MODIFICATION API
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  /**
   * Set the intercept mode: 'forward' (default) or 'intercept' (pause for manual review)
   */
  setInterceptMode(mode: InterceptMode): void {
    this.interceptMode = mode;
    console.log(`[Proxy] Intercept mode set to: ${mode}`);
  }

  /**
   * Get the current intercept mode
   */
  getInterceptMode(): InterceptMode {
    return this.interceptMode;
  }

  /**
   * Set handler for intercepted requests (called when a request is paused in intercept mode)
   */
  setInterceptedRequestHandler(handler: ((request: HttpRequest) => void) | null): void {
    this.onInterceptedRequest = handler;
  }

  /**
   * Set timeout for intercepted requests (default 30 seconds)
   */
  setInterceptTimeout(ms: number): void {
    this.interceptTimeout = Math.max(5000, Math.min(ms, 300000)); // 5s - 5min
  }

  /**
   * Get all currently intercepted (pending) requests
   */
  getInterceptedRequests(): HttpRequest[] {
    return Array.from(this.pendingInterceptedRequests.values()).map(p => p.httpRequest);
  }

  /**
   * Continue an intercepted request (optionally with modifications)
   */
  async continueRequest(requestId: string, modification?: RequestModification): Promise<boolean> {
    const pending = this.pendingInterceptedRequests.get(requestId);
    if (!pending) {
      console.warn(`[Proxy] Request ${requestId} not found in pending intercepted requests`);
      return false;
    }

    try {
      pending.modification = modification;
      pending.httpRequest.modified = !!modification;
      pending.resolve('continue');
      return true;
    } catch (error) {
      console.error(`[Proxy] Error continuing request ${requestId}:`, error);
      return false;
    }
  }

  /**
   * Block an intercepted request
   */
  async blockRequest(requestId: string): Promise<boolean> {
    const pending = this.pendingInterceptedRequests.get(requestId);
    if (!pending) {
      console.warn(`[Proxy] Request ${requestId} not found in pending intercepted requests`);
      return false;
    }

    try {
      pending.httpRequest.blocked = true;
      pending.resolve('block');
      return true;
    } catch (error) {
      console.error(`[Proxy] Error blocking request ${requestId}:`, error);
      return false;
    }
  }

  /**
   * Respond to an intercepted request with a mock response
   */
  async mockRequestResponse(requestId: string, mockResponse: MockResponse): Promise<boolean> {
    const pending = this.pendingInterceptedRequests.get(requestId);
    if (!pending) {
      console.warn(`[Proxy] Request ${requestId} not found in pending intercepted requests`);
      return false;
    }

    try {
      pending.mockResponse = mockResponse;
      pending.httpRequest.mocked = true;
      pending.resolve('mock');
      return true;
    } catch (error) {
      console.error(`[Proxy] Error mocking response for request ${requestId}:`, error);
      return false;
    }
  }

  /**
   * Add an intercept rule
   */
  addInterceptRule(rule: InterceptRule): void {
    this.interceptRules.push(rule);
    console.log(`[Proxy] Added intercept rule: ${rule.id} (${rule.type})`);
  }

  /**
   * Remove an intercept rule by ID
   */
  removeInterceptRule(ruleId: string): boolean {
    const index = this.interceptRules.findIndex(r => r.id === ruleId);
    if (index >= 0) {
      this.interceptRules.splice(index, 1);
      console.log(`[Proxy] Removed intercept rule: ${ruleId}`);
      return true;
    }
    return false;
  }

  /**
   * Get all intercept rules
   */
  getInterceptRules(): InterceptRule[] {
    return [...this.interceptRules];
  }

  /**
   * Update an intercept rule
   */
  updateInterceptRule(ruleId: string, updates: Partial<InterceptRule>): boolean {
    const rule = this.interceptRules.find(r => r.id === ruleId);
    if (rule) {
      Object.assign(rule, updates);
      return true;
    }
    return false;
  }

  /**
   * Check if a request matches any intercept rule
   */
  private matchInterceptRule(httpRequest: HttpRequest): InterceptRule | null {
    for (const rule of this.interceptRules) {
      if (!rule.enabled) continue;

      const { match } = rule;
      
      // Check URL pattern
      if (match.urlPattern) {
        try {
          const regex = new RegExp(match.urlPattern, 'i');
          if (!regex.test(httpRequest.url)) continue;
        } catch {
          // Invalid regex, skip this rule
          continue;
        }
      }

      // Check method
      if (match.method && httpRequest.method.toUpperCase() !== match.method.toUpperCase()) {
        continue;
      }

      // Check header match
      if (match.headerMatch) {
        const headerValue = httpRequest.headers[match.headerMatch.name] || 
                           httpRequest.headers[match.headerMatch.name.toLowerCase()];
        if (!headerValue || !headerValue.includes(match.headerMatch.value)) {
          continue;
        }
      }

      // All conditions matched
      return rule;
    }

    return null;
  }

  /**
   * Process request through intercept mode or rules
   */
  private async processInterceptedRequest(
    request: any,
    httpRequest: HttpRequest,
    page: any,
    originalMethod: string,
    originalBody: string,
    originalHeaders: Record<string, string>
  ): Promise<void> {
    // Check for matching rules first
    const matchedRule = this.matchInterceptRule(httpRequest);
    
    if (matchedRule) {
      console.log(`[Proxy] Request matched rule: ${matchedRule.id} (${matchedRule.type})`);
      
      if (matchedRule.type === 'block') {
        httpRequest.blocked = true;
        try {
          await request.abort('blockedbyclient');
        } catch {
          // Request may have already been handled
        }
        return;
      }

      if (matchedRule.type === 'mock' && matchedRule.action) {
        const mockResp = matchedRule.action as MockResponse;
        httpRequest.mocked = true;
        httpRequest.status = mockResp.status;
        httpRequest.responseHeaders = mockResp.headers || {};
        httpRequest.responseBody = mockResp.body || '';
        try {
          await request.respond({
            status: mockResp.status,
            headers: mockResp.headers || {},
            body: mockResp.body || '',
          });
        } catch {
          // Request may have already been handled
        }
        this.notifyStoreChange();
        return;
      }

      if (matchedRule.type === 'modify' && matchedRule.action) {
        const mod = matchedRule.action as RequestModification;
        httpRequest.modified = true;
        try {
          await request.continue({
            method: mod.method || originalMethod,
            postData: mod.body !== undefined ? mod.body : originalBody || undefined,
            headers: mod.headers || originalHeaders,
            url: mod.url || httpRequest.url,
          });
        } catch {
          // Request may have already been handled
        }
        return;
      }
    }

    // If in intercept mode, pause the request for manual review
    if (this.interceptMode === 'intercept') {
      httpRequest.intercepted = true;
      
      const pendingPromise = new Promise<'continue' | 'block' | 'mock'>((resolve) => {
        const pending: PendingRequest = {
          request,
          httpRequest,
          page,
          resolve,
        };
        this.pendingInterceptedRequests.set(httpRequest.id, pending);

        // Notify listener about intercepted request
        if (this.onInterceptedRequest) {
          this.onInterceptedRequest(httpRequest);
        }

        // Auto-continue after timeout
        setTimeout(() => {
          if (this.pendingInterceptedRequests.has(httpRequest.id)) {
            console.log(`[Proxy] Request ${httpRequest.id} timed out, auto-continuing`);
            resolve('continue');
          }
        }, this.interceptTimeout);
      });

      const action = await pendingPromise;
      const pendingReq = this.pendingInterceptedRequests.get(httpRequest.id);
      this.pendingInterceptedRequests.delete(httpRequest.id);

      if (action === 'block') {
        try {
          await request.abort('blockedbyclient');
        } catch {
          // Request may have already been handled
        }
        return;
      }

      if (action === 'mock' && pendingReq?.mockResponse) {
        const mockResp = pendingReq.mockResponse;
        httpRequest.status = mockResp.status;
        httpRequest.responseHeaders = mockResp.headers || {};
        httpRequest.responseBody = mockResp.body || '';
        try {
          await request.respond({
            status: mockResp.status,
            headers: mockResp.headers || {},
            body: mockResp.body || '',
          });
        } catch {
          // Request may have already been handled
        }
        this.notifyStoreChange();
        return;
      }

      // Continue with optional modifications
      const mod = pendingReq?.modification;
      try {
        await request.continue({
          method: mod?.method || originalMethod,
          postData: mod?.body !== undefined ? mod.body : originalBody || undefined,
          headers: mod?.headers || originalHeaders,
          url: mod?.url || httpRequest.url,
        });
      } catch {
        // Request may have already been handled
      }
      return;
    }

    // Default: forward the request as-is
    try {
      await request.continue({
        method: originalMethod,
        postData: originalBody || undefined,
        headers: originalHeaders,
      });
    } catch {
      // Request may have already been handled
    }
  }

  async start(): Promise<number> {
    console.log('[Proxy] Launching browser for traffic interception...');

    // Use app userData for Chromium cache (app is ready when user clicks Launch)
    process.env.PUPPETEER_CACHE_DIR = getPuppeteerCacheDir();

    this.browser = await launchBrowser({
      headless: false,
      defaultViewport: { width: 1920, height: 1080 },
    });

    // Set up interception for all existing and new pages
    const setupPageInterception = async (page: Page) => {
      // Skip if page is already closed
      if (page.isClosed()) return;
      
      try {
        // Enable request interception
        await page.setRequestInterception(true);

      // Set up request/response handlers
      page.on('request', async (request) => {
        await this.handleRequest(request, page);
      });

      page.on('response', async (response) => {
        await this.handleResponse(response, page);
      });

      // Enhanced page setup for better compatibility
      await page.setJavaScriptEnabled(true);
      await page.setBypassCSP(true);
      
      // Allow all iframe sandbox permissions for better compatibility
      await page.evaluateOnNewDocument(() => {
        // Override iframe sandbox restrictions to allow proper interaction
        const originalCreateElement = document.createElement.bind(document);
        // Use type assertion to handle overloads properly
        (document.createElement as any) = function(tagName: string, options?: any): HTMLElement {
          const element = originalCreateElement(tagName, options);
          if (tagName.toLowerCase() === 'iframe') {
            // Allow scripts and same-origin by default for better compatibility
            // User can still manually set sandbox attributes if needed
            Object.defineProperty(element, 'sandbox', {
              get: function() {
                return this.getAttribute('sandbox') || '';
              },
              set: function(value: string) {
                // Don't restrict if both allow-scripts and allow-same-origin are present
                // This prevents the sandbox escape warning while maintaining functionality
                if (value && value.includes('allow-scripts') && value.includes('allow-same-origin')) {
                  // Keep the attributes but don't enforce strict sandboxing
                  this.setAttribute('sandbox', value);
                } else {
                  this.setAttribute('sandbox', value || '');
                }
              },
              configurable: true
            });
          }
          return element;
        };
      });

      this.pages.add(page);
      console.log(`[Proxy] Interception enabled for page (total pages: ${this.pages.size})`);
      } catch {
        // Page may have closed during setup - ignore
      }
    };

    // Handle new pages (tabs) being created
    this.browser.on('targetcreated', async (target) => {
      // Only 'page' type targets support the Page protocol API
      // Other types (service_worker, background_page, browser, webview, other) will throw
      // "ProtocolError: Page.enable wasn't found" if we try to call target.page()
      const targetType = target.type();
      if (targetType !== 'page') {
        return; // Skip service workers, background pages, etc.
      }
      
      try {
        const page = await target.page();
        if (page && !page.isClosed()) {
          await setupPageInterception(page);
        }
      } catch {
        // Silently ignore - page may have closed before setup
      }
    });

    // Set up interception for initial pages (usually just one blank page)
    const initialPages = await this.browser.pages();
    // Only set up interception for the first page, close others if any
    if (initialPages.length > 0) {
      // Close extra pages, keep only the first one
      for (let i = 1; i < initialPages.length; i++) {
        await initialPages[i].close();
      }
      await setupPageInterception(initialPages[0]);
    } else {
      // If no pages exist, create one
      const newPage = await this.browser.newPage();
      await setupPageInterception(newPage);
    }

    console.log('[Proxy] Browser launched and ready for traffic interception');
    console.log('[Proxy] All tabs will intercept traffic automatically');
    console.log('[Proxy] Open new tabs and navigate to any website');
    
    return 0; // No port needed for Puppeteer
  }

  private async handleRequest(request: any, page: Page): Promise<void> {
    const rawUrl = request.url();
    const method = request.method();
    const postData = request.postData() ?? '';
    const headers = request.headers();

    if (!shouldIntercept(rawUrl)) {
      // Continue with original method and body for non-intercepted requests
      try {
        await request.continue({
          method: method,
          postData: postData || undefined,
          headers: headers,
        });
      } catch {
        // Request may have already been handled
      }
      return;
    }
    const urlResult = validateUrl(rawUrl);
    if (!urlResult.ok) {
      // Continue with original method and body if URL validation fails
      try {
        await request.continue({
          method: method,
          postData: postData || undefined,
          headers: headers,
        });
      } catch {
        // Request may have already been handled
      }
      return;
    }
    const url = urlResult.value;

    const requestId = this.generateId();
    const allHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      allHeaders[key] = typeof value === 'string' ? value : String(value);
    }
    const headersResult = validateHeaders(allHeaders);
    const safeHeaders = headersResult.ok ? headersResult.value : {};
    const body =
      postData.length > MAX_REQUEST_BODY_SIZE
        ? truncateForStore(postData, MAX_REQUEST_BODY_SIZE)
        : postData;

    const httpRequest: HttpRequest = {
      id: requestId,
      method: (method || 'GET').toUpperCase(),
      url,
      headers: safeHeaders,
      body,
      timestamp: Date.now(),
      source: `browser-tab-${page.url().substring(0, 30)}`,
      host: new URL(url).hostname,
      contentType: safeHeaders['content-type'] || safeHeaders['Content-Type'] || '',
      intercepted: false,
      modified: false,
      blocked: false,
      mocked: false,
    };

    // Log non-GET requests for debugging
    if (method && method.toUpperCase() !== 'GET') {
      console.log(`[Proxy] Intercepted ${method.toUpperCase()} request: ${url.substring(0, 100)}${url.length > 100 ? '...' : ''}`);
    }

    this.requestMap.set(requestId, httpRequest);
    const added = this.requestStore.addRequest(httpRequest);
    if (added) {
      const list = this.pendingByUrl.get(url) ?? [];
      list.push(httpRequest);
      this.pendingByUrl.set(url, list);
      this.notifyStoreChange();
    }

    // Process through intercept mode / rules
    await this.processInterceptedRequest(request, httpRequest, page, method, postData, headers);
  }

  private async decompressBody(buffer: Buffer, contentEncoding: string): Promise<string> {
    if (!contentEncoding) {
      return buffer.toString('utf8');
    }

    const encoding = contentEncoding.toLowerCase().trim();
    
    try {
      if (encoding.includes('br') || encoding.includes('brotli')) {
        // Brotli decompression
        const decompressed = brotliLib.decompress(buffer);
        if (decompressed) {
          return Buffer.from(decompressed).toString('utf8');
        }
      } else if (encoding.includes('gzip')) {
        // Gzip decompression
        const gunzip = promisify(zlib.gunzip);
        const decompressed = await gunzip(buffer);
        return decompressed.toString('utf8');
      } else if (encoding.includes('deflate')) {
        // Deflate decompression
        const inflate = promisify(zlib.inflate);
        const decompressed = await inflate(buffer);
        return decompressed.toString('utf8');
      }
    } catch (error) {
      console.warn(`[Proxy] Failed to decompress ${encoding}, using raw text`);
      return buffer.toString('utf8');
    }

    return buffer.toString('utf8');
  }

  private async handleResponse(response: any, page: Page): Promise<void> {
    const url = response.url();
    if (this.shouldThrottleRequest()) return;

    const status = response.status();
    const headers = response.headers();

    const list = this.pendingByUrl.get(url);
    const request = list?.shift() ?? null;
    if (list?.length === 0) this.pendingByUrl.delete(url);
    if (!request) return;

    try {
      // Get response body - ALWAYS as string, Puppeteer's text() handles decompression
      let responseBody: string = '';
      const contentTypeHeader = headers['content-type'] || headers['Content-Type'] || '';
      const contentType = contentTypeHeader.toLowerCase();
      // Extract base content type (remove charset, etc.)
      const baseContentType = contentType.split(';')[0].trim();
      
      // Check if it's a JavaScript file - handle differently to prevent overload
      const isJS = this.isJavaScriptFile(contentTypeHeader, url);
      
      const contentLength = parseInt(headers['content-length'] || headers['Content-Length'] || '0', 10);

      if (contentLength > MAX_RESPONSE_SIZE) {
        request.status = status;
        request.responseHeaders = headers;
        request.responseBody = `[Response too large - ${(contentLength / 1024 / 1024).toFixed(2)} MB - truncated]`;
        this.notifyStoreChange();
        return;
      }
      
      // For text-based content, use text() which handles decompression automatically
      // Handle application/json; charset=UTF-8 and similar
      if (contentType.includes('text/') || 
          baseContentType === 'application/json' ||
          contentType.includes('application/json') || 
          contentType.includes('application/javascript') ||
          contentType.includes('application/xml') ||
          contentType.includes('application/xhtml') ||
          contentType.includes('application/x-www-form-urlencoded')) {
        try {
          responseBody = await response.text();
        } catch (e) {
          // Fallback - try to get as text anyway
          try {
            const buffer = await response.buffer();
            responseBody = buffer.toString('utf8');
          } catch (e2) {
            responseBody = '';
          }
        }
      } else {
        // For other content types, still try to get as text
        try {
          responseBody = await response.text();
        } catch (e) {
          // If text() fails, try buffer and convert
          try {
            const buffer = await response.buffer();
            const text = buffer.toString('utf8');
            // Check if it's valid UTF-8 text (no null bytes in first 1000 chars)
            if (!buffer.includes(0) || text.substring(0, 1000).indexOf('\0') === -1) {
              responseBody = text;
            } else {
              // Binary data - show as placeholder
              responseBody = `[Binary data - ${buffer.length} bytes]`;
            }
          } catch (e2) {
            responseBody = '';
          }
        }
      }

      const originalLength = responseBody.length;
      if (isJS && originalLength > MAX_JS_SIZE) {
        responseBody = responseBody.substring(0, MAX_JS_SIZE);
        responseBody += `\n\n/* [Content truncated - original size: ${(originalLength / 1024 / 1024).toFixed(2)} MB, showing first ${(MAX_JS_SIZE / 1024 / 1024).toFixed(2)} MB] */`;
      } else if (originalLength > MAX_DISPLAY_SIZE) {
        responseBody = responseBody.substring(0, MAX_DISPLAY_SIZE);
        responseBody += `\n\n[Content truncated - original size: ${(originalLength / 1024 / 1024).toFixed(2)} MB, showing first ${(MAX_DISPLAY_SIZE / 1024 / 1024).toFixed(2)} MB]`;
      }
      
      // Ensure responseBody is a proper string (not undefined/null)
      if (!responseBody || typeof responseBody !== 'string') {
        responseBody = '';
      }

      request.status = status;
      request.responseHeaders = headers;
      request.responseBody = responseBody;
      this.notifyStoreChange();

      if (isJS && responseBody) {
        await this.processSourceMapIfPresent(url, responseBody);
      }
    } catch (error: any) {
      request.status = status;
      request.responseHeaders = headers;
      this.notifyStoreChange();
    }
  }

  async stop(): Promise<void> {
    if (this.storeChangeTimeout) {
      clearTimeout(this.storeChangeTimeout);
      this.storeChangeTimeout = null;
    }
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
      this.pages.clear();
      console.log('[Proxy] Browser closed');
    }
  }

  async repeatRequest(requestData: HttpRequest): Promise<HttpRequest> {
    const repeatedRequest: HttpRequest = {
      ...requestData,
      id: this.generateId(),
      timestamp: Date.now(),
    };

    try {
      // Use axios directly from main process - more reliable than Puppeteer page.evaluate
      const method = (requestData.method || 'GET').toUpperCase();
      const config: any = {
        method: method.toLowerCase(),
        url: requestData.url,
        headers: requestData.headers || {},
        maxContentLength: 5 * 1024 * 1024, // 5MB max
        maxBodyLength: 5 * 1024 * 1024,
        validateStatus: () => true, // Don't throw on any status
        timeout: 30000, // 30 second timeout
      };

      // Add body for methods that support it
      const methodsWithoutBody = ['GET', 'HEAD', 'OPTIONS'];
      if (requestData.body && requestData.body.length > 0 && !methodsWithoutBody.includes(method)) {
        config.data = requestData.body;
        // Set content-type if not already set
        if (!config.headers['content-type'] && !config.headers['Content-Type']) {
          config.headers['content-type'] = requestData.contentType || 'application/json';
        }
      }

      const response = await axios(config);
      
      const MAX_DISPLAY = 500 * 1024; // 500KB
      let responseBody = '';
      
      if (typeof response.data === 'string') {
        responseBody = response.data;
      } else if (Buffer.isBuffer(response.data)) {
        // Try to decode as UTF-8, fallback to binary placeholder
        try {
          responseBody = response.data.toString('utf8');
        } catch {
          responseBody = `[Binary data - ${response.data.length} bytes]`;
        }
      } else {
        // JSON or other object
        responseBody = JSON.stringify(response.data, null, 2);
      }

      // Truncate if too large
      if (responseBody.length > MAX_DISPLAY) {
        const originalLength = responseBody.length;
        responseBody = responseBody.substring(0, MAX_DISPLAY) + 
          `\n\n[Content truncated - original size: ${(originalLength / 1024 / 1024).toFixed(2)} MB, showing first ${(MAX_DISPLAY / 1024 / 1024).toFixed(2)} MB]`;
      }

      repeatedRequest.status = response.status;
      repeatedRequest.responseHeaders = response.headers as Record<string, string>;
      repeatedRequest.responseBody = responseBody;

      if (this.requestStore.addRequest(repeatedRequest)) this.notifyStoreChange();
      return repeatedRequest;
    } catch (error: any) {
      repeatedRequest.status = 0;
      const errorMsg = error.response 
        ? `HTTP ${error.response.status}: ${error.response.statusText || error.message}`
        : error.message || 'Failed to send request';
      repeatedRequest.responseBody = `Error: ${errorMsg}`;
      repeatedRequest.responseHeaders = error.response?.headers || {};
      if (this.requestStore.addRequest(repeatedRequest)) this.notifyStoreChange();
      return repeatedRequest;
    }
  }

  /** Extract JavaScript code from HTML content (script tags, inline scripts, event handlers) */
  private extractJavaScriptFromHTML(html: string): string {
    const jsParts: string[] = [];
    
    // Extract <script> tag contents (both inline and external src)
    const scriptTagRegex = /<script[^>]*>(.*?)<\/script>/gis;
    let match: RegExpExecArray | null;
    while ((match = scriptTagRegex.exec(html)) !== null) {
      const scriptContent = match[1];
      if (scriptContent && scriptContent.trim()) {
        jsParts.push(scriptContent);
      }
    }
    
    // Extract inline event handlers (onclick, onerror, onload, etc.)
    const eventHandlerRegex = /\b(on\w+)\s*=\s*["']([^"']+)["']/gi;
    while ((match = eventHandlerRegex.exec(html)) !== null) {
      const handlerCode = match[2];
      if (handlerCode && handlerCode.trim()) {
        jsParts.push(handlerCode);
      }
    }
    
    // Extract JavaScript: URLs (href="javascript:...", src="javascript:...")
    const javascriptUrlRegex = /javascript:\s*([^"'\s>]+)/gi;
    while ((match = javascriptUrlRegex.exec(html)) !== null) {
      const jsCode = match[1];
      if (jsCode && jsCode.trim()) {
        jsParts.push(jsCode);
      }
    }
    
    // Extract data attributes that might contain JavaScript (data-onclick, etc.)
    const dataAttrRegex = /\bdata-(?:on\w+|js|script)\s*=\s*["']([^"']+)["']/gi;
    while ((match = dataAttrRegex.exec(html)) !== null) {
      const dataCode = match[1];
      if (dataCode && dataCode.trim()) {
        jsParts.push(dataCode);
      }
    }
    
    // Extract template literals and expressions in attributes that might be evaluated
    const templateExprRegex = /\$\{([^}]+)\}/g;
    while ((match = templateExprRegex.exec(html)) !== null) {
      const expr = match[1];
      if (expr && expr.trim()) {
        jsParts.push(expr);
      }
    }
    
    // Join all extracted JavaScript with newlines for scanning
    return jsParts.join('\n\n');
  }

  /** Returns { code, url } for JS requests, null otherwise. Used by main to run scan in worker. */
  getCodeToScan(requestData: HttpRequest): { code: string; url: string } | null {
    if (!this.isJavaScriptFile(requestData.contentType || '', requestData.url)) return null;
    const body = requestData.responseBody || '';
    const sourceMapInfo = this.sourceMapManager.getSourceMapInfo(requestData.url);
    let code = sourceMapInfo?.originalSource || body;
    
    // If it's HTML content, extract JavaScript from it
    const contentType = (requestData.contentType || '').toLowerCase();
    if (contentType.includes('text/html') || requestData.url.endsWith('.html') || requestData.url.endsWith('.htm')) {
      const extractedJS = this.extractJavaScriptFromHTML(code);
      if (extractedJS.trim()) {
        code = extractedJS;
      } else {
        // If no JavaScript found in HTML, still return the HTML body for scanning
        // (the scanner can handle HTML and look for patterns in it)
        code = body;
      }
    }
    
    return { code, url: requestData.url };
  }

  async scanRequest(
    requestData: HttpRequest,
    onPhase?: (phase: number, label: string) => void
  ): Promise<ScanResult[]> {
    const payload = this.getCodeToScan(requestData);
    if (!payload) return [];
    return await this.scanner.scanJavaScript(payload.code, payload.url, onPhase);
  }

  /**
   * Process source map if present in JavaScript response
   */
  private async processSourceMapIfPresent(jsUrl: string, jsCode: string): Promise<void> {
    try {
      // Extract source map URL from JavaScript code
      const sourceMapUrl = this.sourceMapManager.extractSourceMapUrl(jsCode);
      
      if (!sourceMapUrl) {
        return; // No source map found
      }

      // Resolve source map URL (handle relative paths)
      const resolvedUrl = this.sourceMapManager.resolveSourceMapUrl(sourceMapUrl, jsUrl);
      
      // Check if we already processed this source map
      if (this.sourceMapManager.getSourceMapInfo(resolvedUrl)) {
        return; // Already processed
      }

      console.log(`[SourceMap] Found source map for ${jsUrl}: ${resolvedUrl}`);

      // Fetch source map
      try {
        const response = await axios.get(resolvedUrl, {
          timeout: 10000,
          maxContentLength: 10 * 1024 * 1024, // 10MB max
        });

        if (response.data) {
          const sourceMapContent = typeof response.data === 'string' 
            ? response.data 
            : JSON.stringify(response.data);
          
          // Process and store source map
          await this.sourceMapManager.processSourceMap(resolvedUrl, jsUrl, sourceMapContent);
          console.log(`[SourceMap] Processed source map for ${jsUrl}`);
        }
      } catch (error: any) {
        // If fetching fails, try inline source map (data URL)
        if (sourceMapUrl.startsWith('data:')) {
          try {
            // Extract base64 data from data URL
            const base64Match = sourceMapUrl.match(/data:application\/json[^,]*;base64,(.+)/);
            if (base64Match) {
              const sourceMapContent = Buffer.from(base64Match[1], 'base64').toString('utf8');
              await this.sourceMapManager.processSourceMap(resolvedUrl, jsUrl, sourceMapContent);
              console.log(`[SourceMap] Processed inline source map for ${jsUrl}`);
            }
          } catch (e) {
            console.warn(`[SourceMap] Failed to process inline source map for ${jsUrl}:`, e);
          }
        } else {
          console.warn(`[SourceMap] Failed to fetch source map ${resolvedUrl}:`, error.message);
        }
      }
    } catch (error: any) {
      console.warn(`[SourceMap] Error processing source map for ${jsUrl}:`, error.message);
    }
  }

  /**
   * Get source maps for a specific host
   */
  getSourceMapsByHost(host: string): SourceMapInfo[] {
    return this.sourceMapManager.getSourceMapsByHost(host);
  }

  /**
   * Get all source maps
   */
  getAllSourceMaps(): SourceMapInfo[] {
    return this.sourceMapManager.getAllSourceMaps();
  }

  getRequests(): HttpRequest[] {
    // All bodies are already strings, just return as-is
    return this.requestStore.getAllRequests().map(req => ({
      ...req,
      body: typeof req.body === 'string' ? req.body : (req.body ? String(req.body) : ''),
      responseBody: typeof req.responseBody === 'string' ? req.responseBody : (req.responseBody ? String(req.responseBody) : undefined),
    }));
  }

  /**
   * Update notes and tags for a request
   */
  async updateRequestNotesTags(
    requestId: string,
    notes: string,
    tags: string[]
  ): Promise<{ success: boolean; error?: string }> {
    const n = validateNotes(notes);
    if (!n.ok) return { success: false, error: n.error };
    const t = validateTags(tags);
    if (!t.ok) return { success: false, error: t.error };
    const request = this.requestStore.getRequestById(requestId);
    if (request) {
      request.notes = n.value;
      request.tags = t.value;
      this.notifyStoreChange();
      return { success: true };
    }
    return { success: false };
  }

  async navigateToUrl(url: string): Promise<void> {
    if (!this.browser || this.pages.size === 0) {
      throw new Error('Browser not started');
    }
    // Use the first available page or create a new one
    const page = Array.from(this.pages)[0] || await this.browser.newPage();
    
    // Enhanced navigation with better wait strategies for all websites
    try {
      // Try multiple wait strategies for maximum compatibility
      await page.goto(url, { 
        waitUntil: 'domcontentloaded', // Start with DOM ready
        timeout: 60000, // 60 second timeout for slow sites
      });
      
      // Wait for network to be idle (but don't fail if it never becomes idle)
      try {
        // Wait for page to be fully loaded
        await Promise.race([
          page.waitForFunction(() => document.readyState === 'complete', { timeout: 10000 }),
          new Promise(resolve => setTimeout(resolve, 5000)) // Fallback timeout
        ]);
      } catch (e) {
        // Network idle timeout is OK - page may still be loading resources
        console.log('[Proxy] Page loaded (network may still be active)');
      }
      
      // Additional wait for dynamic content
      await page.waitForTimeout(2000); // Give time for JS to execute
      
      // Ensure page is interactive
      await page.evaluate(() => {
        // Trigger any lazy-loaded content
        window.scrollTo(0, document.body.scrollHeight / 2);
        return new Promise(resolve => setTimeout(resolve, 1000));
      });
      
    } catch (error: any) {
      // If navigation fails, try with more permissive settings
      console.warn(`[Proxy] Initial navigation failed, retrying with relaxed settings: ${error.message}`);
      try {
        await page.goto(url, { 
          waitUntil: 'load',
          timeout: 90000,
        });
        await page.waitForTimeout(3000); // Give extra time for slow sites
      } catch (retryError: any) {
        console.error(`[Proxy] Navigation failed after retry: ${retryError.message}`);
        throw new Error(`Failed to navigate to ${url}: ${retryError.message}`);
      }
    }
  }

  async createNewTab(): Promise<void> {
    if (!this.browser) {
      throw new Error('Browser not started');
    }
    const newPage = await this.browser.newPage();
    
    // Enhanced page setup for new tabs
    await newPage.setJavaScriptEnabled(true);
    await newPage.setBypassCSP(true);
    
    // Apply same iframe sandbox handling as main pages
    await newPage.evaluateOnNewDocument(() => {
      const originalCreateElement = document.createElement.bind(document);
      // Use type assertion to handle overloads properly
      (document.createElement as any) = function(tagName: string, options?: any): HTMLElement {
        const element = originalCreateElement(tagName, options);
        if (tagName.toLowerCase() === 'iframe') {
          Object.defineProperty(element, 'sandbox', {
            get: function() {
              return this.getAttribute('sandbox') || '';
            },
            set: function(value: string) {
              if (value && value.includes('allow-scripts') && value.includes('allow-same-origin')) {
                this.setAttribute('sandbox', value);
              } else {
                this.setAttribute('sandbox', value || '');
              }
            },
            configurable: true
          });
        }
        return element;
      };
    });
    
    await newPage.setRequestInterception(true);
    
    newPage.on('request', async (request) => {
      await this.handleRequest(request, newPage);
    });

    newPage.on('response', async (response) => {
      await this.handleResponse(response, newPage);
    });

    this.pages.add(newPage);
    console.log(`[Proxy] New tab created (total tabs: ${this.pages.size})`);
  }

  private isJavaScriptFile(contentType: string, url: string): boolean {
    return contentType.includes('javascript') || 
           contentType.includes('application/json') ||
           contentType.includes('text/html') || // HTML pages can contain embedded JavaScript
           url.endsWith('.js') || 
           url.endsWith('.mjs') ||
           url.endsWith('.axd') || // ASP.NET Web Resource files (ScriptResource.axd, WebResource.axd) contain JavaScript
           url.endsWith('.html') ||
           url.endsWith('.htm') ||
           url.includes('/js/') ||
           url.includes('.js?') ||
           url.includes('.axd?'); // ASP.NET .axd files with query parameters
  }

  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

}
