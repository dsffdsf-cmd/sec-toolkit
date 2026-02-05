import { HttpRequest } from '../main/proxy-server';
import * as crypto from 'crypto';
import { LIMITS, truncateForStore } from './validation';

export class RequestStore {
  private requests: HttpRequest[] = [];
  private requestHashes: Set<string> = new Set();
  private cleanupInterval: NodeJS.Timeout | null = null;
  private readonly DEDUP_WINDOW_MS = 5000; // 5 seconds window for deduplication
  private requestHashTimestamps: Map<string, number> = new Map();

  constructor() {
    // Auto-cleanup old requests every 10 minutes (less frequent)
    this.cleanupInterval = setInterval(() => {
      this.cleanupOldRequests();
      this.cleanupOldHashes();
    }, 10 * 60 * 1000);
  }

  /**
   * Generate a unique hash for a request based on method, URL, and body
   * This helps identify duplicate requests within a short time window
   */
  private generateRequestHash(request: HttpRequest): string {
    let normalizedUrl: string;
    
    try {
      // Normalize URL by removing query parameters that might change (like timestamps, nonces)
      const url = new URL(request.url);
      normalizedUrl = `${url.protocol}//${url.hostname}${url.pathname}`;
    } catch {
      // If URL parsing fails, use the original URL
      normalizedUrl = request.url;
    }
    
    // Create hash from method, normalized URL, and body (first 1000 chars of body)
    const bodyHash = request.body ? crypto.createHash('md5').update(request.body.substring(0, 1000)).digest('hex').substring(0, 8) : '';
    const hashInput = `${request.method}:${normalizedUrl}:${bodyHash}`;
    
    return crypto.createHash('md5').update(hashInput).digest('hex');
  }

  /**
   * Check if a request is a duplicate within the deduplication window
   */
  private isDuplicate(request: HttpRequest): boolean {
    const hash = this.generateRequestHash(request);
    const now = Date.now();
    
    // Check if we've seen this hash recently
    const lastSeen = this.requestHashTimestamps.get(hash);
    if (lastSeen && (now - lastSeen) < this.DEDUP_WINDOW_MS) {
      return true;
    }
    
    // Update timestamp for this hash
    this.requestHashTimestamps.set(hash, now);
    return false;
  }

  /**
   * Clean up old hash timestamps to prevent memory leak
   */
  private cleanupOldHashes(): void {
    const now = Date.now();
    const entriesToDelete: string[] = [];
    
    this.requestHashTimestamps.forEach((timestamp, hash) => {
      if (now - timestamp > this.DEDUP_WINDOW_MS * 2) {
        entriesToDelete.push(hash);
      }
    });
    
    entriesToDelete.forEach(hash => {
      this.requestHashTimestamps.delete(hash);
      this.requestHashes.delete(hash);
    });
  }

  /** Returns true if the request was added, false if duplicate (skipped). */
  addRequest(request: HttpRequest): boolean {
    if (this.isDuplicate(request)) return false;

    if (request.responseBody && request.responseBody.length > LIMITS.REQUEST_STORE_RESPONSE_TRUNCATE) {
      request.responseBody = truncateForStore(
        request.responseBody,
        LIMITS.REQUEST_STORE_RESPONSE_TRUNCATE
      );
    }
    if (request.body && request.body.length > LIMITS.REQUEST_STORE_BODY_TRUNCATE) {
      request.body = truncateForStore(request.body, LIMITS.REQUEST_STORE_BODY_TRUNCATE);
    }

    const hash = this.generateRequestHash(request);
    this.requestHashes.add(hash);
    this.requests.push(request);
    return true;
  }

  private cleanupOldRequests(): void {
    const now = Date.now();
    const maxAge = 2 * 60 * 60 * 1000; // 2 hours (increased from 30 minutes)
    
    // Only remove requests older than 2 hours to prevent unlimited growth
    // This keeps recent traffic while allowing all requests to be captured
    this.requests = this.requests.filter(req => {
      const age = now - req.timestamp;
      return age < maxAge;
    });
  }

  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  getAllRequests(): HttpRequest[] {
    return [...this.requests].reverse(); // Most recent first
  }

  getRequestById(id: string): HttpRequest | undefined {
    return this.requests.find((r) => r.id === id);
  }

  clear(): void {
    this.requests = [];
  }

  filterRequests(filter: (request: HttpRequest) => boolean): HttpRequest[] {
    return this.requests.filter(filter);
  }
}

