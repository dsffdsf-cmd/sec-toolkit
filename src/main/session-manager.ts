import * as fs from 'fs';
import * as path from 'path';
import { HttpRequest } from './proxy-server';

interface HAREntry {
  startedDateTime?: string;
  request?: { method?: string; url?: string; headers?: unknown[]; queryString?: unknown[]; postData?: unknown };
  response?: { status?: number; headers?: unknown[]; content?: { text?: string; mimeType?: string } };
}

export interface SessionData {
  name: string;
  timestamp: number;
  requests: HttpRequest[];
  metadata?: {
    description?: string;
    tags?: string[];
  };
}

export class SessionManager {
  private sessionsDir: string;

  constructor() {
    // Store sessions in user's app data directory
    const appDataPath = process.env.APPDATA || 
                       (process.platform === 'darwin' ? process.env.HOME + '/Library/Application Support' : process.env.HOME + '/.config');
    this.sessionsDir = path.join(appDataPath, 'CleanTraffic', 'sessions');
    
    // Create sessions directory if it doesn't exist
    if (!fs.existsSync(this.sessionsDir)) {
      fs.mkdirSync(this.sessionsDir, { recursive: true });
    }
  }

  /**
   * Save current session
   */
  async saveSession(requests: HttpRequest[], name?: string, description?: string): Promise<string> {
    const sessionName = name || `session-${Date.now()}`;
    const sessionData: SessionData = {
      name: sessionName,
      timestamp: Date.now(),
      requests: requests.map(req => ({
        ...req,
        // Ensure all data is serializable
        body: typeof req.body === 'string' ? req.body : String(req.body || ''),
        responseBody: typeof req.responseBody === 'string' ? req.responseBody : String(req.responseBody || ''),
      })),
      metadata: {
        description,
        tags: [],
      },
    };

    const fileName = `${sessionName.replace(/[^a-z0-9]/gi, '_')}_${Date.now()}.json`;
    const filePath = path.join(this.sessionsDir, fileName);

    fs.writeFileSync(filePath, JSON.stringify(sessionData, null, 2), 'utf8');
    
    return filePath;
  }

  /**
   * Load a session
   */
  async loadSession(filePath: string): Promise<SessionData> {
    if (!fs.existsSync(filePath)) {
      throw new Error('Session file not found');
    }

    const fileContent = fs.readFileSync(filePath, 'utf8');
    const sessionData: SessionData = JSON.parse(fileContent);

    return sessionData;
  }

  /**
   * List all saved sessions
   */
  async listSessions(): Promise<Array<{ name: string; filePath: string; timestamp: number; requestCount: number }>> {
    const files = fs.readdirSync(this.sessionsDir);
    const sessions: Array<{ name: string; filePath: string; timestamp: number; requestCount: number }> = [];

    for (const file of files) {
      if (file.endsWith('.json')) {
        try {
          const filePath = path.join(this.sessionsDir, file);
          const fileContent = fs.readFileSync(filePath, 'utf8');
          const sessionData: SessionData = JSON.parse(fileContent);
          
          sessions.push({
            name: sessionData.name,
            filePath,
            timestamp: sessionData.timestamp,
            requestCount: sessionData.requests.length,
          });
        } catch (error) {
          console.error(`Error reading session file ${file}:`, error);
        }
      }
    }

    // Sort by timestamp (newest first)
    return sessions.sort((a, b) => b.timestamp - a.timestamp);
  }

  /**
   * Delete a session
   */
  async deleteSession(filePath: string): Promise<void> {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  }

  /**
   * 2026: Import HAR 1.2 → HttpRequest[]. Spec-compliant parse; Chrome/DevTools/Fiddler interop.
   */
  async importFromHAR(harContent: string): Promise<HttpRequest[]> {
    let har: { log?: { version?: string; entries?: HAREntry[] } };
    try {
      har = JSON.parse(harContent) as typeof har;
    } catch {
      throw new Error('Invalid HAR JSON');
    }
    const log = har?.log;
    if (!log || !Array.isArray(log.entries)) {
      throw new Error('HAR must have log.entries array');
    }

    const base = Date.now();
    const requests: HttpRequest[] = [];
    for (let i = 0; i < log.entries.length; i++) {
      const e = log.entries[i] as HAREntry;
      const req = e.request;
      if (!req) continue;
      const res = e.response ?? {};
      const content = res.content ?? {};
      const fullUrl = req.url ?? '';
      const headers: Record<string, string> = {};
      for (const h of Array.isArray(req.headers) ? req.headers : []) {
        const n = (h as { name?: string; value?: string }).name;
        const v = (h as { name?: string; value?: string }).value;
        if (n != null && n !== '') headers[n] = String(v ?? '');
      }
      const resHeaders: Record<string, string> = {};
      for (const h of Array.isArray(res.headers) ? res.headers : []) {
        const n = (h as { name?: string; value?: string }).name;
        const v = (h as { name?: string; value?: string }).value;
        if (n != null && n !== '') resHeaders[n] = String(v ?? '');
      }
      let body = '';
      const pd = req.postData as { mimeType?: string; text?: string } | undefined;
      if (pd?.text != null) body = String(pd.text);
      let responseBody = '';
      if (content.text != null) responseBody = typeof content.text === 'string' ? content.text : String(content.text);
      const mime = (content.mimeType ?? pd?.mimeType ?? '') as string;
      let ts = base + i;
      if (e.startedDateTime) {
        const d = new Date(e.startedDateTime).getTime();
        if (!Number.isNaN(d)) ts = d;
      }
      requests.push({
        id: `har-${i}-${base}`,
        method: (req.method ?? 'GET').toUpperCase(),
        url: fullUrl,
        headers,
        body,
        timestamp: ts,
        source: 'har',
        status: typeof res.status === 'number' ? res.status : undefined,
        responseHeaders: Object.keys(resHeaders).length ? resHeaders : undefined,
        responseBody: responseBody || undefined,
        contentType: mime || undefined,
      });
    }
    return requests;
  }

  /**
   * Export session to HAR format
   */
  async exportToHAR(requests: HttpRequest[]): Promise<string> {
    const har = {
      log: {
        version: '1.2',
        creator: {
          name: 'CleanTraffic',
          version: '1.0.0',
        },
        entries: requests.map(req => ({
          startedDateTime: new Date(req.timestamp).toISOString(),
          time: 0,
          request: {
            method: req.method,
            url: req.url,
            httpVersion: 'HTTP/1.1',
            headers: Object.entries(req.headers).map(([name, value]) => ({ name, value })),
            queryString: [],
            cookies: [],
            headersSize: -1,
            bodySize: req.body ? new Blob([req.body]).size : 0,
            postData: req.body ? {
              mimeType: req.contentType || 'text/plain',
              text: req.body,
            } : undefined,
          },
          response: {
            status: req.status || 0,
            statusText: '',
            httpVersion: 'HTTP/1.1',
            headers: Object.entries(req.responseHeaders || {}).map(([name, value]) => ({ name, value })),
            cookies: [],
            content: {
              size: req.responseBody ? new Blob([req.responseBody]).size : 0,
              mimeType: req.contentType || 'text/plain',
              text: req.responseBody || '',
            },
            redirectURL: '',
            headersSize: -1,
            bodySize: req.responseBody ? new Blob([req.responseBody]).size : 0,
          },
          cache: {},
          timings: {
            blocked: -1,
            dns: -1,
            connect: -1,
            send: 0,
            wait: 0,
            receive: 0,
            ssl: -1,
          },
        })),
      },
    };

    return JSON.stringify(har, null, 2);
  }
}

