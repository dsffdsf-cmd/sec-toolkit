/**
 * CleanTraffic - Postman Collection v2.1 export from captured HTTP requests.
 * Export selected or all requests for use in Postman.
 */

import type { HttpRequest } from './proxy-server';

function safeName(req: HttpRequest, index: number): string {
  try {
    const u = new URL(req.url);
    const path = u.pathname || '/';
    const method = (req.method || 'GET').toUpperCase();
    const last = path.split('/').filter(Boolean).pop() || 'index';
    return `${method} ${path.length > 50 ? path.slice(0, 47) + '…' : path}`.trim() || `${method} request ${index + 1}`;
  } catch {
    return `${(req.method || 'GET').toUpperCase()} request ${index + 1}`;
  }
}

export function requestsToPostmanCollection(requests: HttpRequest[], collectionName = 'CleanTraffic'): string {
  const items = requests.map((req, i) => {
    const headers = Object.entries(req.headers || {}).map(([key, value]) => ({ key, value }));
    const body: { mode: 'raw'; raw?: string } = { mode: 'raw' };
    if (req.body && req.body.length > 0) {
      body.raw = req.body;
    }
    return {
      name: safeName(req, i),
      request: {
        method: (req.method || 'GET').toUpperCase(),
        header: headers,
        url: req.url,
        body: req.body && req.body.length > 0 ? body : undefined,
      },
    };
  });
  const collection = {
    info: {
      name: collectionName,
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json',
      _exporter: 'CleanTraffic',
    },
    item: items,
  };
  return JSON.stringify(collection, null, 2);
}
