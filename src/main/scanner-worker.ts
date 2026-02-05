/**
 * Scanner worker: runs scanJavaScript off the main thread to avoid UI freeze.
 * Receives { type: 'scan', code, url }; posts { type: 'phase' } and { type: 'done', results } or { type: 'error', error }.
 */
import { parentPort } from 'worker_threads';
import { Scanner } from './scanner';

const scanner = new Scanner();

parentPort?.on('message', (msg: { type: string; code?: string; url?: string; customPatterns?: string[] }) => {
  if (msg.type !== 'scan' || typeof msg.code !== 'string' || typeof msg.url !== 'string') {
    return;
  }
  const { code, url, customPatterns } = msg;
  scanner
    .scanJavaScript(code, url, (phase, label) => {
      parentPort?.postMessage({ type: 'phase', phase, label });
    }, Array.isArray(customPatterns) ? customPatterns : undefined)
    .then((results) => {
      parentPort?.postMessage({ type: 'done', results });
    })
    .catch((err: unknown) => {
      const error = err instanceof Error ? err.message : String(err);
      parentPort?.postMessage({ type: 'error', error });
    });
});
