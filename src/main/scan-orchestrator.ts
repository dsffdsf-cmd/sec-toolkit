/**
 * Runs Scanner in a worker thread. Main stays responsive; phases are forwarded via callback.
 */
import * as path from 'path';
import { Worker } from 'worker_threads';
import { ScanResult } from './scanner';

export function runScanInWorker(
  code: string,
  url: string,
  onPhase: (phase: number, label: string) => void,
  customPatterns?: string[]
): Promise<ScanResult[]> {
  return new Promise((resolve, reject) => {
    const workerPath = path.join(__dirname, 'scanner-worker.js');
    const worker = new Worker(workerPath, { workerData: {} });

    worker.on('message', (msg: { type: string; phase?: number; label?: string; results?: ScanResult[]; error?: string }) => {
      if (msg.type === 'phase' && typeof msg.phase === 'number' && msg.label != null) {
        onPhase(msg.phase, msg.label);
      } else if (msg.type === 'done' && Array.isArray(msg.results)) {
        worker.terminate().catch(() => {});
        resolve(msg.results);
      } else if (msg.type === 'error' && typeof msg.error === 'string') {
        worker.terminate().catch(() => {});
        reject(new Error(msg.error));
      }
    });

    worker.on('error', (err) => {
      worker.terminate().catch(() => {});
      reject(err);
    });

    worker.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`Scanner worker exited with code ${code}`));
      }
    });

    worker.postMessage({ type: 'scan', code, url, customPatterns });
  });
}
