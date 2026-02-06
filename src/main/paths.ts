/**
 * CleanTraffic – single source of truth for all paths.
 * One base dir, same structure on Windows, macOS, Linux.
 * No platform hacks. No fallbacks. Clean.
 */

import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

const MAIN_DIR = path.resolve(__dirname);

/** Base dir for app data. Electron userData when ready, else ~/.cleantraffic */
function getBaseDir(): string {
  try {
    const { app } = require('electron');
    if (app?.isReady?.()) {
      return app.getPath('userData');
    }
  } catch {
    // Not Electron
  }
  const home = os.homedir();
  return home ? path.join(home, '.cleantraffic') : path.join(process.cwd(), '.cleantraffic');
}

/** Puppeteer Chromium cache. Fixed: ~/.cleantraffic/browser. Same path for install and runtime. */
export function getPuppeteerCacheDir(): string {
  const home = os.homedir();
  const base = home ? path.join(home, '.cleantraffic') : path.join(process.cwd(), '.cleantraffic');
  return path.join(base, 'browser');
}

/** Certs */
export function getCertsDir(): string {
  return path.join(getBaseDir(), 'certs');
}

/** Sessions */
export function getSessionsDir(): string {
  return path.join(getBaseDir(), 'sessions');
}

/** Rules – from app bundle or project root */
export function getRulesDir(): string {
  const resourcesPath = (process as NodeJS.Process & { resourcesPath?: string }).resourcesPath;
  if (resourcesPath) {
    const p = path.join(resourcesPath, 'rules');
    if (fs.existsSync(p)) return path.normalize(p);
  }
  const p = path.join(MAIN_DIR, '..', '..', 'rules');
  return path.normalize(p);
}

/** Scanner worker */
export function getScannerWorkerPath(): string {
  return path.normalize(path.join(MAIN_DIR, 'scanner-worker.js'));
}

/** Preload */
export function getPreloadPath(): string {
  return path.normalize(path.join(MAIN_DIR, '..', 'preload', 'preload.js'));
}

/** Renderer HTML */
export function getHtmlPath(): string {
  return path.normalize(path.join(MAIN_DIR, '..', 'renderer', 'index.html'));
}

/** User data (for integration-store compatibility) */
export function getUserDataPath(): string {
  return getBaseDir();
}

/** Resolve path for exec */
export function pathForExec(filePath: string): string {
  return path.normalize(path.resolve(filePath));
}

/** Shell-escape path for exec */
export function shellEscapePath(filePath: string): string {
  const p = pathForExec(filePath);
  if (process.platform === 'win32') {
    return '"' + p.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }
  return "'" + p.replace(/'/g, "'\\''") + "'";
}
