/**
 * CleanTraffic – single source of truth for all paths.
 * One root, same structure on Windows, macOS, Linux.
 * Dev, prod, packaged – same layout everywhere.
 */

import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

const MAIN_DIR = path.resolve(__dirname);
const APP_NAME = 'CleanTraffic';

/** App data root – same as Electron userData. One root for everything. */
function getAppDataRoot(): string {
  try {
    const { app } = require('electron');
    if (app?.isReady?.()) {
      return app.getPath('userData');
    }
  } catch {
    // Not Electron (e.g. tests, scripts)
  }
  const home = os.homedir();
  if (!home) return path.join(process.cwd(), '.cleantraffic');
  if (process.platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', APP_NAME);
  }
  if (process.platform === 'win32') {
    const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
    return path.join(appData, APP_NAME);
  }
  const config = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
  return path.join(config, APP_NAME);
}

/** Chromium binary cache – Puppeteer downloads here. Same path for install and runtime. */
export function getPuppeteerCacheDir(): string {
  return path.join(getAppDataRoot(), 'browser');
}

/** Chromium userDataDir – short path to avoid macOS socket hangup. */
export function getChromiumUserDataDir(): string {
  return path.join(getAppDataRoot(), 'browser-profile');
}

/** CA certs */
export function getCertsDir(): string {
  return path.join(getAppDataRoot(), 'certs');
}

/** Sessions */
export function getSessionsDir(): string {
  return path.join(getAppDataRoot(), 'sessions');
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
  return getAppDataRoot();
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
