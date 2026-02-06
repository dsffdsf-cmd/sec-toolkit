/**
 * Cross-platform path resolution for Electron (dev + packaged).
 * Ensures rules, workers, and resources resolve correctly on Windows, macOS, and Linux.
 *
 * @see docs/BROWSER.md for platform notes
 * @see docs/COMPATIBILITY.md for full compatibility guide
 */

import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

/** Base directory of the current module (dist/main when compiled) */
const MAIN_DIR = path.resolve(__dirname);

/**
 * Get user data / app data directory. Prefers Electron app.getPath when available.
 * Fallback for non-Electron or when app not ready.
 */
export function getUserDataPath(): string {
  try {
    const { app } = require('electron');
    if (app?.isReady?.()) {
      return app.getPath('userData');
    }
  } catch {
    // Not in Electron
  }
  const home = os.homedir();
  if (!home) {
    return path.join(process.cwd(), '.cleantraffic-data');
  }
  if (process.platform === 'win32') {
    const base = process.env.APPDATA || process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Roaming');
    return path.join(base, 'CleanTraffic');
  }
  if (process.platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', 'CleanTraffic');
  }
  const config = process.env.XDG_CONFIG_HOME || path.join(home, '.config');
  return path.join(config, 'CleanTraffic');
}

/**
 * Get the rules directory. Tries multiple locations for dev vs packaged.
 * - Packaged: process.resourcesPath/rules (extraResources) or app.asar/rules
 * - Dev: __dirname/../../rules
 */
export function getRulesDir(): string {
  // Electron packaged: extraResources put rules in Resources/rules
  const resourcesPath = (process as NodeJS.Process & { resourcesPath?: string }).resourcesPath;
  if (resourcesPath && typeof resourcesPath === 'string') {
    const rulesInResources = path.join(resourcesPath, 'rules');
    if (fs.existsSync(rulesInResources)) {
      return path.normalize(rulesInResources);
    }
  }

  // Fallback: relative to main (works in dev and when rules are in asar)
  const rulesRelative = path.join(MAIN_DIR, '..', '..', 'rules');
  const normalized = path.normalize(rulesRelative);
  if (fs.existsSync(normalized)) {
    return normalized;
  }

  // Last resort: use relative path (may fail at runtime if rules missing)
  return normalized;
}

/**
 * Get the path to scanner-worker.js. Works in dev and packaged.
 */
export function getScannerWorkerPath(): string {
  const workerPath = path.join(MAIN_DIR, 'scanner-worker.js');
  return path.normalize(workerPath);
}

/**
 * Get the path to preload script. Works in dev and packaged.
 */
export function getPreloadPath(): string {
  return path.normalize(path.join(MAIN_DIR, '..', 'preload', 'preload.js'));
}

/**
 * Get the path to renderer index.html. Works in dev and packaged.
 */
export function getHtmlPath(): string {
  return path.normalize(path.join(MAIN_DIR, '..', 'renderer', 'index.html'));
}

/**
 * Resolve a path for use in shell commands (exec).
 * Returns normalized absolute path.
 */
export function pathForExec(filePath: string): string {
  return path.normalize(path.resolve(filePath));
}

/**
 * Escape a path for safe use in shell commands. Handles spaces and special chars.
 * - Windows: double-quote and escape backslashes/double-quotes
 * - Unix: single-quote and escape embedded single quotes
 */
export function shellEscapePath(filePath: string): string {
  const p = pathForExec(filePath);
  if (process.platform === 'win32') {
    return '"' + p.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }
  return "'" + p.replace(/'/g, "'\\''") + "'";
}
