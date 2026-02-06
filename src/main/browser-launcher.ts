/**
 * CleanTraffic – one browser, one path, everywhere.
 * Puppeteer bundled Chromium only. No system Chrome. No fallbacks.
 * Run: npm run browser:install (or postinstall does it)
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { getPuppeteerCacheDir, getChromiumUserDataDir } from './paths';

export { getPuppeteerCacheDir };

/** Set before any puppeteer import */
export function configurePuppeteerEnv(): void {
  const cacheDir = getPuppeteerCacheDir();
  process.env.PUPPETEER_CACHE_DIR = cacheDir;
  process.env.PUPPETEER_SKIP_CHROMIUM_DOWNLOAD = '0';
  try {
    fs.mkdirSync(cacheDir, { recursive: true });
    migrateLegacyBrowserCache(cacheDir);
  } catch {
    // ignore
  }
}

/** One-time migration from old ~/.cleantraffic/browser to app data root */
function migrateLegacyBrowserCache(newCacheDir: string): void {
  const home = os.homedir();
  if (!home) return;
  const legacyDir = path.join(home, '.cleantraffic', 'browser');
  if (legacyDir === newCacheDir) return;
  try {
    const hasContent = fs.existsSync(legacyDir) && fs.readdirSync(legacyDir).length > 0;
    const newEmpty = !fs.existsSync(newCacheDir) || fs.readdirSync(newCacheDir).length === 0;
    if (hasContent && newEmpty) {
      fs.cpSync(legacyDir, newCacheDir, { recursive: true });
      console.log('[Browser] Migrated Chromium cache from legacy path');
    }
  } catch {
    // ignore – migration is best-effort
  }
}

/** Launch args – same on all platforms */
const LAUNCH_ARGS = [
  '--disable-web-security',
  '--disable-features=IsolateOrigins,site-per-process',
  '--ignore-certificate-errors',
  '--ignore-certificate-errors-spki-list',
  '--ignore-ssl-errors',
  '--no-sandbox',
  '--disable-setuid-sandbox',
  '--disable-dev-shm-usage',
  '--disable-blink-features=AutomationControlled',
  '--disable-site-isolation-trials',
  '--disable-features=BlockInsecurePrivateNetworkRequests',
  '--no-first-run',
  '--no-default-browser-check',
  '--window-size=1920,1080',
];

export function getPlatformLaunchArgs(): string[] {
  if (process.platform === 'linux') {
    return [...LAUNCH_ARGS, '--disable-gpu', '--no-zygote'];
  }
  if (process.platform === 'darwin') {
    return [...LAUNCH_ARGS, '--use-mock-keychain'];
  }
  return LAUNCH_ARGS;
}

export interface LaunchBrowserOptions {
  headless?: boolean;
  defaultViewport?: { width: number; height: number };
}

/** Launch Puppeteer Chromium. One browser. Same everywhere. */
export async function launchBrowser(options: LaunchBrowserOptions = {}): Promise<import('puppeteer').Browser> {
  const { headless = false, defaultViewport = { width: 1920, height: 1080 } } = options;

  process.env.PUPPETEER_CACHE_DIR = getPuppeteerCacheDir();

  const userDataDir = getChromiumUserDataDir();
  try {
    fs.mkdirSync(userDataDir, { recursive: true });
  } catch {
    // ignore
  }

  const puppeteer = await import('puppeteer');
  const browser = await puppeteer.default.launch({
    headless,
    defaultViewport,
    args: getPlatformLaunchArgs(),
    ignoreHTTPSErrors: true,
    timeout: 60000,
    userDataDir, // Short path – avoids macOS socket path too long / hangup
  });
  return browser;
}
