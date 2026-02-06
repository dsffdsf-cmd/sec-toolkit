/**
 * CleanTraffic – one browser, one path, everywhere.
 * Puppeteer bundled Chromium only. No system Chrome. No fallbacks.
 * Run: npm run browser:install (or postinstall does it)
 */

import * as fs from 'fs';
import { getPuppeteerCacheDir } from './paths';

export { getPuppeteerCacheDir };

/** Set before any puppeteer import */
export function configurePuppeteerEnv(): void {
  const cacheDir = getPuppeteerCacheDir();
  process.env.PUPPETEER_CACHE_DIR = cacheDir;
  process.env.PUPPETEER_SKIP_CHROMIUM_DOWNLOAD = '0';
  try {
    fs.mkdirSync(cacheDir, { recursive: true });
  } catch {
    // ignore
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

  const puppeteer = await import('puppeteer');
  const browser = await puppeteer.default.launch({
    headless,
    defaultViewport,
    args: getPlatformLaunchArgs(),
    ignoreHTTPSErrors: true,
    timeout: 60000,
  });
  return browser;
}
