/**
 * Cross-platform browser launcher for Puppeteer.
 * Ensures Chromium is downloaded and launched correctly on Windows, macOS, and Linux.
 * Uses app userData for cache when running in Electron (packaged or dev).
 */

import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';

/** Get Puppeteer cache directory - persists Chromium across app updates */
export function getPuppeteerCacheDir(): string {
  try {
    const { app } = require('electron');
    if (app?.isReady?.()) {
      return path.join(app.getPath('userData'), 'puppeteer-cache');
    }
  } catch {
    // Not in Electron or app not ready
  }
  return path.join(os.homedir(), '.cleantraffic', 'puppeteer-cache');
}

/** Set Puppeteer environment before any puppeteer import */
export function configurePuppeteerEnv(): void {
  const cacheDir = getPuppeteerCacheDir();
  process.env.PUPPETEER_CACHE_DIR = cacheDir;
  process.env.PUPPETEER_SKIP_CHROMIUM_DOWNLOAD = '0';
  try {
    fs.mkdirSync(cacheDir, { recursive: true });
  } catch {
    // Ignore - puppeteer will create if needed
  }
}

/** Platform-specific Chrome/Chromium launch args */
export function getPlatformLaunchArgs(): string[] {
  const platform = process.platform;
  const base = [
    '--disable-web-security',
    '--disable-features=IsolateOrigins,site-per-process',
    '--ignore-certificate-errors',
    '--ignore-certificate-errors-spki-list',
    '--ignore-ssl-errors',
    '--start-maximized',
    '--window-size=1920,1080',
    '--disable-blink-features=AutomationControlled',
    '--disable-dev-shm-usage',
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-site-isolation-trials',
    '--disable-features=BlockInsecurePrivateNetworkRequests',
    '--disable-background-timer-throttling',
    '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding',
    '--disable-features=TranslateUI',
    '--disable-ipc-flooding-protection',
    '--disable-features=VizDisplayCompositor',
    '--enable-features=NetworkService,NetworkServiceInProcess',
  ];

  if (platform === 'linux') {
    return [
      ...base,
      '--disable-gpu',
      '--no-zygote',
      '--single-process', // Helps on some Linux distros
      '--disable-software-rasterizer',
      '--font-render-hinting=none',
    ];
  }

  if (platform === 'darwin') {
    return [
      ...base,
      '--disable-gpu-sandbox',
      '--use-mock-keychain', // Avoid keychain prompts on macOS
    ];
  }

  // Windows
  return base;
}
