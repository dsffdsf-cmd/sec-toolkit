/**
 * Cross-platform browser launcher for Puppeteer.
 * Ensures Chromium/Chrome is launched correctly on Windows, macOS, and Linux.
 *
 * Compatibility (2024–2026):
 * - Uses Puppeteer-bundled Chromium by default (auto-downloaded on first run)
 * - Falls back to system Chrome if bundled Chromium fails (e.g. macOS firewall prompts)
 * - Platform-specific launch args for macOS (incl. Apple Silicon), Linux, Windows
 *
 * @see docs/BROWSER.md for full documentation
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

/** Known system Chrome/Chromium paths per platform (2024–2026) */
const SYSTEM_BROWSER_PATHS: Record<string, string[]> = {
  darwin: [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  ],
  win32: [
    path.join(process.env['PROGRAMFILES'] || 'C:\\Program Files', 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(process.env['LOCALAPPDATA'] || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
    path.join(process.env['PROGRAMFILES'] || 'C:\\Program Files', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
  ],
  linux: [
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ],
};

/** Find first existing system Chrome/Chromium path */
function findSystemBrowserPath(): string | null {
  const paths = SYSTEM_BROWSER_PATHS[process.platform];
  if (!paths) return null;
  for (const p of paths) {
    try {
      if (fs.existsSync(p)) return p;
    } catch {
      // Skip invalid paths
    }
  }
  return null;
}

/** Platform-specific Chrome/Chromium launch args (2024–2026 compatibility) */
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
    '--disable-features=DialMediaRoute',
    '--disable-client-side-phishing-detection',
    '--no-first-run',
    '--no-default-browser-check',
  ];

  if (platform === 'linux') {
    return [
      ...base,
      '--disable-gpu',
      '--no-zygote',
      '--disable-software-rasterizer',
      '--font-render-hinting=none',
    ];
  }

  if (platform === 'darwin') {
    return [
      ...base,
      '--disable-gpu-sandbox',
      '--use-mock-keychain',
      '--disable-features=MediaRouter',
      '--disable-hang-monitor',
      '--disable-prompt-on-repost',
      '--metrics-recording-only',
      '--password-store=basic',
    ];
  }

  return base;
}

export interface LaunchBrowserOptions {
  headless?: boolean;
  defaultViewport?: { width: number; height: number };
}

/**
 * Launch browser with fallback: tries Puppeteer Chromium first, then system Chrome.
 * Resolves compatibility issues on macOS (firewall prompts), Linux (sandbox), Windows.
 */
export async function launchBrowser(options: LaunchBrowserOptions = {}): Promise<import('puppeteer').Browser> {
  const { headless = false, defaultViewport = { width: 1920, height: 1080 } } = options;
  const args = getPlatformLaunchArgs();

  // Lazy import to ensure PUPPETEER_CACHE_DIR is set before first use
  const puppeteer = await import('puppeteer');

  const launchOpts = {
    headless,
    defaultViewport,
    args,
    ignoreHTTPSErrors: true,
    timeout: 60000,
  };

  // Strategy 1: Puppeteer-bundled Chromium (default)
  try {
    const browser = await puppeteer.default.launch(launchOpts);
    console.log('[Browser] Launched Puppeteer Chromium');
    return browser;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn('[Browser] Puppeteer Chromium failed:', msg);
  }

  // Strategy 2: System Chrome/Chromium (avoids macOS firewall prompts, etc.)
  const systemPath = findSystemBrowserPath();
  if (systemPath) {
    try {
      const browser = await puppeteer.default.launch({
        ...launchOpts,
        executablePath: systemPath,
      });
      console.log('[Browser] Launched system browser:', systemPath);
      return browser;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn('[Browser] System browser failed:', msg);
    }
  }

  // Strategy 3: Puppeteer channel (uses system Chrome if installed in standard location)
  if (process.platform === 'darwin' || process.platform === 'win32') {
    try {
      const browser = await puppeteer.default.launch({
        ...launchOpts,
        channel: 'chrome' as const,
      });
      console.log('[Browser] Launched via channel: chrome');
      return browser;
    } catch {
      // channel may not be available
    }
  }

  throw new Error(
    'Failed to launch browser. Tried: (1) Puppeteer Chromium, (2) System Chrome/Chromium, (3) Chrome channel. ' +
    'On macOS: install Google Chrome or allow Chromium in System Settings → Privacy & Security → Firewall. ' +
    'See docs/BROWSER.md for details.'
  );
}
