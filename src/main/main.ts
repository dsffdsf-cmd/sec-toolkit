import { configurePuppeteerEnv } from './browser-launcher';
configurePuppeteerEnv();

import { app, BrowserWindow, ipcMain, dialog, Menu, shell } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import { getPreloadPath, getHtmlPath } from './paths';
import { ProxyServer, HttpRequest } from './proxy-server';
import { CertificateManager } from './certificate-manager';
import { SessionManager } from './session-manager';
import { runScanInWorker } from './scan-orchestrator';
import { scanGitHubRepo, GitHubScanOptions, GitHubScanProgress } from './github-scanner';
import { 
  decodeTransaction, 
  analyzeEIP712, 
  inspectContract, 
  readStorageSlot, 
  lookupSignature,
  abiEncode,
  abiDecode,
  keccak256,
  getFunctionSelector,
  checksumAddress,
  hexToUtf8,
  utf8ToHex,
  numberToHex,
  hexToNumber,
  formatUnits,
  parseUnits,
} from './web3-analyzer';
import {
  analyzeWeb3Security,
  analyzeRegexPattern,
  analyzeForRemixIssues,
  analyzeForReDoS,
  analyzeForZipVulns,
} from './web3-security-analyzer';
import { getIntegrationConfig, saveIntegrationConfig, sendWebhookIfConfigured } from './integration-store';
import { mergeIntegrationConfig, type IntegrationConfig } from '../shared/integration-config';
import { findingsToSarif } from './sarif-export';
import { findingsToJunit } from './junit-export';
import { requestsToPostmanCollection } from './postman-export';

let mainWindow: BrowserWindow | null = null;
let proxyServer: ProxyServer | null = null;
const sessionManager = new SessionManager();

// WSL/Linux: disable GPU to avoid crashes; allow root (e.g. Docker/WSL) without sandbox
if (process.platform === 'linux') {
  app.disableHardwareAcceleration();
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    app.commandLine.appendSwitch('no-sandbox');
  }
}

// Prevent unhandled rejections from crashing the app (e.g. Puppeteer launch failures)
process.on('unhandledRejection', (reason, promise) => {
  console.error('[Main] Unhandled rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[Main] Uncaught exception:', err?.message || err);
});

function ensureProxyServer(): ProxyServer {
  if (!proxyServer) {
    console.log('[Main] Creating ProxyServer instance for configuration...');
    proxyServer = new ProxyServer();
    setupRequestUpdateEmitter();
  }
  return proxyServer;
}

// Trailing debounce: batch rapid updates (e.g. many requests in 50ms) into one IPC
const REQUEST_UPDATE_DEBOUNCE_MS = 50;

function setupRequestUpdateEmitter(): void {
  if (!proxyServer) return;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const emit = () => {
    timer = null;
    if (!mainWindow?.webContents?.isDestroyed()) {
      try {
        const requests = proxyServer!.getRequests();
        mainWindow!.webContents.send('proxy:request-update', requests);
      } catch (_) {}
    }
  };
  // Leading edge: first change emits immediately (Chrome Network–style quick load), then debounce bursts
  const onStoreChange = () => {
    if (timer === null) {
      emit();
      timer = setTimeout(() => { timer = null; }, REQUEST_UPDATE_DEBOUNCE_MS);
    } else {
      clearTimeout(timer);
      timer = setTimeout(emit, REQUEST_UPDATE_DEBOUNCE_MS);
    }
  };
  proxyServer.setStoreChangeHandler(onStoreChange);
}

function createWindow(): void {
  // Suppress GLib warnings on Linux/WSL
  if (process.platform === 'linux') {
    process.env.GIO_USE_VFS = 'local';
  }

  const isMac = process.platform === 'darwin';
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1100,
    minHeight: 720,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: getPreloadPath(),
      devTools: false, // Disable DevTools by default
    },
    backgroundColor: '#1e1e1e',
    // Custom chrome (so it doesn't look like default Electron)
    frame: false,
    titleBarStyle: isMac ? 'hidden' : 'default',
    autoHideMenuBar: true,
    show: false, // Don't show until ready
  });

  // Hide the default Electron menu completely.
  Menu.setApplicationMenu(null);
  mainWindow.setMenuBarVisibility(false);

  const htmlPath = getHtmlPath();
  if (fs.existsSync(htmlPath)) {
    mainWindow.loadFile(htmlPath);
  } else {
    const fallback = path.resolve(__dirname, '..', 'renderer', 'index.html');
    if (fs.existsSync(fallback)) {
      mainWindow.loadFile(fallback);
    } else {
      console.error('[Main] HTML not found:', htmlPath);
      mainWindow.loadURL('data:text/html,<h1>Error: HTML file not found</h1><p>Run: npm run build</p>');
    }
  }
  
  // Disable console logging in renderer
  mainWindow.webContents.on('console-message', (event, level, message) => {
    // Suppress console messages in production
    if (app.isPackaged) {
      event.preventDefault();
    }
  });

  // Show window when ready
  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();
  proxyServer = new ProxyServer();
  setupRequestUpdateEmitter();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC Handlers
ipcMain.handle('window:minimize', async () => {
  mainWindow?.minimize();
  return { success: true };
});

ipcMain.handle('window:toggle-maximize', async () => {
  if (!mainWindow) return { success: false };
  if (mainWindow.isMaximized()) mainWindow.unmaximize();
  else mainWindow.maximize();
  return { success: true, maximized: mainWindow.isMaximized() };
});

ipcMain.handle('window:close', async () => {
  mainWindow?.close();
  return { success: true };
});

ipcMain.handle('window:is-maximized', async () => {
  return { maximized: !!mainWindow?.isMaximized() };
});

ipcMain.handle('proxy:start', async () => {
  try {
    const server = ensureProxyServer();
    console.log('[Main] Starting proxy server...');
    const port = await server.start();
    console.log('[Main] Proxy server started successfully on port:', port);
    return { port, success: true };
  } catch (error: any) {
    const errorMsg = error?.message || String(error);
    console.error('[Main] Error starting proxy:', errorMsg);
    console.error('[Main] Error stack:', error?.stack);
    return { port: 0, success: false, error: errorMsg };
  }
});

ipcMain.handle('proxy:stop', async () => {
  if (proxyServer) {
    await proxyServer.stop();
    return { success: true };
  }
  return { success: false };
});

ipcMain.handle('proxy:get-requests', async () => {
  try {
    if (proxyServer) return proxyServer.getRequests();
    return [];
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error('[Main] get-requests error:', msg);
    return [];
  }
});

ipcMain.handle('certificate:generate', async () => {
  const certManager = new CertificateManager();
  return await certManager.generateCertificate();
});

ipcMain.handle('certificate:get-info', async () => {
  const certManager = new CertificateManager();
  return await certManager.getCertificateInfo();
});

ipcMain.handle('certificate:open-location', async (event, certPath: string) => {
  const { shell } = require('electron');
  const path = require('path');
  const dir = path.dirname(certPath);
  await shell.openPath(dir);
});

ipcMain.handle('app:open-external', async (_event, url: string) => {
  if (typeof url !== 'string' || !url.startsWith('https://')) return;
  await shell.openExternal(url);
});

ipcMain.handle('certificate:copy', async (event, certPath: string) => {
  const fs = require('fs');
  const { clipboard } = require('electron');
  
  try {
    // Read certificate content
    const certContent = fs.readFileSync(certPath, 'utf8');
    
    // Copy to clipboard
    clipboard.writeText(certContent);
    
    return { success: true, message: 'Certificate copied to clipboard' };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('request:repeat', async (event, requestData) => {
  if (proxyServer) {
    try {
      const result = await proxyServer.repeatRequest(requestData);
      return result;
    } catch (error: any) {
      console.error('[Main] Error repeating request:', error);
      return { 
        ...requestData,
        status: 0,
        responseBody: `Error: ${error.message}`,
        error: error.message 
      };
    }
  }
  return { error: 'Browser not started' };
});

ipcMain.handle('request:send-to-scanner', async (event, requestData, options?: { customPatterns?: string[] }) => {
  try {
    if (!proxyServer) return { error: 'Proxy server not initialized' };
    const payload = proxyServer.getCodeToScan(requestData);
    if (!payload) return [];
    const onPhase = (phase: number, label: string) => {
      if (!event.sender.isDestroyed()) event.sender.send('scanner:phase', { phase, label });
    };
    const customPatterns = Array.isArray(options?.customPatterns) ? options.customPatterns.filter((p): p is string => typeof p === 'string' && p.trim().length > 0) : undefined;
    const results = await runScanInWorker(payload.code, payload.url, onPhase, customPatterns?.length ? customPatterns : undefined);
    const arr = Array.isArray(results) ? results : [];
    sendWebhookIfConfigured({
      source: 'scanner',
      summary: `Scanner: ${arr.length} finding(s)`,
      totalFindings: arr.length,
      critical: arr.filter((r: { severity?: string }) => r.severity === 'critical').length,
      high: arr.filter((r: { severity?: string }) => r.severity === 'high').length,
      medium: arr.filter((r: { severity?: string }) => r.severity === 'medium').length,
      low: arr.filter((r: { severity?: string }) => r.severity === 'low').length,
      info: arr.filter((r: { severity?: string }) => r.severity === 'info').length,
      findings: arr,
    }).catch(() => {});
    return results;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { error: msg };
  }
});


ipcMain.handle('prettify:code', async (event, code: string, language: string) => {
  try {
    let prettier: typeof import('prettier');
    try {
      prettier = require('prettier');
    } catch {
      return { success: false, error: 'Prettier not available', formatted: code };
    }
    let parser = 'babel';
    
    // Map language to prettier parser
    if (language === 'json') parser = 'json';
    else if (language === 'html') parser = 'html';
    else if (language === 'css') parser = 'css';
    else if (language === 'javascript' || language === 'js') parser = 'babel';
    else if (language === 'typescript' || language === 'ts') parser = 'typescript';
    
    const formatted = await prettier.format(code, {
      parser: parser,
      printWidth: 120,
      tabWidth: 2,
      useTabs: false,
      semi: true,
      singleQuote: true,
      trailingComma: 'es5',
      bracketSpacing: true,
      arrowParens: 'avoid',
    });
    
    return { success: true, formatted };
  } catch (error: any) {
    return { success: false, error: error.message, formatted: code };
  }
});

ipcMain.handle('request:update-notes-tags', async (event, requestId: string, notes: string, tags: string[]) => {
  try {
    if (proxyServer) return await proxyServer.updateRequestNotesTags(requestId, notes, tags);
    return { success: false };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { success: false, error: msg };
  }
});

// Session Management
ipcMain.handle('session:save', async (event, requests: HttpRequest[], name?: string, description?: string) => {
  try {
    const filePath = await sessionManager.saveSession(requests, name, description);
    return { success: true, filePath };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('session:save-dialog', async (event, requests: HttpRequest[]) => {
  try {
    const result = await dialog.showSaveDialog(mainWindow!, {
      title: 'Save Session',
      defaultPath: `session-${Date.now()}.json`,
      filters: [
        { name: 'JSON Files', extensions: ['json'] },
        { name: 'All Files', extensions: ['*'] },
      ],
    });

    if (result.canceled || !result.filePath) {
      return { success: false, canceled: true };
    }

    const sessionData = {
      name: path.basename(result.filePath, '.json'),
      timestamp: Date.now(),
      requests: requests.map(req => ({
        ...req,
        body: typeof req.body === 'string' ? req.body : String(req.body || ''),
        responseBody: typeof req.responseBody === 'string' ? req.responseBody : String(req.responseBody || ''),
      })),
      metadata: {
        description: '',
        tags: [],
      },
    };

    fs.writeFileSync(result.filePath, JSON.stringify(sessionData, null, 2), 'utf8');
    return { success: true, filePath: result.filePath };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('session:load-dialog', async () => {
  try {
    const result = await dialog.showOpenDialog(mainWindow!, {
      title: 'Load Session',
      filters: [
        { name: 'JSON Files', extensions: ['json'] },
        { name: 'All Files', extensions: ['*'] },
      ],
      properties: ['openFile'],
    });

    if (result.canceled || !result.filePaths || result.filePaths.length === 0) {
      return { success: false, canceled: true };
    }

    const sessionData = await sessionManager.loadSession(result.filePaths[0]);
    return { success: true, session: sessionData };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('session:list', async () => {
  try {
    const sessions = await sessionManager.listSessions();
    return { success: true, sessions };
  } catch (error: any) {
    return { success: false, error: error.message, sessions: [] };
  }
});

ipcMain.handle('session:delete', async (event, filePath: string) => {
  try {
    await sessionManager.deleteSession(filePath);
    return { success: true };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('session:export-har', async (event, requests: HttpRequest[]) => {
  try {
    const harContent = await sessionManager.exportToHAR(requests);
    return { success: true, har: harContent };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('session:export-har-dialog', async (_event, requests: HttpRequest[]) => {
  try {
    const harContent = await sessionManager.exportToHAR(requests);
    const result = await dialog.showSaveDialog(mainWindow!, {
      title: 'Export HAR',
      defaultPath: `traffic-${Date.now()}.har`,
      filters: [{ name: 'HAR', extensions: ['har'] }, { name: 'All Files', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { success: false, canceled: true };
    fs.writeFileSync(result.filePath, harContent, 'utf8');
    return { success: true, filePath: result.filePath };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
});

ipcMain.handle('session:export-postman-dialog', async (_event, requests: HttpRequest[]) => {
  try {
    const postmanJson = requestsToPostmanCollection(requests, `CleanTraffic-${Date.now()}`);
    const result = await dialog.showSaveDialog(mainWindow!, {
      title: 'Export Postman Collection',
      defaultPath: `postman-${Date.now()}.json`,
      filters: [{ name: 'Postman Collection', extensions: ['json'] }, { name: 'All Files', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { success: false, canceled: true };
    fs.writeFileSync(result.filePath, postmanJson, 'utf8');
    return { success: true, filePath: result.filePath };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
});

/** 2026: HAR 1.2 import → HttpRequest[]. */
ipcMain.handle('session:import-har', async (_event, harContent: string) => {
  try {
    if (typeof harContent !== 'string') {
      return { success: false, error: 'HAR content must be a string' };
    }
    const requests = await sessionManager.importFromHAR(harContent);
    return { success: true, requests };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg, requests: [] };
  }
});

/** GitHub Repository Scanner - Web3 Security */
ipcMain.handle('github:scan-repo', async (_event, options: GitHubScanOptions) => {
  try {
    const onProgress = (progress: GitHubScanProgress) => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('github:scan-progress', progress);
      }
    };

    const results = await scanGitHubRepo(options, onProgress);
    const arr = Array.isArray(results) ? results : [];
    sendWebhookIfConfigured({
      source: 'github',
      summary: `GitHub scan: ${arr.length} finding(s)`,
      totalFindings: arr.length,
      critical: arr.filter((r: { severity?: string }) => r.severity === 'CRITICAL').length,
      high: arr.filter((r: { severity?: string }) => r.severity === 'HIGH').length,
      medium: arr.filter((r: { severity?: string }) => r.severity === 'MEDIUM').length,
      low: arr.filter((r: { severity?: string }) => r.severity === 'LOW').length,
      info: arr.filter((r: { severity?: string }) => r.severity === 'INFO').length,
      findings: arr,
    }).catch(() => {});
    return { success: true, results };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[GitHub Scanner] Error:', msg);
    return { success: false, error: msg, results: [] };
  }
});

/** Integration config (persisted in main userData) */
ipcMain.handle('settings:get-integration', async () => {
  return getIntegrationConfig();
});

ipcMain.handle('settings:save-integration', async (_event, config: unknown) => {
  const merged = mergeIntegrationConfig(config as Partial<IntegrationConfig> | undefined);
  saveIntegrationConfig(merged);
});

function normalizeFindingForSarif(f: unknown): { ruleId: string; severity: string; message: string; file?: string; line?: number; column?: number; endLine?: number; endColumn?: number; code?: string; cwe?: string; category?: string } {
  const x = f as Record<string, unknown>;
  return {
    ruleId: String(x.ruleId ?? x.rule_id ?? 'unknown'),
    severity: String(x.severity ?? 'warning'),
    message: String(x.message ?? ''),
    file: x.file != null ? String(x.file) : undefined,
    line: typeof x.line === 'number' ? x.line : undefined,
    column: typeof x.column === 'number' ? x.column : undefined,
    endLine: typeof x.endLine === 'number' ? x.endLine : undefined,
    endColumn: typeof x.endColumn === 'number' ? x.endColumn : undefined,
    code: x.code != null ? String(x.code) : undefined,
    cwe: x.cwe != null ? String(x.cwe) : undefined,
    category: x.category != null ? String(x.category) : undefined,
  };
}

/** SARIF export for Scanner / GitHub findings (CI) */
ipcMain.handle('export:findings-to-sarif', async (_event, findings: unknown[], toolName?: string) => {
  const list = Array.isArray(findings) ? findings : [];
  const normalized = list.map(normalizeFindingForSarif);
  return findingsToSarif(normalized, toolName || 'CleanTraffic Scanner');
});

ipcMain.handle('export:findings-to-sarif-file', async (_event, findings: unknown[], toolName?: string) => {
  try {
    const list = Array.isArray(findings) ? findings : [];
    const normalized = list.map(normalizeFindingForSarif);
    const sarif = findingsToSarif(normalized, toolName || 'CleanTraffic Scanner');
    const result = await dialog.showSaveDialog(mainWindow!, {
      title: 'Save SARIF',
      defaultPath: `findings-${Date.now()}.sarif.json`,
      filters: [{ name: 'SARIF', extensions: ['sarif.json', 'json'] }, { name: 'All Files', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { success: false, canceled: true };
    fs.writeFileSync(result.filePath, sarif, 'utf8');
    return { success: true, filePath: result.filePath };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
});

/** JUnit XML export for Scanner / GitHub findings (CI) */
ipcMain.handle('export:findings-to-junit', async (_event, findings: unknown[], toolName?: string) => {
  const list = Array.isArray(findings) ? findings : [];
  const normalized = list.map(normalizeFindingForSarif);
  return findingsToJunit(normalized, toolName || 'CleanTraffic Scanner');
});

ipcMain.handle('export:findings-to-junit-file', async (_event, findings: unknown[], toolName?: string) => {
  try {
    const list = Array.isArray(findings) ? findings : [];
    const normalized = list.map(normalizeFindingForSarif);
    const xml = findingsToJunit(normalized, toolName || 'CleanTraffic Scanner');
    const result = await dialog.showSaveDialog(mainWindow!, {
      title: 'Save JUnit XML',
      defaultPath: `findings-${Date.now()}.xml`,
      filters: [{ name: 'JUnit XML', extensions: ['xml'] }, { name: 'All Files', extensions: ['*'] }],
    });
    if (result.canceled || !result.filePath) return { success: false, canceled: true };
    fs.writeFileSync(result.filePath, xml, 'utf8');
    return { success: true, filePath: result.filePath };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, error: msg };
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// WEB3 SECURITY TOOLS
// ═══════════════════════════════════════════════════════════════════════════

/** Decode transaction calldata */
ipcMain.handle('web3:decode-transaction', async (_event, txData: any) => {
  try {
    const result = decodeTransaction(txData);
    return result;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[Web3 Analyzer] Decode error:', msg);
    throw new Error(msg);
  }
});

/** Analyze EIP-712 signature */
ipcMain.handle('web3:analyze-signature', async (_event, typedData: any) => {
  try {
    const result = analyzeEIP712(typedData);
    return result;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[Web3 Analyzer] Signature analysis error:', msg);
    throw new Error(msg);
  }
});

/** Inspect contract for proxy patterns */
ipcMain.handle('web3:inspect-contract', async (_event, address: string, rpcUrl?: string) => {
  try {
    const result = await inspectContract(address, rpcUrl);
    return result;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[Web3 Analyzer] Contract inspection error:', msg);
    throw new Error(msg);
  }
});

/** Read storage slot */
ipcMain.handle('web3:read-storage', async (_event, address: string, slot: string, rpcUrl?: string) => {
  try {
    const result = await readStorageSlot(address, slot, rpcUrl);
    return result;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[Web3 Analyzer] Storage read error:', msg);
    throw new Error(msg);
  }
});

/** Lookup function signature */
ipcMain.handle('web3:lookup-signature', async (_event, signature: string) => {
  try {
    const result = lookupSignature(signature);
    return result;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[Web3 Analyzer] Signature lookup error:', msg);
    throw new Error(msg);
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// WEB3 ENCODING/DECODING UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/** ABI encode */
ipcMain.handle('web3:abi-encode', async (_event, types: string[], values: any[]) => {
  return abiEncode(types, values);
});

/** ABI decode */
ipcMain.handle('web3:abi-decode', async (_event, types: string[], data: string) => {
  return abiDecode(types, data);
});

/** Keccak256 hash */
ipcMain.handle('web3:keccak256', async (_event, data: string) => {
  return keccak256(data);
});

/** Get function selector */
ipcMain.handle('web3:function-selector', async (_event, signature: string) => {
  return getFunctionSelector(signature);
});

/** Checksum address */
ipcMain.handle('web3:checksum-address', async (_event, address: string) => {
  return checksumAddress(address);
});

/** Hex to UTF-8 */
ipcMain.handle('web3:hex-to-utf8', async (_event, hex: string) => {
  return hexToUtf8(hex);
});

/** UTF-8 to Hex */
ipcMain.handle('web3:utf8-to-hex', async (_event, text: string) => {
  return utf8ToHex(text);
});

/** Number to Hex */
ipcMain.handle('web3:number-to-hex', async (_event, num: string, padBytes?: number) => {
  return numberToHex(num, padBytes);
});

/** Hex to Number */
ipcMain.handle('web3:hex-to-number', async (_event, hex: string) => {
  return hexToNumber(hex);
});

/** Format units (wei to ether) */
ipcMain.handle('web3:format-units', async (_event, value: string, decimals?: number) => {
  return formatUnits(value, decimals);
});

/** Parse units (ether to wei) */
ipcMain.handle('web3:parse-units', async (_event, value: string, decimals?: number) => {
  return parseUnits(value, decimals);
});

// ═══════════════════════════════════════════════════════════════════════════
// WEB3 SECURITY ANALYZER (Remix-style, ReDoS, Zip)
// ═══════════════════════════════════════════════════════════════════════════

/** Full security analysis (Remix + ReDoS + Zip) */
ipcMain.handle('web3:security-analyze', async (_event, code: string) => {
  try {
    return analyzeWeb3Security(code);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[Web3 Security] Analysis error:', msg);
    return { findings: [], stats: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, analyzedAt: Date.now() };
  }
});

/** Analyze single regex pattern for ReDoS */
ipcMain.handle('web3:analyze-regex', async (_event, pattern: string) => {
  try {
    return analyzeRegexPattern(pattern);
  } catch (err: unknown) {
    return { pattern, isVulnerable: false, error: (err as Error).message };
  }
});

/** Remix-style analysis only */
ipcMain.handle('web3:remix-analyze', async (_event, code: string) => {
  try {
    return analyzeForRemixIssues(code);
  } catch (err: unknown) {
    return [];
  }
});

/** ReDoS detection only */
ipcMain.handle('web3:redos-analyze', async (_event, code: string) => {
  try {
    return analyzeForReDoS(code);
  } catch (err: unknown) {
    return [];
  }
});

/** Zip vulnerability detection only */
ipcMain.handle('web3:zip-analyze', async (_event, code: string) => {
  try {
    return analyzeForZipVulns(code);
  } catch (err: unknown) {
    return [];
  }
});

