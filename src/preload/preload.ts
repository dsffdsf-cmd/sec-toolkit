import { contextBridge, ipcRenderer } from 'electron';
import { HttpRequest } from '../main/proxy-server';

contextBridge.exposeInMainWorld('electronAPI', {
  // Window chrome controls (frameless window)
  minimizeWindow: () => ipcRenderer.invoke('window:minimize'),
  toggleMaximizeWindow: () => ipcRenderer.invoke('window:toggle-maximize'),
  closeWindow: () => ipcRenderer.invoke('window:close'),
  isWindowMaximized: () => ipcRenderer.invoke('window:is-maximized'),

  // Proxy controls
  startProxy: () => ipcRenderer.invoke('proxy:start'),
  stopProxy: () => ipcRenderer.invoke('proxy:stop'),
  getRequests: () => ipcRenderer.invoke('proxy:get-requests'),

  openExternalUrl: (url: string) => ipcRenderer.invoke('app:open-external', url),

  // Certificate management
  generateCertificate: () => ipcRenderer.invoke('certificate:generate'),
  getCertificateInfo: () => ipcRenderer.invoke('certificate:get-info'),
  openCertificateLocation: (certPath: string) => ipcRenderer.invoke('certificate:open-location', certPath),
  copyCertificate: (certPath: string) => ipcRenderer.invoke('certificate:copy', certPath),

  // Request operations
  repeatRequest: (requestData: HttpRequest) => ipcRenderer.invoke('request:repeat', requestData),
  sendToScanner: (requestData: HttpRequest, options?: { customPatterns?: string[] }) =>
    ipcRenderer.invoke('request:send-to-scanner', requestData, options),
  prettifyCode: (code: string, language: string) => ipcRenderer.invoke('prettify:code', code, language),
  updateRequestNotesTags: (requestId: string, notes: string, tags: string[]) => ipcRenderer.invoke('request:update-notes-tags', requestId, notes, tags),

  // Session management
  saveSession: (requests: HttpRequest[], name?: string, description?: string) => ipcRenderer.invoke('session:save', requests, name, description),
  saveSessionDialog: (requests: HttpRequest[]) => ipcRenderer.invoke('session:save-dialog', requests),
  loadSessionDialog: () => ipcRenderer.invoke('session:load-dialog'),
  listSessions: () => ipcRenderer.invoke('session:list'),
  deleteSession: (filePath: string) => ipcRenderer.invoke('session:delete', filePath),
  exportToHAR: (requests: HttpRequest[]) => ipcRenderer.invoke('session:export-har', requests),
  exportToHARDialog: (requests: HttpRequest[]) => ipcRenderer.invoke('session:export-har-dialog', requests),
  importFromHAR: (harContent: string) => ipcRenderer.invoke('session:import-har', harContent),

  onScannerPhase: (callback: (data: { phase: number; label: string }) => void) => {
    const handler = (_: unknown, data: { phase: number; label: string }) => callback(data);
    ipcRenderer.on('scanner:phase', handler);
    return () => {
      ipcRenderer.removeListener('scanner:phase', handler);
    };
  },

  onRequestUpdate: (callback: (requests: HttpRequest[]) => void) => {
    const handler = (_: unknown, requests: HttpRequest[]) => callback(requests);
    ipcRenderer.on('proxy:request-update', handler);
    return () => ipcRenderer.removeListener('proxy:request-update', handler);
  },

  getIntegrationConfig: () => ipcRenderer.invoke('settings:get-integration'),
  saveIntegrationConfig: (config: import('../shared/integration-config').IntegrationConfig) =>
    ipcRenderer.invoke('settings:save-integration', config),

  exportFindingsToSarif: (findings: unknown[], toolName?: string) =>
    ipcRenderer.invoke('export:findings-to-sarif', findings, toolName),
  exportFindingsToSarifFile: (findings: unknown[], toolName?: string) =>
    ipcRenderer.invoke('export:findings-to-sarif-file', findings, toolName),
  exportFindingsToJunit: (findings: unknown[], toolName?: string) =>
    ipcRenderer.invoke('export:findings-to-junit', findings, toolName),
  exportFindingsToJunitFile: (findings: unknown[], toolName?: string) =>
    ipcRenderer.invoke('export:findings-to-junit-file', findings, toolName),
  exportToPostmanDialog: (requests: HttpRequest[]) =>
    ipcRenderer.invoke('session:export-postman-dialog', requests),

  // GitHub Repository Scanner (options match main GitHubScanOptions)
  scanGitHubRepo: async (options: {
    repoUrl: string;
    branch?: string;
    githubToken?: string;
    useDefaultRules?: boolean;
    customRules?: string;
    customRulesPath?: string;
    scanDepth?: 'shallow' | 'full';
    includeTests?: boolean;
    maxFileSize?: number;
    timeout?: number;
  }) => {
    const result = await ipcRenderer.invoke('github:scan-repo', options);
    if (result.success) {
      return result.results;
    }
    throw new Error(result.error || 'GitHub scan failed');
  },
  
  onGitHubScanProgress: (callback: (progress: { stage: string; message: string; progress?: number }) => void) => {
    const handler = (_: unknown, progress: { stage: string; message: string; progress?: number }) => callback(progress);
    ipcRenderer.on('github:scan-progress', handler);
    return () => ipcRenderer.removeListener('github:scan-progress', handler);
  },

  // Web3 Security Tools
  web3DecodeTransaction: (txData: any) => ipcRenderer.invoke('web3:decode-transaction', txData),
  web3AnalyzeSignature: (typedData: any) => ipcRenderer.invoke('web3:analyze-signature', typedData),
  web3InspectContract: (address: string, rpcUrl?: string) => ipcRenderer.invoke('web3:inspect-contract', address, rpcUrl),
  web3ReadStorageSlot: (address: string, slot: string, rpcUrl?: string) => ipcRenderer.invoke('web3:read-storage', address, slot, rpcUrl),
  web3LookupSignature: (signature: string) => ipcRenderer.invoke('web3:lookup-signature', signature),

  // Web3 Encoding/Decoding Utilities
  web3AbiEncode: (types: string[], values: any[]) => ipcRenderer.invoke('web3:abi-encode', types, values),
  web3AbiDecode: (types: string[], data: string) => ipcRenderer.invoke('web3:abi-decode', types, data),
  web3Keccak256: (data: string) => ipcRenderer.invoke('web3:keccak256', data),
  web3FunctionSelector: (signature: string) => ipcRenderer.invoke('web3:function-selector', signature),
  web3ChecksumAddress: (address: string) => ipcRenderer.invoke('web3:checksum-address', address),
  web3HexToUtf8: (hex: string) => ipcRenderer.invoke('web3:hex-to-utf8', hex),
  web3Utf8ToHex: (text: string) => ipcRenderer.invoke('web3:utf8-to-hex', text),
  web3NumberToHex: (num: string, padBytes?: number) => ipcRenderer.invoke('web3:number-to-hex', num, padBytes),
  web3HexToNumber: (hex: string) => ipcRenderer.invoke('web3:hex-to-number', hex),
  web3FormatUnits: (value: string, decimals?: number) => ipcRenderer.invoke('web3:format-units', value, decimals),
  web3ParseUnits: (value: string, decimals?: number) => ipcRenderer.invoke('web3:parse-units', value, decimals),

  // Web3 Security Analyzer (Remix, ReDoS, Zip)
  web3SecurityAnalyze: (code: string) => ipcRenderer.invoke('web3:security-analyze', code),
  web3AnalyzeRegex: (pattern: string) => ipcRenderer.invoke('web3:analyze-regex', pattern),
  web3RemixAnalyze: (code: string) => ipcRenderer.invoke('web3:remix-analyze', code),
  web3RedosAnalyze: (code: string) => ipcRenderer.invoke('web3:redos-analyze', code),
  web3ZipAnalyze: (code: string) => ipcRenderer.invoke('web3:zip-analyze', code),
});
