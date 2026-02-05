import type { HttpRequest } from '../main/proxy-server';

declare global {
  interface Window {
    electronAPI: {
      // Window chrome controls (frameless window)
      minimizeWindow?: () => Promise<{ success?: boolean }>;
      toggleMaximizeWindow?: () => Promise<{ success: boolean; maximized?: boolean }>;
      closeWindow?: () => Promise<{ success?: boolean }>;
      isWindowMaximized?: () => Promise<{ maximized: boolean }>;

      // Proxy controls
      startProxy: () => Promise<{ port: number; success: boolean; error?: string }>;
      stopProxy: () => Promise<{ success: boolean; error?: string }>;
      getRequests: () => Promise<HttpRequest[]>;

      openExternalUrl?: (url: string) => Promise<void>;

      // Request operations
      repeatRequest: (request: HttpRequest) => Promise<HttpRequest>;
      sendToScanner: (request: HttpRequest, options?: { customPatterns?: string[] }) => Promise<any>;
      prettifyCode?: (code: string, language: string) => Promise<{ success: boolean; formatted?: string; error?: string }>;
      updateRequestNotesTags?: (
        requestId: string,
        notes: string,
        tags: string[]
      ) => Promise<{ success: boolean; error?: string }>;

      // Certificate management
      generateCertificate?: () => Promise<any>;
      getCertificateInfo: () => Promise<any>;
      openCertificateLocation?: (certPath: string) => Promise<void>;
      copyCertificate?: (certPath: string) => Promise<{ success: boolean; error?: string }>;

      // Session management
      saveSession?: (
        requests: HttpRequest[],
        name?: string,
        description?: string
      ) => Promise<{ success: boolean; filePath?: string; error?: string }>;
      saveSessionDialog?: (
        requests: HttpRequest[]
      ) => Promise<{ success: boolean; filePath?: string; canceled?: boolean; error?: string }>;
      loadSessionDialog?: () => Promise<{ success: boolean; session?: any; canceled?: boolean; error?: string }>;
      listSessions?: () => Promise<{ success: boolean; sessions?: any[]; error?: string }>;
      deleteSession?: (filePath: string) => Promise<{ success: boolean; error?: string }>;
      exportToHAR?: (requests: HttpRequest[]) => Promise<{ success: boolean; har?: string; error?: string }>;
      exportToHARDialog?: (requests: HttpRequest[]) => Promise<{ success: boolean; filePath?: string; canceled?: boolean; error?: string }>;
      importFromHAR?: (harContent: string) => Promise<{ success: boolean; requests?: HttpRequest[]; error?: string }>;


      // Live updates
      onRequestUpdate: (callback: (requests: HttpRequest[]) => void) => () => void;
      onScannerPhase: (callback: (data: { phase: number; label: string }) => void) => () => void;

      getIntegrationConfig: () => Promise<import('../shared/integration-config').IntegrationConfig>;
      saveIntegrationConfig: (config: import('../shared/integration-config').IntegrationConfig) => Promise<void>;

      exportFindingsToSarif?: (findings: unknown[], toolName?: string) => Promise<string>;
      exportFindingsToSarifFile?: (findings: unknown[], toolName?: string) => Promise<{ success: boolean; filePath?: string; canceled?: boolean; error?: string }>;
      exportFindingsToJunit?: (findings: unknown[], toolName?: string) => Promise<string>;
      exportFindingsToJunitFile?: (findings: unknown[], toolName?: string) => Promise<{ success: boolean; filePath?: string; canceled?: boolean; error?: string }>;
      exportToPostmanDialog?: (requests: HttpRequest[]) => Promise<{ success: boolean; filePath?: string; canceled?: boolean; error?: string }>;

      // GitHub Scanner
      scanGitHubRepo: (options: {
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
      }) => Promise<any[]>;
      onGitHubScanProgress: (callback: (progress: { stage: string; message: string; progress?: number }) => void) => () => void;

      // Web3 Security Tools
      web3DecodeTransaction: (txData: any) => Promise<{
        to: string;
        from?: string;
        value: string;
        valueEth: string;
        data: string;
        functionName?: string;
        functionSignature?: string;
        decodedArgs?: { name: string; type: string; value: string }[];
        isContractCreation: boolean;
        warnings: string[];
      }>;
      web3AnalyzeSignature: (typedData: any) => Promise<{
        domain: { name?: string; version?: string; chainId?: number; verifyingContract?: string };
        primaryType: string;
        types: Record<string, { name: string; type: string }[]>;
        message: Record<string, any>;
        warnings: string[];
        riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
      }>;
      web3InspectContract: (address: string, rpcUrl?: string) => Promise<{
        address: string;
        isContract: boolean;
        isProxy: boolean;
        proxyType?: string;
        implementation?: string;
        admin?: string;
        beacon?: string;
        bytecodeHash?: string;
      }>;
      web3ReadStorageSlot: (address: string, slot: string, rpcUrl?: string) => Promise<{
        slot: string;
        value: string;
        decoded?: string;
        label?: string;
      }>;
      web3LookupSignature: (signature: string) => Promise<{
        signature: string;
        name: string;
        inputs: { name: string; type: string }[];
      } | null>;

      // Web3 Encoding/Decoding Utilities
      web3AbiEncode: (types: string[], values: any[]) => Promise<{ success: boolean; result?: string; error?: string }>;
      web3AbiDecode: (types: string[], data: string) => Promise<{ success: boolean; result?: any; error?: string }>;
      web3Keccak256: (data: string) => Promise<{ success: boolean; result?: string; error?: string }>;
      web3FunctionSelector: (signature: string) => Promise<{ success: boolean; result?: string; error?: string }>;
      web3ChecksumAddress: (address: string) => Promise<{ valid: boolean; checksummed?: string; error?: string }>;
      web3HexToUtf8: (hex: string) => Promise<{ success: boolean; result?: string; error?: string }>;
      web3Utf8ToHex: (text: string) => Promise<{ success: boolean; result?: string; error?: string }>;
      web3NumberToHex: (num: string, padBytes?: number) => Promise<{ success: boolean; result?: string; error?: string }>;
      web3HexToNumber: (hex: string) => Promise<{ success: boolean; result?: string; error?: string }>;
      web3FormatUnits: (value: string, decimals?: number) => Promise<{ success: boolean; result?: string; error?: string }>;
      web3ParseUnits: (value: string, decimals?: number) => Promise<{ success: boolean; result?: string; error?: string }>;

      // Web3 Security Analyzer (Remix, ReDoS, Zip)
      web3SecurityAnalyze: (code: string) => Promise<{
        findings: Array<{
          id: string;
          category: 'remix' | 'redos' | 'zip' | 'web3' | 'crypto';
          severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
          title: string;
          description: string;
          line?: number;
          column?: number;
          code?: string;
          recommendation: string;
          cwe?: string;
        }>;
        stats: { critical: number; high: number; medium: number; low: number; info: number };
        analyzedAt: number;
      }>;
      web3AnalyzeRegex: (pattern: string) => Promise<{
        pattern: string;
        isVulnerable: boolean;
        vulnerabilityType?: 'exponential' | 'polynomial' | 'catastrophic';
        explanation?: string;
        safeAlternative?: string;
        estimatedComplexity?: string;
      }>;
      web3RemixAnalyze: (code: string) => Promise<Array<any>>;
      web3RedosAnalyze: (code: string) => Promise<Array<any>>;
      web3ZipAnalyze: (code: string) => Promise<Array<any>>;
    };
  }
}

export {};

