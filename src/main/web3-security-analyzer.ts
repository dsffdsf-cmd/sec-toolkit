/**
 * CleanTraffic - Web3 Security Analyzer
 * Remix-style analysis, ReDoS detection, Zip vulnerability detection
 */

// ═══════════════════════════════════════════════════════════════════════════
// TYPES & INTERFACES
// ═══════════════════════════════════════════════════════════════════════════

export interface SecurityFinding {
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
  references?: string[];
}

export interface AnalysisResult {
  findings: SecurityFinding[];
  stats: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  analyzedAt: number;
}

export interface RegexAnalysis {
  pattern: string;
  isVulnerable: boolean;
  vulnerabilityType?: 'exponential' | 'polynomial' | 'catastrophic';
  explanation?: string;
  safeAlternative?: string;
  estimatedComplexity?: string;
}

export interface ZipAnalysis {
  pattern: string;
  isVulnerable: boolean;
  vulnerabilityType?: 'path-traversal' | 'zip-bomb' | 'symlink' | 'race-condition';
  description: string;
  recommendation: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// REMIX-STYLE ANALYSIS PATTERNS (Adapted for JS/TS Web3 code)
// ═══════════════════════════════════════════════════════════════════════════

const REMIX_PATTERNS = {
  // Reentrancy-like patterns in frontend
  reentrancyCallback: {
    pattern: /\.on\s*\(\s*['"](?:receipt|confirmation|transactionHash)['"]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{[^}]*(?:send|transfer|call)\s*\(/gi,
    title: 'Potential Reentrancy in Callback',
    description: 'Transaction callback contains another transaction call, which could lead to reentrancy-like issues',
    severity: 'HIGH' as const,
    recommendation: 'Use a mutex/lock pattern or ensure state is updated before making nested calls',
    cwe: 'CWE-662',
  },

  // Unchecked transaction results
  uncheckedSend: {
    pattern: /(?:\.send|\.transfer|\.call)\s*\([^)]*\)\s*(?:;|\n|$)/gi,
    title: 'Unchecked Transaction Result',
    description: 'Transaction call result is not checked for success/failure',
    severity: 'MEDIUM' as const,
    recommendation: 'Always check the return value or use try/catch for transaction calls',
    cwe: 'CWE-252',
  },

  // Hardcoded gas limits
  hardcodedGas: {
    pattern: /gas\s*:\s*(?:['"]?\d+['"]?|0x[a-fA-F0-9]+)/gi,
    title: 'Hardcoded Gas Limit',
    description: 'Gas limit is hardcoded which may cause transactions to fail after network upgrades',
    severity: 'LOW' as const,
    recommendation: 'Use gas estimation or allow users to configure gas limits',
    cwe: 'CWE-1188',
  },

  // Tx origin usage
  txOrigin: {
    pattern: /tx\.origin|msg\.sender\s*==\s*tx\.origin/gi,
    title: 'tx.origin Usage',
    description: 'Using tx.origin for authorization can be exploited through phishing attacks',
    severity: 'HIGH' as const,
    recommendation: 'Use msg.sender instead of tx.origin for authorization',
    cwe: 'CWE-284',
  },

  // Block timestamp dependency
  blockTimestamp: {
    pattern: /block\.timestamp|now\s*[<>=]/gi,
    title: 'Block Timestamp Dependency',
    description: 'Relying on block.timestamp can be manipulated by miners within ~15 seconds',
    severity: 'LOW' as const,
    recommendation: 'Avoid using block.timestamp for critical logic, use block numbers instead',
    cwe: 'CWE-829',
  },

  // Floating pragma (in comments/strings referencing Solidity)
  floatingPragma: {
    pattern: /pragma\s+solidity\s*\^/gi,
    title: 'Floating Pragma',
    description: 'Using floating pragma can lead to unexpected behavior with different compiler versions',
    severity: 'INFO' as const,
    recommendation: 'Lock the pragma to a specific compiler version',
    cwe: 'CWE-1104',
  },

  // Unchecked math (pre-0.8.0 patterns)
  uncheckedMath: {
    pattern: /unchecked\s*\{[^}]*[+\-*/][^}]*\}/gi,
    title: 'Unchecked Arithmetic',
    description: 'Unchecked arithmetic can lead to overflow/underflow vulnerabilities',
    severity: 'MEDIUM' as const,
    recommendation: 'Ensure unchecked blocks are intentional and values are validated',
    cwe: 'CWE-190',
  },

  // Dangerous delegatecall
  delegatecall: {
    pattern: /\.delegatecall\s*\(/gi,
    title: 'Delegatecall Usage',
    description: 'delegatecall preserves context and can be dangerous if target is user-controlled',
    severity: 'CRITICAL' as const,
    recommendation: 'Ensure delegatecall target is trusted and not user-controllable',
    cwe: 'CWE-829',
  },

  // Selfdestruct
  selfdestruct: {
    pattern: /selfdestruct\s*\(|suicide\s*\(/gi,
    title: 'Selfdestruct Usage',
    description: 'selfdestruct can permanently destroy contracts and send funds unexpectedly',
    severity: 'HIGH' as const,
    recommendation: 'Avoid selfdestruct or protect it with strong access controls',
    cwe: 'CWE-749',
  },

  // Low-level call
  lowLevelCall: {
    pattern: /\.call\s*\{[^}]*\}\s*\(|\.call\s*\(\s*abi\.encode/gi,
    title: 'Low-level Call',
    description: 'Low-level calls bypass type checking and can fail silently',
    severity: 'MEDIUM' as const,
    recommendation: 'Prefer high-level contract calls when possible, always check return values',
    cwe: 'CWE-252',
  },

  // Assembly usage
  assemblyUsage: {
    pattern: /assembly\s*\{/gi,
    title: 'Inline Assembly',
    description: 'Assembly bypasses safety checks and is error-prone',
    severity: 'INFO' as const,
    recommendation: 'Use assembly only when necessary and audit thoroughly',
    cwe: 'CWE-676',
  },

  // Private key in code
  privateKeyExposure: {
    pattern: /(?:private[_-]?key|privateKey|PRIVATE_KEY)\s*[=:]\s*['"`](?:0x)?[a-fA-F0-9]{64}['"`]/gi,
    title: 'Private Key Exposure',
    description: 'Private key appears to be hardcoded in the source code',
    severity: 'CRITICAL' as const,
    recommendation: 'Never commit private keys - use environment variables or secure vaults',
    cwe: 'CWE-798',
  },

  // Mnemonic in code
  mnemonicExposure: {
    pattern: /(?:mnemonic|seed[_-]?phrase|seedPhrase|MNEMONIC)\s*[=:]\s*['"`][a-z]+(?:\s+[a-z]+){11,23}['"`]/gi,
    title: 'Mnemonic/Seed Phrase Exposure',
    description: 'Mnemonic phrase appears to be hardcoded in the source code',
    severity: 'CRITICAL' as const,
    recommendation: 'Never commit mnemonic phrases - use secure storage',
    cwe: 'CWE-798',
  },

  // Unprotected approve
  unlimitedApprove: {
    pattern: /\.approve\s*\([^,]+,\s*(?:ethers\.MaxUint256|2\s*\*\*\s*256|0xf{64}|type\s*\(\s*uint256\s*\)\.max)/gi,
    title: 'Unlimited Token Approval',
    description: 'Approving unlimited tokens is a security risk if the spender is compromised',
    severity: 'MEDIUM' as const,
    recommendation: 'Approve only the needed amount or implement approval expiration',
    cwe: 'CWE-269',
  },

  // Missing slippage protection
  noSlippage: {
    pattern: /(?:swap|exchange)[^}]*(?:amountOutMin|minAmount|slippage)\s*:\s*0/gi,
    title: 'Missing Slippage Protection',
    description: 'Swap with zero slippage protection is vulnerable to sandwich attacks',
    severity: 'HIGH' as const,
    recommendation: 'Always set appropriate slippage tolerance for swaps',
    cwe: 'CWE-20',
  },

  // No deadline
  noDeadline: {
    pattern: /(?:swap|exchange)[^}]*deadline\s*:\s*(?:0|ethers\.MaxUint256)/gi,
    title: 'Missing Transaction Deadline',
    description: 'Transaction without deadline can be held and executed at unfavorable prices',
    severity: 'MEDIUM' as const,
    recommendation: 'Set a reasonable deadline for time-sensitive transactions',
    cwe: 'CWE-20',
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// REDOS DETECTION PATTERNS
// ═══════════════════════════════════════════════════════════════════════════

const REDOS_PATTERNS = {
  // Nested quantifiers
  nestedQuantifiers: {
    pattern: /\([^)]*[+*]\)[+*]|\([^)]*\{[^}]+\}\)[+*{]/,
    type: 'exponential' as const,
    explanation: 'Nested quantifiers can cause exponential backtracking',
    example: '(a+)+ or (a*)*',
  },

  // Overlapping alternation with quantifier
  overlappingAlternation: {
    pattern: /\([^)]*\|[^)]*\)[+*]/,
    type: 'polynomial' as const,
    explanation: 'Alternation inside a quantified group can cause polynomial backtracking',
    example: '(a|a)+',
  },

  // Adjacent quantifiers
  adjacentQuantifiers: {
    pattern: /[+*]\s*[+*]/,
    type: 'catastrophic' as const,
    explanation: 'Adjacent quantifiers cause catastrophic backtracking',
    example: 'a++',
  },

  // Greedy quantifier followed by same pattern
  greedyFollowedBySame: {
    pattern: /\.?\*[^?][^\s]*\./,
    type: 'polynomial' as const,
    explanation: 'Greedy quantifier followed by overlapping pattern',
    example: '.*x.*',
  },

  // Repetition of complex groups
  complexRepetition: {
    pattern: /\([^)]{10,}\)[+*{]/,
    type: 'exponential' as const,
    explanation: 'Complex repeated groups can cause severe backtracking',
    example: '([a-zA-Z0-9]+)+',
  },

  // Evil regex patterns
  evilPatterns: [
    /\([^)]*[+*]\)\+/,           // (x+)+
    /\([^)]*[+*]\)\*/,           // (x+)*
    /\([^)]*[+*]\)\{/,           // (x+){n}
    /\([^)]*\|[^)]*\)[+*]/,      // (a|b)+
    /\[\^[^\]]*\][+*]\[\^/,      // [^x]+[^y]
  ],
};

// ═══════════════════════════════════════════════════════════════════════════
// ZIP/COMPRESSION VULNERABILITY PATTERNS
// ═══════════════════════════════════════════════════════════════════════════

const ZIP_PATTERNS = {
  // Path traversal in extraction
  pathTraversal: {
    pattern: /(?:extractAll|extract|unzip|decompress)\s*\([^)]*(?:req\.|user|input|param|query|body)/gi,
    title: 'Path Traversal in Archive Extraction',
    description: 'Extracting archives with user-controlled paths can lead to arbitrary file write',
    severity: 'CRITICAL' as const,
    type: 'path-traversal' as const,
    recommendation: 'Validate and sanitize all paths, reject paths with ".." or absolute paths',
    cwe: 'CWE-22',
  },

  // Zip slip
  zipSlip: {
    pattern: /entry\.(?:name|path|fileName)[^}]*(?:path\.join|fs\.write|createWriteStream)/gi,
    title: 'Zip Slip Vulnerability',
    description: 'Archive entry paths are used directly without sanitization',
    severity: 'CRITICAL' as const,
    type: 'path-traversal' as const,
    recommendation: 'Validate that resolved paths are within the target directory',
    cwe: 'CWE-22',
  },

  // No size check
  noSizeCheck: {
    pattern: /(?:zlib|pako|jszip|archiver|decompress)\.(?:inflate|decompress|unzip)[^}]*(?!size|length|limit)/gi,
    title: 'Missing Decompression Size Limit',
    description: 'No size limit check before decompression - vulnerable to zip bombs',
    severity: 'HIGH' as const,
    type: 'zip-bomb' as const,
    recommendation: 'Check compressed ratio and set maximum decompressed size limits',
    cwe: 'CWE-409',
  },

  // Dangerous archive libraries
  dangerousExtraction: {
    pattern: /(?:tar|untar|gunzip|bunzip2|unlzma|unxz)\s*\(\s*(?:req\.|user|input)/gi,
    title: 'Dangerous Archive Extraction',
    description: 'Extracting user-provided archives without validation',
    severity: 'HIGH' as const,
    type: 'path-traversal' as const,
    recommendation: 'Validate archive contents and paths before extraction',
    cwe: 'CWE-22',
  },

  // Symlink following
  symlinkFollow: {
    pattern: /(?:extractAll|unzip)[^}]*(?:follow[Ss]ymlinks?\s*:\s*true|resolveSymlinks?\s*:\s*true)/gi,
    title: 'Symlink Following Enabled',
    description: 'Following symlinks during extraction can lead to arbitrary file access',
    severity: 'HIGH' as const,
    type: 'symlink' as const,
    recommendation: 'Disable symlink following or validate symlink targets',
    cwe: 'CWE-59',
  },

  // Stream piping without limits
  streamPiping: {
    pattern: /\.pipe\s*\(\s*(?:zlib|pako)\.(?:createGunzip|createInflate|createUnzip)/gi,
    title: 'Unbounded Stream Decompression',
    description: 'Piping compressed data without size limits',
    severity: 'MEDIUM' as const,
    type: 'zip-bomb' as const,
    recommendation: 'Use stream transforms to limit decompressed size',
    cwe: 'CWE-409',
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// WEB3 SECURITY ANALYZER CLASS
// ═══════════════════════════════════════════════════════════════════════════

class Web3SecurityAnalyzer {
  private findingId = 0;

  /**
   * Analyze code for Remix-style security issues
   */
  analyzeRemixPatterns(code: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    if (typeof code !== 'string') return findings;
    const normalizedCode = code || '';
    const lines = normalizedCode.split('\n');

    for (const [, config] of Object.entries(REMIX_PATTERNS)) {
      const regex = new RegExp(config.pattern.source, config.pattern.flags);
      let match;
      while ((match = regex.exec(normalizedCode)) !== null) {
        // Find line number
        const beforeMatch = code.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;
        const lineStart = beforeMatch.lastIndexOf('\n') + 1;
        const column = match.index - lineStart + 1;

        // Get context (surrounding lines)
        const startLine = Math.max(0, lineNumber - 2);
        const endLine = Math.min(lines.length, lineNumber + 2);
        const contextCode = lines.slice(startLine, endLine).join('\n');

        findings.push({
          id: `remix-${++this.findingId}`,
          category: 'remix',
          severity: config.severity,
          title: config.title,
          description: config.description,
          line: lineNumber,
          column,
          code: contextCode,
          recommendation: config.recommendation,
          cwe: config.cwe,
        });
      }
    }

    return findings;
  }

  /**
   * Analyze a regex pattern for ReDoS vulnerabilities
   */
  analyzeRegex(pattern: string): RegexAnalysis {
    const patternStr = typeof pattern === 'string' ? pattern : String(pattern ?? '');
    const result: RegexAnalysis = {
      pattern: patternStr,
      isVulnerable: false,
    };
    if (!patternStr) return result;

    // Check for nested quantifiers
    if (REDOS_PATTERNS.nestedQuantifiers.pattern.test(patternStr)) {
      result.isVulnerable = true;
      result.vulnerabilityType = 'exponential';
      result.explanation = REDOS_PATTERNS.nestedQuantifiers.explanation;
      result.estimatedComplexity = 'O(2^n)';
    }
    // Check for overlapping alternation
    else if (REDOS_PATTERNS.overlappingAlternation.pattern.test(patternStr)) {
      result.isVulnerable = true;
      result.vulnerabilityType = 'polynomial';
      result.explanation = REDOS_PATTERNS.overlappingAlternation.explanation;
      result.estimatedComplexity = 'O(n^2)';
    }
    // Check for adjacent quantifiers
    else if (REDOS_PATTERNS.adjacentQuantifiers.pattern.test(patternStr)) {
      result.isVulnerable = true;
      result.vulnerabilityType = 'catastrophic';
      result.explanation = REDOS_PATTERNS.adjacentQuantifiers.explanation;
      result.estimatedComplexity = 'O(2^n)';
    }
    // Check evil patterns
    else {
      for (const evil of REDOS_PATTERNS.evilPatterns) {
        if (evil.test(patternStr)) {
          result.isVulnerable = true;
          result.vulnerabilityType = 'exponential';
          result.explanation = 'Pattern matches known evil regex signature';
          result.estimatedComplexity = 'O(2^n)';
          break;
        }
      }
    }

    // Suggest safe alternative if vulnerable
    if (result.isVulnerable) {
      result.safeAlternative = this.suggestSafeAlternative(patternStr);
    }

    return result;
  }

  /**
   * Find all regex patterns in code and analyze them
   */
  findRegexInCode(code: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    if (typeof code !== 'string') return findings;
    const normalizedCode = code || '';
    const lines = normalizedCode.split('\n');

    // Match regex literals and RegExp constructors (reset lastIndex each run to avoid cross-call reuse bug)
    const regexPatterns = [
      /\/([^\/\n]+)\/[gimsuvy]*/g,                    // Regex literals
      /new\s+RegExp\s*\(\s*['"`]([^'"`]+)['"`]/g,    // RegExp constructor
      /RegExp\s*\(\s*['"`]([^'"`]+)['"`]/g,          // RegExp without new
    ];

    for (const patternRegex of regexPatterns) {
      patternRegex.lastIndex = 0;
      let match;
      while ((match = patternRegex.exec(normalizedCode)) !== null) {
        const regexPattern = match[1];
        const analysis = this.analyzeRegex(regexPattern);

        if (analysis.isVulnerable) {
          const beforeMatch = normalizedCode.substring(0, match.index);
          const lineNumber = beforeMatch.split('\n').length;
          const startLine = Math.max(0, lineNumber - 2);
          const endLine = Math.min(lines.length, lineNumber + 2);

          findings.push({
            id: `redos-${++this.findingId}`,
            category: 'redos',
            severity: analysis.vulnerabilityType === 'catastrophic' ? 'CRITICAL' : 
                     analysis.vulnerabilityType === 'exponential' ? 'HIGH' : 'MEDIUM',
            title: `ReDoS Vulnerability (${analysis.vulnerabilityType})`,
            description: `${analysis.explanation}. Complexity: ${analysis.estimatedComplexity}`,
            line: lineNumber,
            code: lines.slice(startLine, endLine).join('\n'),
            recommendation: analysis.safeAlternative 
              ? `Consider using: ${analysis.safeAlternative}`
              : 'Refactor the regex to avoid nested/repeated quantifiers',
            cwe: 'CWE-1333',
          });
        }
      }
    }

    return findings;
  }

  /**
   * Analyze code for zip/compression vulnerabilities
   */
  analyzeZipPatterns(code: string): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    if (typeof code !== 'string') return findings;
    const normalizedCode = code || '';
    const lines = normalizedCode.split('\n');

    for (const [, config] of Object.entries(ZIP_PATTERNS)) {
      const regex = new RegExp(config.pattern.source, config.pattern.flags);
      let match;
      while ((match = regex.exec(normalizedCode)) !== null) {
        const beforeMatch = code.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;
        const startLine = Math.max(0, lineNumber - 2);
        const endLine = Math.min(lines.length, lineNumber + 2);

        findings.push({
          id: `zip-${++this.findingId}`,
          category: 'zip',
          severity: config.severity,
          title: config.title,
          description: config.description,
          line: lineNumber,
          code: lines.slice(startLine, endLine).join('\n'),
          recommendation: config.recommendation,
          cwe: config.cwe,
        });
      }
    }

    // Also check for compression library imports
    const compressionImports = [
      { pattern: /(?:require|import)[^;]*['"](?:zlib|pako|jszip|archiver|adm-zip|unzipper|node-gzip|lz4|snappy|brotli)['"]/, lib: 'Compression Library' },
      { pattern: /(?:require|import)[^;]*['"](?:tar|tar-stream|tar-fs|node-tar)['"]/, lib: 'Tar Library' },
    ];

    for (const { pattern, lib } of compressionImports) {
      if (pattern.test(normalizedCode)) {
        findings.push({
          id: `zip-${++this.findingId}`,
          category: 'zip',
          severity: 'INFO',
          title: `${lib} Usage Detected`,
          description: `Code uses ${lib} - review for potential zip bomb and path traversal vulnerabilities`,
          recommendation: 'Ensure proper size limits and path validation are in place',
          cwe: 'CWE-409',
        });
      }
    }

    return findings;
  }

  /**
   * Full security analysis
   */
  analyzeCode(code: string): AnalysisResult {
    if (typeof code !== 'string') {
      return { findings: [], stats: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, analyzedAt: Date.now() };
    }
    const normalizedCode = code || '';
    const findings: SecurityFinding[] = [
      ...this.analyzeRemixPatterns(normalizedCode),
      ...this.findRegexInCode(normalizedCode),
      ...this.analyzeZipPatterns(normalizedCode),
    ];

    // Sort by severity
    const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    // Calculate stats
    const stats = {
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
      info: findings.filter(f => f.severity === 'INFO').length,
    };

    return {
      findings,
      stats,
      analyzedAt: Date.now(),
    };
  }

  /**
   * Suggest a safe alternative for vulnerable regex
   */
  private suggestSafeAlternative(pattern: string): string | undefined {
    // Replace (x+)+ with (x)+
    if (/\([^)]*\+\)\+/.test(pattern)) {
      return pattern.replace(/\(([^)]*)\+\)\+/g, '($1)+');
    }
    // Replace (x*)* with (x)*
    if (/\([^)]*\*\)\*/.test(pattern)) {
      return pattern.replace(/\(([^)]*)\*\)\*/g, '($1)*');
    }
    // Suggest atomic groups or possessive quantifiers (conceptual)
    if (/\([^)]*[+*]\)[+*]/.test(pattern)) {
      return 'Use atomic groups or possessive quantifiers if supported';
    }
    return undefined;
  }
}

// Export singleton
export const web3SecurityAnalyzer = new Web3SecurityAnalyzer();

// Export functions for IPC
export function analyzeWeb3Security(code: string): AnalysisResult {
  return web3SecurityAnalyzer.analyzeCode(code);
}

export function analyzeRegexPattern(pattern: string): RegexAnalysis {
  return web3SecurityAnalyzer.analyzeRegex(pattern);
}

export function analyzeForRemixIssues(code: string): SecurityFinding[] {
  return web3SecurityAnalyzer.analyzeRemixPatterns(code);
}

export function analyzeForReDoS(code: string): SecurityFinding[] {
  return web3SecurityAnalyzer.findRegexInCode(code);
}

export function analyzeForZipVulns(code: string): SecurityFinding[] {
  return web3SecurityAnalyzer.analyzeZipPatterns(code);
}
