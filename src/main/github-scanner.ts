/**
 * CleanTraffic - GitHub Repository Scanner
 * Advanced Web3/Blockchain Security Scanner
 * Clones repos and performs deep Semgrep analysis
 */

import { execSync, spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// TYPES & INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════════════════════

export interface GitHubScanResult {
  id: string;
  ruleId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
  file: string;
  line: number;
  endLine: number;
  column: number;
  endColumn: number;
  code: string;
  category: string;
  cweIds?: string[];
  owaspIds?: string[];
  fix?: string;
  references?: string[];
  dataflowTrace?: string[];
}

export interface GitHubScanProgress {
  stage: 'cloning' | 'analyzing' | 'scanning' | 'complete' | 'error';
  message: string;
  progress?: number;
  totalFiles?: number;
  scannedFiles?: number;
  currentFile?: string;
}

export interface GitHubScanOptions {
  repoUrl: string;
  branch?: string;
  /** GitHub Personal Access Token for private repos and higher rate limits */
  githubToken?: string;
  customRulesPath?: string;
  useDefaultRules?: boolean;
  customRules?: string;
  scanDepth?: 'shallow' | 'full';
  includeTests?: boolean;
  maxFileSize?: number; // KB
  timeout?: number; // seconds
}

export interface RepoAnalysis {
  totalFiles: number;
  scannableFiles: number;
  languages: Map<string, number>;
  directories: number;
  largeFiles: string[];
  hasPackageJson: boolean;
  hasCargoToml: boolean;
  hasPyProjectToml: boolean;
  hasGoMod: boolean;
  hasSolidityFiles: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// SEMGREP RULES - Comprehensive Web3 & General Security
// ═══════════════════════════════════════════════════════════════════════════════════════════════

const WEB3_SEMGREP_RULES = `rules:
  # ═══════════════════════════════════════════════════════════════════════════
  # SOLIDITY / SMART CONTRACT SECURITY
  # ═══════════════════════════════════════════════════════════════════════════

  - id: solidity-reentrancy
    message: "CRITICAL: Potential reentrancy vulnerability - state changes after external call"
    severity: ERROR
    languages: [solidity]
    patterns:
      - pattern: |
          $CONTRACT.call{...}(...)
          ...
          $STATE = ...
    metadata:
      category: reentrancy
      cwe: CWE-841
      confidence: HIGH

  - id: solidity-unchecked-call
    message: "HIGH: Unchecked return value from low-level call"
    severity: ERROR
    languages: [solidity]
    patterns:
      - pattern: $ADDR.call(...)
      - pattern: $ADDR.delegatecall(...)
      - pattern: $ADDR.staticcall(...)
    pattern-not-inside: |
      (bool $SUCCESS, ...) = ...
    metadata:
      category: unchecked-call
      cwe: CWE-252

  - id: solidity-tx-origin
    message: "HIGH: tx.origin used for authentication - use msg.sender instead"
    severity: ERROR
    languages: [solidity]
    patterns:
      - pattern: require(tx.origin == ...)
      - pattern: if (tx.origin == ...)
    metadata:
      category: authentication
      cwe: CWE-477

  - id: solidity-selfdestruct
    message: "CRITICAL: selfdestruct can be triggered - verify access controls"
    severity: ERROR
    languages: [solidity]
    pattern: selfdestruct(...)
    metadata:
      category: access-control
      cwe: CWE-284

  - id: solidity-arbitrary-send
    message: "HIGH: ETH sent to user-controlled address"
    severity: ERROR
    languages: [solidity]
    patterns:
      - pattern: $ADDR.transfer(...)
      - pattern: $ADDR.send(...)
      - pattern: |
          $ADDR.call{value: ...}(...)
    metadata:
      category: arbitrary-send
      cwe: CWE-20

  - id: solidity-timestamp-dependence
    message: "MEDIUM: Block timestamp used - can be manipulated by miners"
    severity: WARNING
    languages: [solidity]
    patterns:
      - pattern: block.timestamp
      - pattern: now
    metadata:
      category: timestamp
      cwe: CWE-829

  - id: solidity-weak-randomness
    message: "HIGH: Weak randomness source - blockhash/timestamp are predictable"
    severity: ERROR
    languages: [solidity]
    patterns:
      - pattern: keccak256(...block.timestamp...)
      - pattern: keccak256(...blockhash(...)...)
      - pattern: keccak256(...block.number...)
    metadata:
      category: randomness
      cwe: CWE-330

  - id: solidity-integer-overflow
    message: "HIGH: Potential integer overflow/underflow (use SafeMath or Solidity 0.8+)"
    severity: ERROR
    languages: [solidity]
    patterns:
      - pattern-either:
          - pattern: $A + $B
          - pattern: $A - $B
          - pattern: $A * $B
    pattern-not-inside: |
      unchecked { ... }
    metadata:
      category: arithmetic
      cwe: CWE-190

  - id: solidity-delegatecall-loop
    message: "CRITICAL: delegatecall in loop - potential gas griefing"
    severity: ERROR
    languages: [solidity]
    pattern: |
      for (...) {
        ...
        $ADDR.delegatecall(...)
        ...
      }
    metadata:
      category: gas-griefing
      cwe: CWE-400

  - id: solidity-public-function-visibility
    message: "MEDIUM: Function without explicit visibility - defaults to public"
    severity: WARNING
    languages: [solidity]
    pattern: |
      function $FUNC(...) {
        ...
      }
    pattern-not: |
      function $FUNC(...) public ...
    pattern-not: |
      function $FUNC(...) private ...
    pattern-not: |
      function $FUNC(...) internal ...
    pattern-not: |
      function $FUNC(...) external ...
    metadata:
      category: visibility
      cwe: CWE-284

  # ═══════════════════════════════════════════════════════════════════════════
  # RUST / MOVE / BLOCKCHAIN BACKEND
  # ═══════════════════════════════════════════════════════════════════════════

  - id: rust-unwrap-panic
    message: "MEDIUM: unwrap() can panic - use expect() or proper error handling"
    severity: WARNING
    languages: [rust]
    pattern: $X.unwrap()
    metadata:
      category: error-handling
      cwe: CWE-755

  - id: rust-unsafe-block
    message: "HIGH: Unsafe block detected - review for memory safety"
    severity: WARNING
    languages: [rust]
    pattern: |
      unsafe { ... }
    metadata:
      category: memory-safety
      cwe: CWE-119

  - id: rust-transmute
    message: "CRITICAL: mem::transmute bypasses type safety - high risk"
    severity: ERROR
    languages: [rust]
    patterns:
      - pattern: std::mem::transmute(...)
      - pattern: mem::transmute(...)
    metadata:
      category: type-safety
      cwe: CWE-843

  - id: rust-raw-pointer
    message: "HIGH: Raw pointer dereference - potential memory corruption"
    severity: WARNING
    languages: [rust]
    patterns:
      - pattern: "*$PTR"
    pattern-inside: |
      unsafe { ... }
    metadata:
      category: memory-safety
      cwe: CWE-119

  # ═══════════════════════════════════════════════════════════════════════════
  # JAVASCRIPT / TYPESCRIPT - WEB3 FRONTEND
  # ═══════════════════════════════════════════════════════════════════════════

  - id: js-hardcoded-private-key
    message: "CRITICAL: Hardcoded private key detected"
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: privateKey = "..."
          - pattern: PRIVATE_KEY = "..."
          - pattern: private_key = "..."
          - pattern: |
              { privateKey: "..." }
    metadata:
      category: secrets
      cwe: CWE-798
      confidence: HIGH

  - id: js-hardcoded-mnemonic
    message: "CRITICAL: Hardcoded mnemonic/seed phrase detected"
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: mnemonic = "..."
          - pattern: MNEMONIC = "..."
          - pattern: seedPhrase = "..."
          - pattern: seed_phrase = "..."
    metadata:
      category: secrets
      cwe: CWE-798

  - id: js-private-key-regex
    message: "CRITICAL: Ethereum private key pattern detected (0x + 64 hex chars)"
    severity: ERROR
    languages: [javascript, typescript]
    pattern-regex: '["'']0x[a-fA-F0-9]{64}["'']'
    metadata:
      category: secrets
      cwe: CWE-798
      confidence: HIGH

  - id: js-insecure-random
    message: "HIGH: Math.random() is not cryptographically secure"
    severity: ERROR
    languages: [javascript, typescript]
    pattern: Math.random()
    metadata:
      category: cryptography
      cwe: CWE-330

  - id: js-eval-injection
    message: "CRITICAL: Dynamic code execution via eval"
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: eval(...)
          - pattern: new Function(...)
          - pattern: setTimeout($CODE, ...)
          - pattern: setInterval($CODE, ...)
    metadata:
      category: injection
      cwe: CWE-94

  - id: js-dangerous-innerhtml
    message: "HIGH: innerHTML with untrusted data - XSS risk"
    severity: ERROR
    languages: [javascript, typescript]
    mode: taint
    pattern-sources:
      - pattern: location.search
      - pattern: location.hash
      - pattern: document.URL
      - pattern: req.query.$X
      - pattern: req.body.$X
    pattern-sinks:
      - pattern: $EL.innerHTML = $DATA
      - pattern: $EL.outerHTML = $DATA
      - pattern: document.write($DATA)
    metadata:
      category: xss
      cwe: CWE-79

  - id: js-command-injection
    message: "CRITICAL: Command injection vulnerability"
    severity: ERROR
    languages: [javascript, typescript]
    mode: taint
    pattern-sources:
      - pattern: req.query.$X
      - pattern: req.body.$X
      - pattern: req.params.$X
    pattern-sinks:
      - pattern: exec($CMD)
      - pattern: execSync($CMD)
      - pattern: spawn($CMD, ...)
      - pattern: child_process.exec($CMD)
    metadata:
      category: injection
      cwe: CWE-78

  - id: js-unsafe-web3-transaction
    message: "HIGH: Web3 transaction without error handling"
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: $PROVIDER.send(...)
          - pattern: $SIGNER.sendTransaction(...)
          - pattern: $CONTRACT.$METHOD.send(...)
    pattern-not-inside: |
      try { ... } catch { ... }
    metadata:
      category: web3
      cwe: CWE-252

  - id: js-prototype-pollution
    message: "HIGH: Prototype pollution via object merge"
    severity: ERROR
    languages: [javascript, typescript]
    mode: taint
    pattern-sources:
      - pattern: req.body
      - pattern: req.query
      - pattern: JSON.parse(...)
    pattern-sinks:
      - pattern: Object.assign($TARGET, $SOURCE)
      - pattern: _.merge($TARGET, $SOURCE)
      - pattern: _.defaultsDeep($TARGET, $SOURCE)
    metadata:
      category: prototype-pollution
      cwe: CWE-1321

  - id: js-sql-injection
    message: "CRITICAL: SQL injection via string concatenation"
    severity: ERROR
    languages: [javascript, typescript]
    mode: taint
    pattern-sources:
      - pattern: req.query.$X
      - pattern: req.body.$X
      - pattern: req.params.$X
    pattern-sinks:
      - pattern: $DB.query($SQL + ...)
      - pattern: $DB.query(\`...\${$VAR}...\`)
      - pattern: $DB.execute($SQL + ...)
    metadata:
      category: injection
      cwe: CWE-89

  - id: js-ssrf
    message: "HIGH: Server-Side Request Forgery - user input in URL"
    severity: ERROR
    languages: [javascript, typescript]
    mode: taint
    pattern-sources:
      - pattern: req.query.$X
      - pattern: req.body.$X
    pattern-sinks:
      - pattern: fetch($URL, ...)
      - pattern: axios.get($URL, ...)
      - pattern: axios.post($URL, ...)
      - pattern: axios($URL, ...)
      - pattern: http.get($URL, ...)
    metadata:
      category: ssrf
      cwe: CWE-918

  - id: js-path-traversal
    message: "HIGH: Path traversal - user input in file path"
    severity: ERROR
    languages: [javascript, typescript]
    mode: taint
    pattern-sources:
      - pattern: req.query.$X
      - pattern: req.body.$X
      - pattern: req.params.$X
    pattern-sinks:
      - pattern: fs.readFileSync($PATH, ...)
      - pattern: fs.readFile($PATH, ...)
      - pattern: fs.writeFileSync($PATH, ...)
      - pattern: fs.createReadStream($PATH)
      - pattern: path.join(..., $SINK, ...)
    pattern-sanitizers:
      - pattern: path.basename($X)
    metadata:
      category: path-traversal
      cwe: CWE-22

  - id: js-jwt-no-verify
    message: "CRITICAL: JWT decoded without signature verification"
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: jwt.decode($TOKEN)
          - pattern: jwtDecode($TOKEN)
    pattern-not-inside: |
      jwt.verify(...)
    metadata:
      category: authentication
      cwe: CWE-347

  - id: js-cors-wildcard
    message: "MEDIUM: CORS allows all origins"
    severity: WARNING
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: |
              "Access-Control-Allow-Origin": "*"
          - pattern: |
              cors({ origin: "*" })
          - pattern: |
              cors({ origin: true })
    metadata:
      category: misconfiguration
      cwe: CWE-942

  - id: js-redos-user-input
    message: "HIGH: User input used in regex - ReDoS risk"
    severity: ERROR
    languages: [javascript, typescript]
    mode: taint
    pattern-sources:
      - pattern: req.query.$X
      - pattern: req.body.$X
      - pattern: req.params.$X
    pattern-sinks:
      - pattern: new RegExp($SINK, ...)
      - pattern: $STR.match($SINK)
      - pattern: $STR.replace($SINK, ...)
    metadata:
      category: redos
      cwe: CWE-1333

  # ═══════════════════════════════════════════════════════════════════════════
  # PYTHON SECURITY
  # ═══════════════════════════════════════════════════════════════════════════

  - id: py-hardcoded-secret
    message: "CRITICAL: Hardcoded secret in Python"
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: private_key = "..."
          - pattern: PRIVATE_KEY = "..."
          - pattern: secret_key = "..."
          - pattern: api_key = "..."
          - pattern: password = "..."
    metadata:
      category: secrets
      cwe: CWE-798

  - id: py-pickle-rce
    message: "CRITICAL: pickle.load can execute arbitrary code"
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: pickle.load(...)
          - pattern: pickle.loads(...)
          - pattern: cPickle.load(...)
          - pattern: cPickle.loads(...)
    metadata:
      category: deserialization
      cwe: CWE-502

  - id: py-sql-injection
    message: "CRITICAL: SQL injection via string formatting"
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: cursor.execute($Q % ...)
          - pattern: cursor.execute($Q.format(...))
          - pattern: cursor.execute(f"...")
    metadata:
      category: injection
      cwe: CWE-89

  - id: py-subprocess-shell
    message: "HIGH: subprocess with shell=True allows command injection"
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: subprocess.run(..., shell=True, ...)
          - pattern: subprocess.call(..., shell=True, ...)
          - pattern: subprocess.Popen(..., shell=True, ...)
          - pattern: os.system(...)
    metadata:
      category: injection
      cwe: CWE-78

  - id: py-yaml-load
    message: "HIGH: yaml.load without SafeLoader is unsafe"
    severity: ERROR
    languages: [python]
    pattern: yaml.load($DATA)
    pattern-not: yaml.load($DATA, Loader=yaml.SafeLoader)
    pattern-not: yaml.safe_load($DATA)
    metadata:
      category: deserialization
      cwe: CWE-502

  - id: py-weak-random
    message: "HIGH: random module is not cryptographically secure"
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: random.random()
          - pattern: random.randint(...)
          - pattern: random.choice(...)
    metadata:
      category: cryptography
      cwe: CWE-330

  # ═══════════════════════════════════════════════════════════════════════════
  # GO SECURITY
  # ═══════════════════════════════════════════════════════════════════════════

  - id: go-weak-random
    message: "HIGH: math/rand is not cryptographically secure - use crypto/rand"
    severity: ERROR
    languages: [go]
    patterns:
      - pattern-either:
          - pattern: rand.Int(...)
          - pattern: rand.Intn(...)
          - pattern: rand.Read(...)
    metadata:
      category: cryptography
      cwe: CWE-330

  - id: go-hardcoded-creds
    message: "CRITICAL: Hardcoded credentials"
    severity: ERROR
    languages: [go]
    patterns:
      - pattern-either:
          - pattern: password := "..."
          - pattern: apiKey := "..."
          - pattern: secretKey := "..."
          - pattern: privateKey := "..."
    metadata:
      category: secrets
      cwe: CWE-798

  - id: go-sql-injection
    message: "CRITICAL: SQL injection via string concatenation"
    severity: ERROR
    languages: [go]
    patterns:
      - pattern-either:
          - pattern: db.Query($Q + ...)
          - pattern: db.Exec($Q + ...)
          - pattern: fmt.Sprintf($FMT, ...)
    pattern-inside: |
      db.$METHOD(...)
    metadata:
      category: injection
      cwe: CWE-89

  - id: go-command-injection
    message: "CRITICAL: Command injection vulnerability"
    severity: ERROR
    languages: [go]
    mode: taint
    pattern-sources:
      - pattern: r.URL.Query().Get(...)
      - pattern: r.FormValue(...)
    pattern-sinks:
      - pattern: exec.Command($CMD, ...)
      - pattern: exec.CommandContext($CTX, $CMD, ...)
    metadata:
      category: injection
      cwe: CWE-78

  # ═══════════════════════════════════════════════════════════════════════════
  # SECRETS & TOKENS (ALL LANGUAGES)
  # ═══════════════════════════════════════════════════════════════════════════

  - id: secret-aws-key
    message: "CRITICAL: AWS Access Key detected"
    severity: ERROR
    languages: [generic]
    pattern-regex: 'AKIA[0-9A-Z]{16}'
    metadata:
      category: secrets
      cwe: CWE-798

  - id: secret-github-token
    message: "CRITICAL: GitHub token detected"
    severity: ERROR
    languages: [generic]
    pattern-regex: 'gh[pousr]_[A-Za-z0-9_]{36,}'
    metadata:
      category: secrets
      cwe: CWE-798

  - id: secret-jwt-token
    message: "HIGH: JWT token detected in source code"
    severity: ERROR
    languages: [generic]
    pattern-regex: 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'
    metadata:
      category: secrets
      cwe: CWE-798

  - id: secret-slack-token
    message: "CRITICAL: Slack token detected"
    severity: ERROR
    languages: [generic]
    pattern-regex: 'xox[baprs]-[0-9A-Za-z-]+'
    metadata:
      category: secrets
      cwe: CWE-798

  - id: secret-stripe-key
    message: "CRITICAL: Stripe API key detected"
    severity: ERROR
    languages: [generic]
    pattern-regex: 'sk_live_[0-9a-zA-Z]{24,}'
    metadata:
      category: secrets
      cwe: CWE-798
`;

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// GITHUB SCANNER CLASS
// ═══════════════════════════════════════════════════════════════════════════════════════════════

class GitHubScanner {
  private tempDir: string;
  private rulesDir: string;
  private semgrepVersion: string | null = null;

  // File extensions to scan
  private static readonly SCANNABLE_EXTENSIONS = new Set([
    '.sol', '.rs', '.js', '.ts', '.jsx', '.tsx', '.py', '.go',
    '.move', '.cairo', '.vy', '.java', '.c', '.cpp', '.h', '.hpp',
    '.cs', '.rb', '.php', '.swift', '.kt', '.scala', '.sh', '.bash',
    '.yml', '.yaml', '.json', '.toml', '.env', '.config',
  ]);

  // Directories to exclude
  private static readonly EXCLUDED_DIRS = new Set([
    'node_modules', '.git', 'target', 'build', 'dist', '__pycache__',
    '.next', '.nuxt', 'vendor', 'venv', '.venv', 'env', '.tox',
    'coverage', '.nyc_output', '.cache', 'artifacts', 'deployments',
    'typechain', 'typechain-types', 'cache', 'out', 'lib', 'deps',
  ]);

  constructor() {
    this.tempDir = path.join(os.tmpdir(), 'cleantraffic-github-scanner');
    this.rulesDir = path.join(this.tempDir, 'rules');
    this.ensureDirectories();
  }

  private ensureDirectories(): void {
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true });
    }
    if (!fs.existsSync(this.rulesDir)) {
      fs.mkdirSync(this.rulesDir, { recursive: true });
    }
  }

  private writeRules(): string {
    const rulesPath = path.join(this.rulesDir, 'security-rules.yml');
    fs.writeFileSync(rulesPath, WEB3_SEMGREP_RULES, 'utf-8');
    return rulesPath;
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // URL PARSING
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  parseGitHubUrl(url: string): { owner: string; repo: string; branch?: string } | null {
    const patterns = [
      // Full GitHub URLs
      /github\.com\/([^\/]+)\/([^\/]+?)(?:\.git)?(?:\/tree\/([^\/]+))?(?:\/.*)?$/,
      /github\.com\/([^\/]+)\/([^\/]+?)(?:\.git)?$/,
      // Short format: owner/repo
      /^([^\/]+)\/([^\/]+)$/,
    ];

    const cleanUrl = url.trim().replace(/\/$/, '');

    for (const pattern of patterns) {
      const match = cleanUrl.match(pattern);
      if (match) {
        return {
          owner: match[1],
          repo: match[2].replace(/\.git$/, ''),
          branch: match[3],
        };
      }
    }
    return null;
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // REPOSITORY CLONING
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  async cloneRepository(
    repoUrl: string,
    options: GitHubScanOptions,
    onProgress?: (progress: GitHubScanProgress) => void
  ): Promise<string> {
    const parsed = this.parseGitHubUrl(repoUrl);
    if (!parsed) {
      throw new Error(`Invalid GitHub URL: ${repoUrl}`);
    }

    const cloneDir = path.join(this.tempDir, `${parsed.owner}-${parsed.repo}-${Date.now()}`);
    const baseUrl = `https://github.com/${parsed.owner}/${parsed.repo}.git`;
    const gitUrl = options.githubToken?.trim()
      ? `https://${options.githubToken.trim()}@github.com/${parsed.owner}/${parsed.repo}.git`
      : baseUrl;

    onProgress?.({
      stage: 'cloning',
      message: `Cloning ${parsed.owner}/${parsed.repo}...`,
      progress: 5,
    });

    try {
      const branchArg = options.branch || parsed.branch 
        ? `--branch ${options.branch || parsed.branch}` 
        : '';
      
      const depthArg = options.scanDepth === 'full' ? '' : '--depth 1';
      
      const cloneDirNorm = path.normalize(cloneDir);
      const cmd = `git clone ${depthArg} ${branchArg} "${gitUrl}" "${cloneDirNorm}"`;

      if (!options.githubToken?.trim()) {
        console.log('[GitHub Scanner] Cloning:', baseUrl);
      } else {
        console.log('[GitHub Scanner] Cloning (with token):', `${parsed.owner}/${parsed.repo}`);
      }

      const execOpts: { stdio: 'pipe'; timeout: number; maxBuffer: number; shell?: string } = {
        stdio: 'pipe',
        timeout: 180000,
        maxBuffer: 50 * 1024 * 1024,
      };
      if (process.platform === 'win32') {
        execOpts.shell = process.env.COMSPEC || 'cmd.exe';
      }
      execSync(cmd, execOpts);

      onProgress?.({
        stage: 'cloning',
        message: 'Repository cloned successfully',
        progress: 20,
      });

      return cloneDir;
    } catch (error) {
      const err = error as Error;
      console.error('[GitHub Scanner] Clone failed:', err.message);
      throw new Error(`Failed to clone repository: ${err.message}`);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // REPOSITORY ANALYSIS
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  analyzeRepository(
    repoPath: string,
    options: GitHubScanOptions,
    onProgress?: (progress: GitHubScanProgress) => void
  ): RepoAnalysis {
    onProgress?.({
      stage: 'analyzing',
      message: 'Analyzing repository structure...',
      progress: 25,
    });

    const analysis: RepoAnalysis = {
      totalFiles: 0,
      scannableFiles: 0,
      languages: new Map(),
      directories: 0,
      largeFiles: [],
      hasPackageJson: false,
      hasCargoToml: false,
      hasPyProjectToml: false,
      hasGoMod: false,
      hasSolidityFiles: false,
    };

    const maxFileSize = (options.maxFileSize || 500) * 1024; // Default 500KB

    const walkDir = (dir: string, depth: number = 0): void => {
      if (depth > 50) return; // Prevent infinite recursion

      try {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          
          if (entry.isDirectory()) {
            // Skip excluded directories
            if (GitHubScanner.EXCLUDED_DIRS.has(entry.name)) continue;
            if (entry.name.startsWith('.') && entry.name !== '.github') continue;
            
            analysis.directories++;
            walkDir(fullPath, depth + 1);
          } else if (entry.isFile()) {
            analysis.totalFiles++;
            
            const ext = path.extname(entry.name).toLowerCase();
            const basename = entry.name.toLowerCase();
            
            // Check for project files
            if (basename === 'package.json') analysis.hasPackageJson = true;
            if (basename === 'cargo.toml') analysis.hasCargoToml = true;
            if (basename === 'pyproject.toml') analysis.hasPyProjectToml = true;
            if (basename === 'go.mod') analysis.hasGoMod = true;
            if (ext === '.sol') analysis.hasSolidityFiles = true;
            
            // Check if scannable
            if (GitHubScanner.SCANNABLE_EXTENSIONS.has(ext)) {
              try {
                const stats = fs.statSync(fullPath);
                if (stats.size <= maxFileSize) {
                  analysis.scannableFiles++;
                  
                  // Count by language
                  const count = analysis.languages.get(ext) || 0;
                  analysis.languages.set(ext, count + 1);
                } else {
                  analysis.largeFiles.push(path.relative(repoPath, fullPath));
                }
              } catch {
                // Skip files we can't stat
              }
            }
          }
        }
      } catch (err) {
        console.warn('[GitHub Scanner] Error reading directory:', dir, err);
      }
    };

    walkDir(repoPath);

    // Log analysis results
    console.log('[GitHub Scanner] Analysis complete:');
    console.log(`  - Total files: ${analysis.totalFiles}`);
    console.log(`  - Scannable files: ${analysis.scannableFiles}`);
    console.log(`  - Directories: ${analysis.directories}`);
    console.log(`  - Languages: ${Array.from(analysis.languages.entries()).map(([k, v]) => `${k}(${v})`).join(', ')}`);

    onProgress?.({
      stage: 'analyzing',
      message: `Found ${analysis.scannableFiles} scannable files in ${analysis.directories} directories`,
      progress: 30,
      totalFiles: analysis.scannableFiles,
    });

    return analysis;
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // SEMGREP INTEGRATION
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  private async checkSemgrep(): Promise<{ installed: boolean; version?: string; error?: string }> {
    return new Promise((resolve) => {
      const proc = spawn('semgrep', ['--version'], { shell: true });
      let output = '';
      let error = '';

      proc.stdout.on('data', (data) => { output += data.toString(); });
      proc.stderr.on('data', (data) => { error += data.toString(); });

      proc.on('close', (code) => {
        if (code === 0 && output) {
          this.semgrepVersion = output.trim();
          resolve({ installed: true, version: output.trim() });
        } else {
          resolve({ installed: false, error: error || 'Semgrep not found' });
        }
      });

      proc.on('error', (err) => {
        resolve({ installed: false, error: err.message });
      });

      setTimeout(() => resolve({ installed: false, error: 'Timeout checking Semgrep' }), 15000);
    });
  }

  private async runSemgrep(args: string[], timeout: number = 300000): Promise<{ 
    stdout: string; 
    stderr: string; 
    code: number;
  }> {
    return new Promise((resolve, reject) => {
      const fullArgs = args.join(' ');
      console.log('[GitHub Scanner] Running: semgrep', fullArgs);
      
      const proc = spawn('semgrep', args, {
        shell: true,
        env: { 
          ...process.env, 
          SEMGREP_SEND_METRICS: 'off',
          SEMGREP_VERSION_CACHE_PATH: path.join(this.tempDir, '.semgrep-version'),
        },
      });

      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (data: Buffer) => { stdout += data.toString(); });
      proc.stderr?.on('data', (data: Buffer) => { stderr += data.toString(); });

      proc.on('close', (code: number | null) => {
        console.log('[GitHub Scanner] Semgrep exit code:', code);
        resolve({ stdout, stderr, code: code || 0 });
      });

      proc.on('error', (err: Error) => {
        console.error('[GitHub Scanner] Semgrep spawn error:', err);
        reject(err);
      });

      // Timeout handler
      const timeoutId = setTimeout(() => {
        proc.kill('SIGTERM');
        setTimeout(() => proc.kill('SIGKILL'), 5000);
        reject(new Error(`Semgrep timed out after ${timeout/1000} seconds`));
      }, timeout);

      proc.on('close', () => clearTimeout(timeoutId));
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // MAIN SCAN LOGIC
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  async runScan(
    repoPath: string,
    options: GitHubScanOptions,
    analysis: RepoAnalysis,
    onProgress?: (progress: GitHubScanProgress) => void
  ): Promise<GitHubScanResult[]> {
    // Check Semgrep installation
    onProgress?.({
      stage: 'scanning',
      message: 'Checking Semgrep installation...',
      progress: 35,
    });

    const semgrepCheck = await this.checkSemgrep();
    if (!semgrepCheck.installed) {
      throw new Error(`Semgrep not installed: ${semgrepCheck.error}. Install with: pip install semgrep`);
    }

    console.log('[GitHub Scanner] Semgrep version:', semgrepCheck.version);

    // Write rules
    const rulesPath = this.writeRules();
    console.log('[GitHub Scanner] Rules written to:', rulesPath);

    onProgress?.({
      stage: 'scanning',
      message: `Scanning ${analysis.scannableFiles} files with Semgrep...`,
      progress: 40,
      totalFiles: analysis.scannableFiles,
    });

    // Build exclusion patterns
    const excludePatterns = Array.from(GitHubScanner.EXCLUDED_DIRS).map(dir => `--exclude=${dir}`);
    
    // Add test exclusions unless includeTests is true
    if (!options.includeTests) {
      excludePatterns.push('--exclude=*test*', '--exclude=*spec*', '--exclude=*mock*');
    }

    // Calculate timeout based on file count
    const baseTimeout = options.timeout || 300;
    const timeout = Math.min(600, Math.max(baseTimeout, analysis.scannableFiles * 0.5)) * 1000;

    try {
      const args = [
        'scan',
        '--config', rulesPath,
        ...excludePatterns,
        '--json',
        '--timeout', String(Math.floor(timeout / 1000)),
        '--timeout-threshold', '3',
        '--max-target-bytes', String((options.maxFileSize || 500) * 1024),
        '--metrics', 'off',
        '--disable-version-check',
        repoPath,
      ];

      // Add custom rules if specified
      if (options.customRulesPath && fs.existsSync(options.customRulesPath)) {
        args.splice(2, 0, '--config', options.customRulesPath);
      }

      const { stdout, stderr, code } = await this.runSemgrep(args, timeout);

      // Log errors for debugging
      if (code > 1) {
        console.error('[GitHub Scanner] Semgrep error (code', code, '):');
        const stderrLines = stderr.split('\n').filter(l => l.trim()).slice(0, 15);
        stderrLines.forEach(line => console.error('  ', line));
        
        // Try to extract meaningful error
        const errorMatch = stderr.match(/(?:error|Error|ERROR)[:\s]+(.+)/);
        const errorMsg = errorMatch ? errorMatch[1].slice(0, 200) : stderr.slice(0, 300);
        throw new Error(`Semgrep scan failed (code ${code}): ${errorMsg}`);
      }

      onProgress?.({
        stage: 'scanning',
        message: 'Processing scan results...',
        progress: 80,
      });

      // Parse results
      const results = this.parseResults(stdout, repoPath);

      onProgress?.({
        stage: 'complete',
        message: `Scan complete - ${results.length} findings`,
        progress: 100,
        totalFiles: analysis.scannableFiles,
      });

      return results;

    } catch (error) {
      const err = error as Error;
      console.error('[GitHub Scanner] Scan error:', err.message);
      
      onProgress?.({
        stage: 'error',
        message: err.message.slice(0, 150),
      });

      throw err;
    }
  }

  private parseResults(stdout: string, repoPath: string): GitHubScanResult[] {
    const results: GitHubScanResult[] = [];

    if (!stdout.trim()) {
      console.log('[GitHub Scanner] No output from Semgrep');
      return results;
    }

    let jsonOutput: any;
    try {
      jsonOutput = JSON.parse(stdout);
    } catch (err) {
      console.error('[GitHub Scanner] Failed to parse JSON:', err);
      console.error('[GitHub Scanner] Raw output (first 1000 chars):', stdout.slice(0, 1000));
      return results;
    }

    // Process results
    if (jsonOutput.results && Array.isArray(jsonOutput.results)) {
      for (const result of jsonOutput.results) {
        // Read code context
        let code = '';
        try {
          const fileContent = fs.readFileSync(result.path, 'utf-8');
          const lines = fileContent.split('\n');
          const startLine = Math.max(0, (result.start?.line || 1) - 4);
          const endLine = Math.min(lines.length, (result.end?.line || result.start?.line || 1) + 3);
          code = lines.slice(startLine, endLine).join('\n');
        } catch {
          code = result.extra?.lines || '';
        }

        const metadata = result.extra?.metadata || {};
        const ruleId = result.check_id || 'unknown';
        
        results.push({
          id: `gh-${Date.now()}-${results.length}`,
          ruleId,
          severity: this.mapSeverity(result.extra?.severity),
          confidence: this.mapConfidence(metadata.confidence),
          message: result.extra?.message || ruleId,
          file: path.relative(repoPath, result.path),
          line: result.start?.line || 1,
          endLine: result.end?.line || result.start?.line || 1,
          column: result.start?.col || 1,
          endColumn: result.end?.col || 1,
          code,
          category: metadata.category || 'security',
          cweIds: metadata.cwe ? [metadata.cwe] : [],
          owaspIds: metadata.owasp ? [metadata.owasp] : [],
          fix: metadata.fix,
          references: metadata.references,
          dataflowTrace: result.extra?.dataflow_trace?.intermediate_vars?.map(
            (v: any) => `${v.location?.path}:${v.location?.start?.line}`
          ),
        });
      }
    }

    // Log errors from Semgrep
    if (jsonOutput.errors?.length > 0) {
      console.warn('[GitHub Scanner] Semgrep reported', jsonOutput.errors.length, 'errors');
      jsonOutput.errors.slice(0, 5).forEach((err: any) => {
        console.warn('  -', err.message || JSON.stringify(err).slice(0, 100));
      });
    }

    return results;
  }

  private mapSeverity(severity?: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
    const s = (severity || '').toUpperCase();
    if (s === 'ERROR' || s === 'CRITICAL') return 'CRITICAL';
    if (s === 'WARNING' || s === 'HIGH') return 'HIGH';
    if (s === 'INFO') return 'INFO';
    if (s === 'LOW') return 'LOW';
    return 'MEDIUM';
  }

  private mapConfidence(confidence?: string): 'HIGH' | 'MEDIUM' | 'LOW' {
    const c = (confidence || '').toUpperCase();
    if (c === 'HIGH' || c === 'VERY-HIGH') return 'HIGH';
    if (c === 'LOW') return 'LOW';
    return 'MEDIUM';
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // PUBLIC API
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  async scan(
    options: GitHubScanOptions,
    onProgress?: (progress: GitHubScanProgress) => void
  ): Promise<GitHubScanResult[]> {
    let repoPath: string | null = null;

    try {
      // Clone repository
      repoPath = await this.cloneRepository(options.repoUrl, options, onProgress);

      // Analyze repository structure
      const analysis = this.analyzeRepository(repoPath, options, onProgress);

      if (analysis.scannableFiles === 0) {
        onProgress?.({
          stage: 'complete',
          message: 'No scannable files found in repository',
          progress: 100,
          totalFiles: 0,
        });
        return [];
      }

      // Run Semgrep scan
      const results = await this.runScan(repoPath, options, analysis, onProgress);

      return results;

    } finally {
      // Cleanup cloned repository
      if (repoPath && fs.existsSync(repoPath)) {
        try {
          fs.rmSync(repoPath, { recursive: true, force: true });
          console.log('[GitHub Scanner] Cleaned up:', repoPath);
        } catch (err) {
          console.warn('[GitHub Scanner] Cleanup failed:', err);
        }
      }
    }
  }

  cleanup(): void {
    try {
      if (fs.existsSync(this.tempDir)) {
        fs.rmSync(this.tempDir, { recursive: true, force: true });
        console.log('[GitHub Scanner] Full cleanup complete');
      }
    } catch (err) {
      console.warn('[GitHub Scanner] Cleanup error:', err);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════════════════════

export const githubScanner = new GitHubScanner();

export async function scanGitHubRepo(
  options: GitHubScanOptions,
  onProgress?: (progress: GitHubScanProgress) => void
): Promise<GitHubScanResult[]> {
  return githubScanner.scan(options, onProgress);
}

export function getDefaultWeb3Rules(): string {
  return WEB3_SEMGREP_RULES;
}
