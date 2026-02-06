import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { exec, execSync } from 'child_process';
import { getUserDataPath } from './app-paths';
import { promisify } from 'util';
import * as forge from 'node-forge';
import * as https from 'https';
import * as tls from 'tls';

const execAsync = promisify(exec);

export interface CertificateInfo {
  cert: string;
  key: string;
  certPath: string;
  keyPath: string;
  expiresAt?: Date;
  issuedAt?: Date;
  subject?: string;
  issuer?: string;
  serialNumber?: string;
}

export interface CertificateStatus {
  exists: boolean;
  valid: boolean;
  expiresAt?: Date;
  daysUntilExpiry?: number;
  isExpired?: boolean;
  isTrusted?: boolean;
  error?: string;
}

export class CertificateManager {
  private certDir: string;
  private certPath: string;
  private keyPath: string;
  private hostCertCache: Map<string, CertificateInfo> = new Map();
  private caCert: forge.pki.Certificate | null = null;
  private caKey: forge.pki.PrivateKey | null = null;

  constructor() {
    this.certDir = path.join(getUserDataPath(), 'certs');
    this.certPath = path.join(this.certDir, 'ca.crt');
    this.keyPath = path.join(this.certDir, 'ca.key');

    if (!fs.existsSync(this.certDir)) {
      fs.mkdirSync(this.certDir, { recursive: true });
    }
    if (!fs.existsSync(this.certPath) || !fs.existsSync(this.keyPath)) {
      this.migrateLegacyCerts();
    }
  }

  private migrateLegacyCerts(): void {
    const home = os.homedir();
    const legacyPaths = [
      process.platform === 'win32' ? path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), '.sec-toolkit') : null,
      path.join(home, '.sec-toolkit'),
    ].filter(Boolean) as string[];
    for (const legacy of legacyPaths) {
      const oldCrt = path.join(legacy, 'ca.crt');
      const oldKey = path.join(legacy, 'ca.key');
      if (fs.existsSync(oldCrt) && fs.existsSync(oldKey)) {
        try {
          fs.copyFileSync(oldCrt, this.certPath);
          fs.copyFileSync(oldKey, this.keyPath);
          console.log('[CertManager] Migrated certs from legacy path');
          break;
        } catch (e) {
          console.warn('[CertManager] Legacy cert migration failed:', (e as Error).message);
        }
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // CERTIFICATE GENERATION
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  async generateCertificate(force: boolean = false): Promise<CertificateInfo> {
    // Check if certificate already exists (unless force regeneration)
    if (!force && fs.existsSync(this.certPath) && fs.existsSync(this.keyPath)) {
      const status = await this.getCertificateStatus();
      if (status.valid && !status.isExpired) {
        return this.getCertificateInfo();
      }
    }

    console.log('[CertManager] Generating new CA certificate...');

    // Generate CA certificate (root certificate) using node-forge
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    
    cert.publicKey = keys.publicKey;
    cert.serialNumber = this.generateSerialNumber();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 2); // 2 years validity
    
    const attrs = [
      { name: 'commonName', value: 'CleanTraffic Security CA' },
      { name: 'organizationName', value: 'CleanTraffic' },
      { name: 'organizationalUnitName', value: 'Security Testing' },
      { name: 'countryName', value: 'US' },
    ];
    
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    
    // Add extensions for CA - must be a proper root CA
    cert.setExtensions([
      {
        name: 'basicConstraints',
        cA: true,
        pathLenConstraint: 0,
        critical: true,
      },
      {
        name: 'keyUsage',
        keyCertSign: true,
        cRLSign: true,
        digitalSignature: true,
        critical: true,
      },
      {
        name: 'subjectKeyIdentifier',
      },
      {
        name: 'authorityKeyIdentifier',
        keyIdentifier: true,
      },
    ]);
    
    // Sign the certificate with SHA-256
    cert.sign(keys.privateKey, forge.md.sha256.create());
    
    // Convert to PEM format
    const certPem = forge.pki.certificateToPem(cert);
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
    
    // Save certificate and key
    fs.writeFileSync(this.certPath, certPem);
    fs.writeFileSync(this.keyPath, keyPem, { mode: 0o600 }); // Restrict key permissions

    // Cache the CA cert and key
    this.caCert = cert;
    this.caKey = keys.privateKey;

    console.log('[CertManager] CA certificate generated successfully');
    console.log(`[CertManager] Certificate path: ${this.certPath}`);
    console.log(`[CertManager] Expires: ${cert.validity.notAfter.toISOString()}`);

    return {
      cert: certPem,
      key: keyPem,
      certPath: this.certPath,
      keyPath: this.keyPath,
      expiresAt: cert.validity.notAfter,
      issuedAt: cert.validity.notBefore,
      subject: 'CleanTraffic Security CA',
      issuer: 'CleanTraffic Security CA',
      serialNumber: cert.serialNumber,
    };
  }

  /**
   * Generate a cryptographically secure serial number
   */
  private generateSerialNumber(): string {
    const bytes = forge.random.getBytesSync(16);
    return forge.util.bytesToHex(bytes);
  }

  /**
   * Generate a certificate for a specific hostname (for MITM)
   */
  async generateCertificateForHost(hostname: string): Promise<CertificateInfo> {
    // Check cache first
    if (this.hostCertCache.has(hostname)) {
      return this.hostCertCache.get(hostname)!;
    }

    // Ensure CA is loaded
    await this.loadCA();

    if (!this.caCert || !this.caKey) {
      throw new Error('CA certificate not loaded');
    }

    console.log(`[CertManager] Generating certificate for: ${hostname}`);
    
    // Generate a certificate signed by our CA for this hostname
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    
    cert.publicKey = keys.publicKey;
    cert.serialNumber = this.generateSerialNumber();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + 1);
    
    // Extract base domain for wildcard
    const parts = hostname.split('.');
    const baseDomain = parts.length >= 2 
      ? parts.slice(-2).join('.') 
      : hostname;
    
    const attrs = [
      { name: 'commonName', value: hostname },
      { name: 'organizationName', value: 'CleanTraffic' },
      { name: 'organizationalUnitName', value: 'MITM Proxy' },
      { name: 'countryName', value: 'US' },
    ];
    
    cert.setSubject(attrs);
    cert.setIssuer(this.caCert.subject.attributes);
    
    // Add subjectAltName extension with multiple DNS entries
    const altNames: any[] = [
      { type: 2, value: hostname }, // DNS
    ];
    
    // Add wildcard for subdomains if applicable
    if (baseDomain !== hostname && parts.length > 2) {
      altNames.push({ type: 2, value: `*.${baseDomain}` });
    }
    
    // Also add the bare domain
    if (parts.length >= 2) {
      altNames.push({ type: 2, value: baseDomain });
      altNames.push({ type: 2, value: `*.${baseDomain}` });
    }
    
    cert.setExtensions([
      {
        name: 'basicConstraints',
        cA: false,
        critical: true,
      },
      {
        name: 'keyUsage',
        digitalSignature: true,
        keyEncipherment: true,
        keyAgreement: true,
        critical: true,
      },
      {
        name: 'extKeyUsage',
        serverAuth: true,
        clientAuth: true,
      },
      {
        name: 'subjectAltName',
        altNames: altNames,
        critical: false,
      },
      {
        name: 'subjectKeyIdentifier',
      },
      {
        name: 'authorityKeyIdentifier',
        keyIdentifier: true,
      },
    ]);
    
    // Sign the certificate with CA key using SHA-256
    cert.sign(this.caKey as forge.pki.rsa.PrivateKey, forge.md.sha256.create());
    
    // Convert to PEM format
    const certPem = forge.pki.certificateToPem(cert);
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
    
    const certInfo: CertificateInfo = {
      cert: certPem,
      key: keyPem,
      certPath: this.certPath,
      keyPath: this.keyPath,
      expiresAt: cert.validity.notAfter,
      issuedAt: cert.validity.notBefore,
      subject: hostname,
      issuer: 'CleanTraffic Security CA',
      serialNumber: cert.serialNumber,
    };

    // Cache it
    this.hostCertCache.set(hostname, certInfo);
    return certInfo;
  }

  /**
   * Load CA certificate and key into memory
   */
  private async loadCA(): Promise<void> {
    if (this.caCert && this.caKey) {
      return; // Already loaded
    }

    const caInfo = await this.getCertificateInfo();
    this.caCert = forge.pki.certificateFromPem(caInfo.cert);
    this.caKey = forge.pki.privateKeyFromPem(caInfo.key);
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // CERTIFICATE INFO & STATUS
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  async getCertificateInfo(): Promise<CertificateInfo> {
    if (!fs.existsSync(this.certPath) || !fs.existsSync(this.keyPath)) {
      return await this.generateCertificate();
    }

    const certPem = fs.readFileSync(this.certPath, 'utf8');
    const keyPem = fs.readFileSync(this.keyPath, 'utf8');
    
    // Parse certificate to get metadata
    try {
      const cert = forge.pki.certificateFromPem(certPem);
      return {
        cert: certPem,
        key: keyPem,
        certPath: this.certPath,
        keyPath: this.keyPath,
        expiresAt: cert.validity.notAfter,
        issuedAt: cert.validity.notBefore,
        subject: cert.subject.getField('CN')?.value || 'Unknown',
        issuer: cert.issuer.getField('CN')?.value || 'Unknown',
        serialNumber: cert.serialNumber,
      };
    } catch (error) {
      // Return basic info if parsing fails
      return {
        cert: certPem,
        key: keyPem,
        certPath: this.certPath,
        keyPath: this.keyPath,
      };
    }
  }

  async getCertificateStatus(): Promise<CertificateStatus> {
    if (!fs.existsSync(this.certPath) || !fs.existsSync(this.keyPath)) {
      return {
        exists: false,
        valid: false,
        error: 'Certificate files not found',
      };
    }

    try {
      const certPem = fs.readFileSync(this.certPath, 'utf8');
      const cert = forge.pki.certificateFromPem(certPem);
      
      const now = new Date();
      const expiresAt = cert.validity.notAfter;
      const daysUntilExpiry = Math.floor((expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      const isExpired = now > expiresAt;

      // Check if certificate is trusted by the system
      const isTrusted = await this.checkSystemTrust();

      return {
        exists: true,
        valid: !isExpired,
        expiresAt,
        daysUntilExpiry,
        isExpired,
        isTrusted,
      };
    } catch (error) {
      return {
        exists: true,
        valid: false,
        error: `Failed to parse certificate: ${(error as Error).message}`,
      };
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // SYSTEM TRUST INSTALLATION
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  /**
   * Install root CA certificate into system trust store
   */
  async installToSystemTrust(): Promise<{ success: boolean; message: string }> {
    const platform = process.platform;

    try {
      // Ensure certificate exists
      if (!fs.existsSync(this.certPath)) {
        await this.generateCertificate();
      }

      if (platform === 'win32') {
        return await this.installToWindowsTrust();
      } else if (platform === 'darwin') {
        return await this.installToMacOSTrust();
      } else if (platform === 'linux') {
        return await this.installToLinuxTrust();
      } else {
        return {
          success: false,
          message: `Unsupported platform: ${platform}. Please install the certificate manually.`,
        };
      }
    } catch (error) {
      return {
        success: false,
        message: `Failed to install certificate: ${(error as Error).message}`,
      };
    }
  }

  /**
   * Windows: Install using certutil
   */
  private async installToWindowsTrust(): Promise<{ success: boolean; message: string }> {
    try {
      // Add to Trusted Root Certification Authorities
      const cmd = `certutil -addstore -user Root "${this.certPath}"`;
      await execAsync(cmd);
      
      console.log('[CertManager] Certificate installed to Windows trust store');
      return {
        success: true,
        message: 'Certificate installed to Windows User Trust Store. You may need to restart your browser.',
      };
    } catch (error: any) {
      // Try with admin privileges hint
      if (error.message?.includes('Access is denied')) {
        return {
          success: false,
          message: 'Administrator privileges required. Please run CleanTraffic as Administrator, or install manually via certmgr.msc',
        };
      }
      throw error;
    }
  }

  /**
   * macOS: Install using security command
   */
  private async installToMacOSTrust(): Promise<{ success: boolean; message: string }> {
    try {
      // Add to user keychain and trust it
      const cmd = `security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db "${this.certPath}"`;
      await execAsync(cmd);
      
      console.log('[CertManager] Certificate installed to macOS Keychain');
      return {
        success: true,
        message: 'Certificate installed to macOS Keychain. You may need to restart your browser.',
      };
    } catch (error: any) {
      if (error.message?.includes('User interaction is not allowed')) {
        return {
          success: false,
          message: 'Please enter your password when prompted, or install manually via Keychain Access.app',
        };
      }
      throw error;
    }
  }

  /**
   * Linux: Copy to ca-certificates directory
   */
  private async installToLinuxTrust(): Promise<{ success: boolean; message: string }> {
    try {
      const destPath = '/usr/local/share/ca-certificates/cleantraffic-ca.crt';
      
      // Copy certificate (requires sudo)
      await execAsync(`sudo cp "${this.certPath}" "${destPath}"`);
      await execAsync('sudo update-ca-certificates');
      
      console.log('[CertManager] Certificate installed to Linux trust store');
      return {
        success: true,
        message: 'Certificate installed to Linux trust store. You may need to restart your browser.',
      };
    } catch (error: any) {
      if (error.message?.includes('sudo') || error.message?.includes('permission')) {
        return {
          success: false,
          message: `Please run with sudo, or manually copy ${this.certPath} to /usr/local/share/ca-certificates/ and run update-ca-certificates`,
        };
      }
      throw error;
    }
  }

  /**
   * Check if certificate is trusted by the system
   */
  private async checkSystemTrust(): Promise<boolean> {
    const platform = process.platform;

    try {
      if (platform === 'win32') {
        const { stdout } = await execAsync(`certutil -store -user Root "CleanTraffic Security CA"`);
        return stdout.includes('CleanTraffic');
      } else if (platform === 'darwin') {
        const { stdout } = await execAsync(`security find-certificate -c "CleanTraffic" -a`);
        return stdout.includes('CleanTraffic');
      } else if (platform === 'linux') {
        return fs.existsSync('/usr/local/share/ca-certificates/cleantraffic-ca.crt');
      }
    } catch {
      // If command fails, assume not trusted
    }

    return false;
  }

  /**
   * Remove certificate from system trust store
   */
  async removeFromSystemTrust(): Promise<{ success: boolean; message: string }> {
    const platform = process.platform;

    try {
      if (platform === 'win32') {
        await execAsync(`certutil -delstore -user Root "CleanTraffic Security CA"`);
      } else if (platform === 'darwin') {
        await execAsync(`security delete-certificate -c "CleanTraffic Security CA"`);
      } else if (platform === 'linux') {
        await execAsync('sudo rm -f /usr/local/share/ca-certificates/cleantraffic-ca.crt');
        await execAsync('sudo update-ca-certificates');
      }

      return {
        success: true,
        message: 'Certificate removed from system trust store.',
      };
    } catch (error) {
      return {
        success: false,
        message: `Failed to remove certificate: ${(error as Error).message}`,
      };
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // TLS CONTEXT FOR PROXY
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  /**
   * Get TLS options for creating HTTPS server
   */
  async getTLSOptions(): Promise<https.ServerOptions> {
    const caInfo = await this.getCertificateInfo();
    return {
      key: caInfo.key,
      cert: caInfo.cert,
    };
  }

  /**
   * Create a TLS SNI callback for dynamic certificate generation
   * Used by network proxy for MITM
   */
  createSNICallback(): (servername: string, cb: (err: Error | null, ctx?: tls.SecureContext) => void) => void {
    return async (servername: string, cb: (err: Error | null, ctx?: tls.SecureContext) => void) => {
      try {
        const hostCert = await this.generateCertificateForHost(servername);
        const ctx = tls.createSecureContext({
          key: hostCert.key,
          cert: hostCert.cert,
        });
        cb(null, ctx);
      } catch (error) {
        console.error(`[CertManager] Failed to generate cert for ${servername}:`, error);
        cb(error as Error);
      }
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════════════════════════
  // UTILITY METHODS
  // ═══════════════════════════════════════════════════════════════════════════════════════════════

  getCertificatePath(): string {
    return this.certPath;
  }

  getKeyPath(): string {
    return this.keyPath;
  }

  getCertDir(): string {
    return this.certDir;
  }

  /**
   * Clear the host certificate cache
   */
  clearHostCertCache(): void {
    this.hostCertCache.clear();
    console.log('[CertManager] Host certificate cache cleared');
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { cachedHosts: number; hostnames: string[] } {
    return {
      cachedHosts: this.hostCertCache.size,
      hostnames: Array.from(this.hostCertCache.keys()),
    };
  }

  /**
   * Open certificate directory in file explorer
   */
  async openCertificateLocation(): Promise<void> {
    const platform = process.platform;
    
    try {
      if (platform === 'win32') {
        await execAsync(`explorer "${this.certDir}"`);
      } else if (platform === 'darwin') {
        await execAsync(`open "${this.certDir}"`);
      } else {
        await execAsync(`xdg-open "${this.certDir}"`);
      }
    } catch (error) {
      console.error('[CertManager] Failed to open certificate location:', error);
    }
  }

  /**
   * Export certificate as DER format (for mobile devices)
   */
  async exportAsDER(): Promise<string> {
    const derPath = path.join(this.certDir, 'ca.der');
    
    const certInfo = await this.getCertificateInfo();
    const cert = forge.pki.certificateFromPem(certInfo.cert);
    const asn1 = forge.pki.certificateToAsn1(cert);
    const der = forge.asn1.toDer(asn1).getBytes();
    
    fs.writeFileSync(derPath, Buffer.from(der, 'binary'));
    
    return derPath;
  }

  /**
   * Get certificate fingerprint (SHA-256)
   */
  async getFingerprint(): Promise<string> {
    const certInfo = await this.getCertificateInfo();
    const cert = forge.pki.certificateFromPem(certInfo.cert);
    const asn1 = forge.pki.certificateToAsn1(cert);
    const der = forge.asn1.toDer(asn1).getBytes();
    const md = forge.md.sha256.create();
    md.update(der);
    const fingerprint = md.digest().toHex();
    
    // Format as colon-separated pairs
    return fingerprint.match(/.{2}/g)?.join(':').toUpperCase() || fingerprint;
  }
}
