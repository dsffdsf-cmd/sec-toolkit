/**
 * CleanTraffic - Web3 Security Tools (local use only; no mainnet integration settings)
 * Transaction Decoder, Signature Analyzer, Contract Inspector
 */

import React, { useState } from 'react';
import Editor from '@monaco-editor/react';
import './Web3Tools.css';

/** Local RPC presets for Web3 tools only – not persisted in Settings */
const LOCAL_RPC_PRESETS = [
  { id: 'eth', name: 'Ethereum', rpcUrl: 'https://eth.llamarpc.com' },
  { id: 'sepolia', name: 'Sepolia', rpcUrl: 'https://rpc.sepolia.org' },
  { id: 'polygon', name: 'Polygon', rpcUrl: 'https://polygon-rpc.com' },
];
const DEFAULT_RPC = LOCAL_RPC_PRESETS[0].rpcUrl;

// Types
interface DecodedArg {
  name: string;
  type: string;
  value: string;
}

interface DecodedTransaction {
  to: string;
  from?: string;
  value: string;
  valueEth: string;
  data: string;
  functionName?: string;
  functionSignature?: string;
  decodedArgs?: DecodedArg[];
  isContractCreation: boolean;
  warnings: string[];
}

interface EIP712Message {
  domain: {
    name?: string;
    version?: string;
    chainId?: number;
    verifyingContract?: string;
  };
  primaryType: string;
  types: Record<string, { name: string; type: string }[]>;
  message: Record<string, any>;
  warnings: string[];
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

interface ContractInfo {
  address: string;
  isContract: boolean;
  isProxy: boolean;
  proxyType?: string;
  implementation?: string;
  admin?: string;
  beacon?: string;
  bytecodeHash?: string;
}

interface StorageSlot {
  slot: string;
  value: string;
  decoded?: string;
  label?: string;
}

type ToolTab = 'decoder' | 'signature' | 'contract' | 'storage' | 'encoder' | 'security';

interface SecurityFinding {
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
}

interface SecurityResult {
  findings: SecurityFinding[];
  stats: { critical: number; high: number; medium: number; low: number; info: number };
  analyzedAt: number;
}

const Web3Tools: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ToolTab>('decoder');
  const [rpcPresetId, setRpcPresetId] = useState(LOCAL_RPC_PRESETS[0].id);
  const [rpcUrl, setRpcUrl] = useState(DEFAULT_RPC);

  const handleRpcPresetChange = (id: string) => {
    setRpcPresetId(id);
    const preset = LOCAL_RPC_PRESETS.find((p) => p.id === id);
    if (preset) setRpcUrl(preset.rpcUrl);
  };

  // Transaction Decoder State
  const [txInput, setTxInput] = useState('');
  const [decodedTx, setDecodedTx] = useState<DecodedTransaction | null>(null);

  // Signature Analyzer State
  const [sigInput, setSigInput] = useState('');
  const [analyzedSig, setAnalyzedSig] = useState<EIP712Message | null>(null);

  // Contract Inspector State
  const [contractAddress, setContractAddress] = useState('');
  const [contractInfo, setContractInfo] = useState<ContractInfo | null>(null);
  const [isLoadingContract, setIsLoadingContract] = useState(false);
  
  // Storage Slot Reader State
  const [storageAddress, setStorageAddress] = useState('');
  const [storageSlot, setStorageSlot] = useState('');
  const [storageResult, setStorageResult] = useState<StorageSlot | null>(null);
  const [commonSlots, setCommonSlots] = useState<StorageSlot[]>([]);

  // Encoder/Decoder State
  const [encodeMode, setEncodeMode] = useState<'keccak' | 'selector' | 'checksum' | 'hex' | 'units' | 'abi'>('keccak');
  const [encodeInput, setEncodeInput] = useState('');
  const [encodeInput2, setEncodeInput2] = useState('');
  const [encodeResult, setEncodeResult] = useState<{ success: boolean; result?: string; error?: string } | null>(null);

  // Security Analyzer State
  const [securityCode, setSecurityCode] = useState('');
  const [securityResult, setSecurityResult] = useState<SecurityResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [regexInput, setRegexInput] = useState('');
  const [regexResult, setRegexResult] = useState<any>(null);

  // Decode transaction
  const handleDecodeTx = async () => {
    if (!txInput.trim()) return;
    
    try {
      let txData: any;
      
      // Try to parse as JSON first
      try {
        txData = JSON.parse(txInput);
      } catch {
        // If not JSON, treat as raw calldata
        txData = { data: txInput.trim() };
      }

      const result = await window.electronAPI.web3DecodeTransaction(txData);
      setDecodedTx(result);
    } catch (error) {
      console.error('Decode error:', error);
      setDecodedTx({
        to: '',
        value: '0',
        valueEth: '0',
        data: txInput,
        isContractCreation: false,
        warnings: [`Error: ${(error as Error).message}`],
      });
    }
  };

  // Analyze EIP-712 signature
  const handleAnalyzeSig = async () => {
    if (!sigInput.trim()) return;
    
    try {
      const typedData = JSON.parse(sigInput);
      const result = await window.electronAPI.web3AnalyzeSignature(typedData);
      setAnalyzedSig(result);
    } catch (error) {
      console.error('Signature analysis error:', error);
      setAnalyzedSig({
        domain: {},
        primaryType: 'Error',
        types: {},
        message: {},
        warnings: [`Parse error: ${(error as Error).message}`],
        riskLevel: 'HIGH',
      });
    }
  };

  // Inspect contract
  const handleInspectContract = async () => {
    if (!contractAddress.trim()) return;
    
    setIsLoadingContract(true);
    try {
      const result = await window.electronAPI.web3InspectContract(contractAddress, rpcUrl);
      setContractInfo(result);
      
      // If it's a proxy, auto-read common slots
      if (result.isProxy) {
        await readCommonSlots(contractAddress);
      }
    } catch (error) {
      console.error('Contract inspection error:', error);
      setContractInfo({
        address: contractAddress,
        isContract: false,
        isProxy: false,
      });
    } finally {
      setIsLoadingContract(false);
    }
  };

  // Read storage slot
  const handleReadSlot = async () => {
    if (!storageAddress.trim() || !storageSlot.trim()) return;
    
    try {
      const result = await window.electronAPI.web3ReadStorageSlot(storageAddress, storageSlot, rpcUrl);
      setStorageResult(result);
    } catch (error) {
      console.error('Storage read error:', error);
      setStorageResult({
        slot: storageSlot,
        value: `Error: ${(error as Error).message}`,
      });
    }
  };

  // Read common proxy slots
  const readCommonSlots = async (address: string) => {
    const slots = [
      { name: 'Implementation (EIP-1967)', slot: '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc' },
      { name: 'Admin (EIP-1967)', slot: '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103' },
      { name: 'Beacon (EIP-1967)', slot: '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50' },
    ];

    const results: StorageSlot[] = [];
    for (const s of slots) {
      try {
        const result = await window.electronAPI.web3ReadStorageSlot(address, s.slot, rpcUrl);
        results.push({ ...result, label: s.name });
      } catch {}
    }
    setCommonSlots(results);
  };

  // Get risk level color
  const getRiskColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return '#ff4444';
      case 'HIGH': return '#ff8844';
      case 'MEDIUM': return '#ffaa44';
      case 'LOW': return '#44aa44';
      default: return '#888';
    }
  };

  return (
    <div className="web3-tools">
      {/* Header */}
      <div className="web3-header">
        <h2>Web3 Security Tools</h2>
        <span className="web3-subtitle">Transaction Decoder • Signature Analyzer • Contract Inspector</span>
      </div>

      {/* Tab Navigation */}
      <div className="web3-tabs">
        <button 
          className={`web3-tab ${activeTab === 'decoder' ? 'active' : ''}`}
          onClick={() => setActiveTab('decoder')}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="3" width="18" height="18" rx="2" />
            <path d="M9 9h6M9 12h6M9 15h4" />
          </svg>
          TX Decoder
        </button>
        <button 
          className={`web3-tab ${activeTab === 'signature' ? 'active' : ''}`}
          onClick={() => setActiveTab('signature')}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 19l7-7 3 3-7 7-3-3z" />
            <path d="M18 13l-1.5-7.5L2 2l3.5 14.5L13 18l5-5z" />
            <path d="M2 2l7.586 7.586" />
          </svg>
          Signature
        </button>
        <button 
          className={`web3-tab ${activeTab === 'contract' ? 'active' : ''}`}
          onClick={() => setActiveTab('contract')}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
            <line x1="16" y1="13" x2="8" y2="13" />
            <line x1="16" y1="17" x2="8" y2="17" />
          </svg>
          Contract
        </button>
        <button 
          className={`web3-tab ${activeTab === 'storage' ? 'active' : ''}`}
          onClick={() => setActiveTab('storage')}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <ellipse cx="12" cy="5" rx="9" ry="3" />
            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
          </svg>
          Storage
        </button>
        <button 
          className={`web3-tab ${activeTab === 'encoder' ? 'active' : ''}`}
          onClick={() => setActiveTab('encoder')}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="16 18 22 12 16 6" />
            <polyline points="8 6 2 12 8 18" />
          </svg>
          Encoder
        </button>
        <button 
          className={`web3-tab ${activeTab === 'security' ? 'active' : ''}`}
          onClick={() => setActiveTab('security')}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
          Security
        </button>
      </div>

      {/* Tab Content */}
      <div className="web3-content">
        {/* Transaction Decoder */}
        {activeTab === 'decoder' && (
          <div className="tool-panel">
            <div className="tool-section">
              <label>Transaction Data / Calldata</label>
              <textarea
                className="web3-input"
                value={txInput}
                onChange={(e) => setTxInput(e.target.value)}
                placeholder='Paste transaction JSON or raw calldata (0x...)'
                rows={6}
              />
              <button className="web3-btn primary" onClick={handleDecodeTx}>
                Decode Transaction
              </button>
            </div>

            {decodedTx && (
              <div className="tool-result">
                <h3>Decoded Result</h3>
                
                {/* Warnings */}
                {decodedTx.warnings.length > 0 && (
                  <div className="warnings-box">
                    {decodedTx.warnings.map((w, i) => (
                      <div key={i} className="warning-item">{w}</div>
                    ))}
                  </div>
                )}

                {/* Function Info */}
                {decodedTx.functionName && (
                  <div className="info-row">
                    <span className="info-label">Function</span>
                    <span className="info-value fn-name">{decodedTx.functionName}</span>
                  </div>
                )}

                {decodedTx.functionSignature && (
                  <div className="info-row">
                    <span className="info-label">Signature</span>
                    <code className="info-value">{decodedTx.functionSignature}</code>
                  </div>
                )}

                {decodedTx.to && (
                  <div className="info-row">
                    <span className="info-label">To</span>
                    <code className="info-value address">{decodedTx.to}</code>
                  </div>
                )}

                {decodedTx.valueEth !== '0' && (
                  <div className="info-row">
                    <span className="info-label">Value</span>
                    <span className="info-value">{decodedTx.valueEth} ETH</span>
                  </div>
                )}

                {/* Decoded Arguments */}
                {decodedTx.decodedArgs && decodedTx.decodedArgs.length > 0 && (
                  <div className="args-section">
                    <h4>Arguments</h4>
                    <div className="args-list">
                      {decodedTx.decodedArgs.map((arg, i) => (
                        <div key={i} className="arg-item">
                          <span className="arg-name">{arg.name}</span>
                          <span className="arg-type">{arg.type}</span>
                          <code className="arg-value">{arg.value}</code>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Raw Data */}
                <div className="raw-section">
                  <h4>Raw Calldata</h4>
                  <Editor
                    height="100px"
                    language="plaintext"
                    value={decodedTx.data}
                    theme="vs-dark"
                    options={{
                      readOnly: true,
                      minimap: { enabled: false },
                      fontSize: 11,
                      wordWrap: 'on',
                      scrollBeyondLastLine: false,
                    }}
                  />
                </div>
              </div>
            )}
          </div>
        )}

        {/* Signature Analyzer */}
        {activeTab === 'signature' && (
          <div className="tool-panel">
            <div className="tool-section">
              <label>EIP-712 Typed Data (JSON)</label>
              <textarea
                className="web3-input"
                value={sigInput}
                onChange={(e) => setSigInput(e.target.value)}
                placeholder='Paste EIP-712 typed data JSON...'
                rows={8}
              />
              <button className="web3-btn primary" onClick={handleAnalyzeSig}>
                Analyze Signature
              </button>
            </div>

            {analyzedSig && (
              <div className="tool-result">
                <h3>
                  Signature Analysis
                  <span 
                    className="risk-badge"
                    style={{ backgroundColor: getRiskColor(analyzedSig.riskLevel) }}
                  >
                    {analyzedSig.riskLevel} RISK
                  </span>
                </h3>

                {/* Warnings */}
                {analyzedSig.warnings.length > 0 && (
                  <div className="warnings-box">
                    {analyzedSig.warnings.map((w, i) => (
                      <div key={i} className="warning-item">{w}</div>
                    ))}
                  </div>
                )}

                {/* Domain Info */}
                <div className="section-box">
                  <h4>Domain</h4>
                  {analyzedSig.domain.name && (
                    <div className="info-row">
                      <span className="info-label">Name</span>
                      <span className="info-value">{analyzedSig.domain.name}</span>
                    </div>
                  )}
                  {analyzedSig.domain.version && (
                    <div className="info-row">
                      <span className="info-label">Version</span>
                      <span className="info-value">{analyzedSig.domain.version}</span>
                    </div>
                  )}
                  {analyzedSig.domain.chainId && (
                    <div className="info-row">
                      <span className="info-label">Chain ID</span>
                      <span className="info-value">{analyzedSig.domain.chainId}</span>
                    </div>
                  )}
                  {analyzedSig.domain.verifyingContract && (
                    <div className="info-row">
                      <span className="info-label">Contract</span>
                      <code className="info-value address">{analyzedSig.domain.verifyingContract}</code>
                    </div>
                  )}
                </div>

                {/* Message */}
                <div className="section-box">
                  <h4>Message ({analyzedSig.primaryType})</h4>
                  <Editor
                    height="150px"
                    language="json"
                    value={JSON.stringify(analyzedSig.message, null, 2)}
                    theme="vs-dark"
                    options={{
                      readOnly: true,
                      minimap: { enabled: false },
                      fontSize: 11,
                      scrollBeyondLastLine: false,
                    }}
                  />
                </div>
              </div>
            )}
          </div>
        )}

        {/* Contract Inspector */}
        {activeTab === 'contract' && (
          <div className="tool-panel">
            <div className="tool-section">
              <label>Contract Address</label>
              <input
                type="text"
                className="web3-input-field"
                value={contractAddress}
                onChange={(e) => setContractAddress(e.target.value)}
                placeholder="0x..."
              />
              
              <label>RPC</label>
              <select
                className="web3-select"
                value={rpcPresetId}
                onChange={(e) => handleRpcPresetChange(e.target.value)}
              >
                {LOCAL_RPC_PRESETS.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
              <label className="web3-input-hint">RPC URL</label>
              <input
                type="url"
                className="web3-input-field"
                value={rpcUrl}
                onChange={(e) => setRpcUrl(e.target.value)}
                placeholder="https://..."
              />
              
              <button 
                className="web3-btn primary" 
                onClick={handleInspectContract}
                disabled={isLoadingContract}
              >
                {isLoadingContract ? 'Inspecting...' : 'Inspect Contract'}
              </button>
            </div>

            {contractInfo && (
              <div className="tool-result">
                <h3>Contract Info</h3>
                
                <div className="info-row">
                  <span className="info-label">Address</span>
                  <code className="info-value address">{contractInfo.address}</code>
                </div>

                <div className="info-row">
                  <span className="info-label">Is Contract</span>
                  <span className={`info-value ${contractInfo.isContract ? 'yes' : 'no'}`}>
                    {contractInfo.isContract ? 'Yes ✓' : 'No (EOA)'}
                  </span>
                </div>

                {contractInfo.isContract && (
                  <>
                    <div className="info-row">
                      <span className="info-label">Is Proxy</span>
                      <span className={`info-value ${contractInfo.isProxy ? 'yes' : 'no'}`}>
                        {contractInfo.isProxy ? `Yes - ${contractInfo.proxyType}` : 'No'}
                      </span>
                    </div>

                    {contractInfo.implementation && (
                      <div className="info-row highlight">
                        <span className="info-label">Implementation</span>
                        <code className="info-value address">{contractInfo.implementation}</code>
                      </div>
                    )}

                    {contractInfo.admin && (
                      <div className="info-row">
                        <span className="info-label">Admin</span>
                        <code className="info-value address">{contractInfo.admin}</code>
                      </div>
                    )}

                    {contractInfo.beacon && (
                      <div className="info-row">
                        <span className="info-label">Beacon</span>
                        <code className="info-value address">{contractInfo.beacon}</code>
                      </div>
                    )}

                    {contractInfo.bytecodeHash && (
                      <div className="info-row">
                        <span className="info-label">Bytecode Hash</span>
                        <code className="info-value small">{contractInfo.bytecodeHash}</code>
                      </div>
                    )}
                  </>
                )}

                {/* Common Slots */}
                {commonSlots.length > 0 && (
                  <div className="section-box">
                    <h4>Proxy Storage Slots</h4>
                    {commonSlots.map((slot, i) => (
                      <div key={i} className="slot-item">
                        <span className="slot-label">{slot.label}</span>
                        <code className="slot-value">{slot.decoded || slot.value}</code>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Storage Slot Reader */}
        {activeTab === 'storage' && (
          <div className="tool-panel">
            <div className="tool-section">
              <label>Contract Address</label>
              <input
                type="text"
                className="web3-input-field"
                value={storageAddress}
                onChange={(e) => setStorageAddress(e.target.value)}
                placeholder="0x..."
              />

              <label>Storage Slot</label>
              <input
                type="text"
                className="web3-input-field"
                value={storageSlot}
                onChange={(e) => setStorageSlot(e.target.value)}
                placeholder="0x0 or slot number"
              />

              <div className="quick-slots">
                <span>Quick:</span>
                <button onClick={() => setStorageSlot('0x0')}>Slot 0</button>
                <button onClick={() => setStorageSlot('0x1')}>Slot 1</button>
                <button onClick={() => setStorageSlot('0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc')}>
                  Impl
                </button>
                <button onClick={() => setStorageSlot('0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103')}>
                  Admin
                </button>
              </div>

              <button className="web3-btn primary" onClick={handleReadSlot}>
                Read Storage
              </button>
            </div>

            {storageResult && (
              <div className="tool-result">
                <h3>Storage Value</h3>
                
                <div className="info-row">
                  <span className="info-label">Slot</span>
                  <code className="info-value small">{storageResult.slot}</code>
                </div>

                {storageResult.label && (
                  <div className="info-row">
                    <span className="info-label">Type</span>
                    <span className="info-value">{storageResult.label}</span>
                  </div>
                )}

                <div className="info-row">
                  <span className="info-label">Raw Value</span>
                  <code className="info-value small">{storageResult.value}</code>
                </div>

                {storageResult.decoded && (
                  <div className="info-row highlight">
                    <span className="info-label">Decoded</span>
                    <code className="info-value address">{storageResult.decoded}</code>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Encoder/Decoder Utilities */}
        {activeTab === 'encoder' && (
          <div className="tool-panel">
            <div className="tool-section">
              <label>Encoding Mode</label>
              <div className="encode-modes">
                <button 
                  className={`encode-mode-btn ${encodeMode === 'keccak' ? 'active' : ''}`}
                  onClick={() => { setEncodeMode('keccak'); setEncodeResult(null); }}
                >
                  Keccak256
                </button>
                <button 
                  className={`encode-mode-btn ${encodeMode === 'selector' ? 'active' : ''}`}
                  onClick={() => { setEncodeMode('selector'); setEncodeResult(null); }}
                >
                  Selector
                </button>
                <button 
                  className={`encode-mode-btn ${encodeMode === 'checksum' ? 'active' : ''}`}
                  onClick={() => { setEncodeMode('checksum'); setEncodeResult(null); }}
                >
                  Checksum
                </button>
                <button 
                  className={`encode-mode-btn ${encodeMode === 'hex' ? 'active' : ''}`}
                  onClick={() => { setEncodeMode('hex'); setEncodeResult(null); }}
                >
                  Hex
                </button>
                <button 
                  className={`encode-mode-btn ${encodeMode === 'units' ? 'active' : ''}`}
                  onClick={() => { setEncodeMode('units'); setEncodeResult(null); }}
                >
                  Units
                </button>
              </div>

              {/* Keccak256 */}
              {encodeMode === 'keccak' && (
                <>
                  <label>Input (text or hex)</label>
                  <textarea
                    className="web3-input"
                    value={encodeInput}
                    onChange={(e) => setEncodeInput(e.target.value)}
                    placeholder="Enter text or 0x-prefixed hex to hash..."
                    rows={3}
                  />
                  <button 
                    className="web3-btn primary"
                    onClick={async () => {
                      if (!encodeInput.trim()) return;
                      const result = await window.electronAPI.web3Keccak256(encodeInput);
                      setEncodeResult(result);
                    }}
                  >
                    Calculate Keccak256
                  </button>
                </>
              )}

              {/* Function Selector */}
              {encodeMode === 'selector' && (
                <>
                  <label>Function Signature</label>
                  <input
                    type="text"
                    className="web3-input-field"
                    value={encodeInput}
                    onChange={(e) => setEncodeInput(e.target.value)}
                    placeholder="transfer(address,uint256)"
                  />
                  <button 
                    className="web3-btn primary"
                    onClick={async () => {
                      if (!encodeInput.trim()) return;
                      const result = await window.electronAPI.web3FunctionSelector(encodeInput);
                      setEncodeResult(result);
                    }}
                  >
                    Get Selector
                  </button>
                </>
              )}

              {/* Address Checksum */}
              {encodeMode === 'checksum' && (
                <>
                  <label>Address</label>
                  <input
                    type="text"
                    className="web3-input-field"
                    value={encodeInput}
                    onChange={(e) => setEncodeInput(e.target.value)}
                    placeholder="0x..."
                  />
                  <button 
                    className="web3-btn primary"
                    onClick={async () => {
                      if (!encodeInput.trim()) return;
                      const result = await window.electronAPI.web3ChecksumAddress(encodeInput);
                      setEncodeResult({ 
                        success: result.valid, 
                        result: result.checksummed, 
                        error: result.error 
                      });
                    }}
                  >
                    Validate & Checksum
                  </button>
                </>
              )}

              {/* Hex Conversion */}
              {encodeMode === 'hex' && (
                <>
                  <label>Input</label>
                  <input
                    type="text"
                    className="web3-input-field"
                    value={encodeInput}
                    onChange={(e) => setEncodeInput(e.target.value)}
                    placeholder="Text, hex (0x...), or number"
                  />
                  <div className="encode-actions">
                    <button 
                      className="web3-btn primary"
                      onClick={async () => {
                        if (!encodeInput.trim()) return;
                        const result = await window.electronAPI.web3Utf8ToHex(encodeInput);
                        setEncodeResult(result);
                      }}
                    >
                      Text → Hex
                    </button>
                    <button 
                      className="web3-btn primary"
                      onClick={async () => {
                        if (!encodeInput.trim()) return;
                        const result = await window.electronAPI.web3HexToUtf8(encodeInput);
                        setEncodeResult(result);
                      }}
                    >
                      Hex → Text
                    </button>
                    <button 
                      className="web3-btn primary"
                      onClick={async () => {
                        if (!encodeInput.trim()) return;
                        const result = await window.electronAPI.web3NumberToHex(encodeInput);
                        setEncodeResult(result);
                      }}
                    >
                      Number → Hex
                    </button>
                    <button 
                      className="web3-btn primary"
                      onClick={async () => {
                        if (!encodeInput.trim()) return;
                        const result = await window.electronAPI.web3HexToNumber(encodeInput);
                        setEncodeResult(result);
                      }}
                    >
                      Hex → Number
                    </button>
                  </div>
                </>
              )}

              {/* Units Conversion */}
              {encodeMode === 'units' && (
                <>
                  <label>Value</label>
                  <input
                    type="text"
                    className="web3-input-field"
                    value={encodeInput}
                    onChange={(e) => setEncodeInput(e.target.value)}
                    placeholder="Amount (wei or ether)"
                  />
                  <label>Decimals</label>
                  <select
                    className="web3-select"
                    value={encodeInput2}
                    onChange={(e) => setEncodeInput2(e.target.value)}
                  >
                    <option value="18">18 (ETH, most tokens)</option>
                    <option value="6">6 (USDC, USDT)</option>
                    <option value="8">8 (BTC, WBTC)</option>
                    <option value="9">9 (some tokens)</option>
                  </select>
                  <div className="encode-actions">
                    <button 
                      className="web3-btn primary"
                      onClick={async () => {
                        if (!encodeInput.trim()) return;
                        const decimals = parseInt(encodeInput2) || 18;
                        const result = await window.electronAPI.web3FormatUnits(encodeInput, decimals);
                        setEncodeResult(result);
                      }}
                    >
                      Wei → Ether
                    </button>
                    <button 
                      className="web3-btn primary"
                      onClick={async () => {
                        if (!encodeInput.trim()) return;
                        const decimals = parseInt(encodeInput2) || 18;
                        const result = await window.electronAPI.web3ParseUnits(encodeInput, decimals);
                        setEncodeResult(result);
                      }}
                    >
                      Ether → Wei
                    </button>
                  </div>
                </>
              )}

              {/* Result Display */}
              {encodeResult && (
                <div className={`encode-result ${encodeResult.success ? 'success' : 'error'}`}>
                  <label>{encodeResult.success ? 'Result' : 'Error'}</label>
                  <code className="encode-result-value">
                    {encodeResult.success ? encodeResult.result : encodeResult.error}
                  </code>
                  {encodeResult.success && (
                    <button 
                      className="copy-btn"
                      onClick={() => {
                        navigator.clipboard.writeText(encodeResult.result || '');
                      }}
                    >
                      Copy
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* Quick Reference */}
            <div className="section-box">
              <h4>Quick Reference</h4>
              <div className="reference-grid">
                <div className="reference-item">
                  <span className="ref-label">Max uint256</span>
                  <code className="ref-value">0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff</code>
                </div>
                <div className="reference-item">
                  <span className="ref-label">1 ETH in wei</span>
                  <code className="ref-value">1000000000000000000</code>
                </div>
                <div className="reference-item">
                  <span className="ref-label">1 Gwei</span>
                  <code className="ref-value">1000000000</code>
                </div>
                <div className="reference-item">
                  <span className="ref-label">Zero address</span>
                  <code className="ref-value">0x0000000000000000000000000000000000000000</code>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Security Analyzer (Remix-style, ReDoS, Zip) */}
        {activeTab === 'security' && (
          <div className="tool-panel">
            {/* Code Analysis Section */}
            <div className="tool-section">
              <label>Paste Code for Security Analysis</label>
              <textarea
                className="web3-input"
                value={securityCode}
                onChange={(e) => setSecurityCode(e.target.value)}
                placeholder="Paste JavaScript/TypeScript/Solidity code to analyze for security issues..."
                rows={10}
              />
              <button 
                className="web3-btn primary"
                disabled={isAnalyzing}
                onClick={async () => {
                  if (!securityCode.trim()) return;
                  setIsAnalyzing(true);
                  try {
                    const result = await window.electronAPI.web3SecurityAnalyze(securityCode);
                    setSecurityResult(result);
                  } catch (e) {
                    console.error('Security analysis error:', e);
                  } finally {
                    setIsAnalyzing(false);
                  }
                }}
              >
                {isAnalyzing ? 'Analyzing...' : 'Analyze Code'}
              </button>
            </div>

            {/* Stats Summary */}
            {securityResult && (
              <div className="security-stats">
                <div className="stat-item critical">{securityResult.stats.critical} Critical</div>
                <div className="stat-item high">{securityResult.stats.high} High</div>
                <div className="stat-item medium">{securityResult.stats.medium} Medium</div>
                <div className="stat-item low">{securityResult.stats.low} Low</div>
                <div className="stat-item info">{securityResult.stats.info} Info</div>
              </div>
            )}

            {/* Findings List */}
            {securityResult && securityResult.findings.length > 0 && (
              <div className="security-findings">
                {securityResult.findings.map((finding) => (
                  <div key={finding.id} className={`finding-item severity-${finding.severity.toLowerCase()}`}>
                    <div className="finding-header">
                      <span className={`severity-badge ${finding.severity.toLowerCase()}`}>
                        {finding.severity}
                      </span>
                      <span className="finding-category">{finding.category.toUpperCase()}</span>
                      <span className="finding-title">{finding.title}</span>
                      {finding.line && <span className="finding-line">Line {finding.line}</span>}
                    </div>
                    <div className="finding-description">{finding.description}</div>
                    {finding.code && (
                      <pre className="finding-code">{finding.code}</pre>
                    )}
                    <div className="finding-recommendation">
                      <strong>Fix:</strong> {finding.recommendation}
                    </div>
                    {finding.cwe && (
                      <span className="finding-cwe">{finding.cwe}</span>
                    )}
                  </div>
                ))}
              </div>
            )}

            {securityResult && securityResult.findings.length === 0 && (
              <div className="no-findings">
                No security issues detected in the provided code.
              </div>
            )}

            {/* Regex Tester Section */}
            <div className="section-box">
              <h4>ReDoS Regex Tester</h4>
              <p className="section-desc">Test a regex pattern for ReDoS vulnerabilities</p>
              <input
                type="text"
                className="web3-input-field"
                value={regexInput}
                onChange={(e) => setRegexInput(e.target.value)}
                placeholder="Enter regex pattern (e.g., (a+)+)"
              />
              <button 
                className="web3-btn primary"
                onClick={async () => {
                  if (!regexInput.trim()) return;
                  const result = await window.electronAPI.web3AnalyzeRegex(regexInput);
                  setRegexResult(result);
                }}
              >
                Test Regex
              </button>
              
              {regexResult && (
                <div className={`regex-result ${regexResult.isVulnerable ? 'vulnerable' : 'safe'}`}>
                  <div className="regex-status">
                    {regexResult.isVulnerable ? '⚠️ VULNERABLE' : '✓ SAFE'}
                  </div>
                  {regexResult.isVulnerable && (
                    <>
                      <div className="regex-type">Type: {regexResult.vulnerabilityType}</div>
                      <div className="regex-complexity">Complexity: {regexResult.estimatedComplexity}</div>
                      <div className="regex-explanation">{regexResult.explanation}</div>
                      {regexResult.safeAlternative && (
                        <div className="regex-fix">Suggestion: {regexResult.safeAlternative}</div>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>

            {/* Detection Categories Info */}
            <div className="section-box">
              <h4>What We Detect</h4>
              <div className="detection-categories">
                <div className="detection-item">
                  <strong>Remix-style</strong>
                  <span>Reentrancy, unchecked calls, delegatecall, selfdestruct, private key exposure</span>
                </div>
                <div className="detection-item">
                  <strong>ReDoS</strong>
                  <span>Nested quantifiers, evil regex patterns, exponential backtracking</span>
                </div>
                <div className="detection-item">
                  <strong>Zip/Compression</strong>
                  <span>Path traversal, zip bombs, symlink attacks, unbounded decompression</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Web3Tools;
