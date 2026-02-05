/**
 * CleanTraffic - Web3 Security Analyzer
 * Transaction Decoder, Signature Analyzer, Contract Inspector
 */

import { ethers } from 'ethers';

// ═══════════════════════════════════════════════════════════════════════════
// TYPES & INTERFACES
// ═══════════════════════════════════════════════════════════════════════════

export interface DecodedTransaction {
  to: string;
  from?: string;
  value: string;
  valueEth: string;
  data: string;
  functionName?: string;
  functionSignature?: string;
  decodedArgs?: DecodedArg[];
  isContractCreation: boolean;
  gasLimit?: string;
  gasPrice?: string;
  nonce?: number;
  chainId?: number;
  warnings: string[];
}

export interface DecodedArg {
  name: string;
  type: string;
  value: string;
  indexed?: boolean;
}

export interface SignatureInfo {
  signature: string;
  name: string;
  inputs: { name: string; type: string }[];
}

export interface EIP712Message {
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

export interface ContractInfo {
  address: string;
  isContract: boolean;
  isProxy: boolean;
  proxyType?: 'EIP-1967' | 'EIP-1822' | 'Transparent' | 'UUPS' | 'Beacon' | 'Unknown';
  implementation?: string;
  admin?: string;
  beacon?: string;
  bytecodeHash?: string;
  verified?: boolean;
  name?: string;
}

export interface StorageSlot {
  slot: string;
  value: string;
  decoded?: string;
  label?: string;
}

export interface RPCCall {
  id: string;
  timestamp: number;
  method: string;
  params: any[];
  result?: any;
  error?: string;
  decoded?: {
    type: string;
    details: Record<string, any>;
  };
  warnings: string[];
}

// ═══════════════════════════════════════════════════════════════════════════
// 4-BYTE SIGNATURE DATABASE (Common Web3 functions)
// ═══════════════════════════════════════════════════════════════════════════

const SIGNATURE_DATABASE: Record<string, SignatureInfo> = {
  // ERC20
  '0xa9059cbb': { signature: '0xa9059cbb', name: 'transfer', inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }] },
  '0x23b872dd': { signature: '0x23b872dd', name: 'transferFrom', inputs: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }] },
  '0x095ea7b3': { signature: '0x095ea7b3', name: 'approve', inputs: [{ name: 'spender', type: 'address' }, { name: 'amount', type: 'uint256' }] },
  '0x70a08231': { signature: '0x70a08231', name: 'balanceOf', inputs: [{ name: 'account', type: 'address' }] },
  '0xdd62ed3e': { signature: '0xdd62ed3e', name: 'allowance', inputs: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }] },
  '0x18160ddd': { signature: '0x18160ddd', name: 'totalSupply', inputs: [] },
  
  // ERC721
  '0x42842e0e': { signature: '0x42842e0e', name: 'safeTransferFrom', inputs: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'tokenId', type: 'uint256' }] },
  '0xb88d4fde': { signature: '0xb88d4fde', name: 'safeTransferFrom', inputs: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'tokenId', type: 'uint256' }, { name: 'data', type: 'bytes' }] },
  '0xa22cb465': { signature: '0xa22cb465', name: 'setApprovalForAll', inputs: [{ name: 'operator', type: 'address' }, { name: 'approved', type: 'bool' }] },
  '0x6352211e': { signature: '0x6352211e', name: 'ownerOf', inputs: [{ name: 'tokenId', type: 'uint256' }] },
  
  // ERC1155
  '0xf242432a': { signature: '0xf242432a', name: 'safeTransferFrom', inputs: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'id', type: 'uint256' }, { name: 'amount', type: 'uint256' }, { name: 'data', type: 'bytes' }] },
  '0x2eb2c2d6': { signature: '0x2eb2c2d6', name: 'safeBatchTransferFrom', inputs: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'ids', type: 'uint256[]' }, { name: 'amounts', type: 'uint256[]' }, { name: 'data', type: 'bytes' }] },
  
  // Permit (EIP-2612)
  '0xd505accf': { signature: '0xd505accf', name: 'permit', inputs: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'deadline', type: 'uint256' }, { name: 'v', type: 'uint8' }, { name: 'r', type: 'bytes32' }, { name: 's', type: 'bytes32' }] },
  
  // Uniswap V2
  '0x7ff36ab5': { signature: '0x7ff36ab5', name: 'swapExactETHForTokens', inputs: [{ name: 'amountOutMin', type: 'uint256' }, { name: 'path', type: 'address[]' }, { name: 'to', type: 'address' }, { name: 'deadline', type: 'uint256' }] },
  '0x18cbafe5': { signature: '0x18cbafe5', name: 'swapExactTokensForETH', inputs: [{ name: 'amountIn', type: 'uint256' }, { name: 'amountOutMin', type: 'uint256' }, { name: 'path', type: 'address[]' }, { name: 'to', type: 'address' }, { name: 'deadline', type: 'uint256' }] },
  '0x38ed1739': { signature: '0x38ed1739', name: 'swapExactTokensForTokens', inputs: [{ name: 'amountIn', type: 'uint256' }, { name: 'amountOutMin', type: 'uint256' }, { name: 'path', type: 'address[]' }, { name: 'to', type: 'address' }, { name: 'deadline', type: 'uint256' }] },
  
  // Uniswap V3
  '0x414bf389': { signature: '0x414bf389', name: 'exactInputSingle', inputs: [{ name: 'params', type: 'tuple' }] },
  '0xc04b8d59': { signature: '0xc04b8d59', name: 'exactInput', inputs: [{ name: 'params', type: 'tuple' }] },
  '0x5023b4df': { signature: '0x5023b4df', name: 'exactOutputSingle', inputs: [{ name: 'params', type: 'tuple' }] },
  
  // Multicall
  '0xac9650d8': { signature: '0xac9650d8', name: 'multicall', inputs: [{ name: 'data', type: 'bytes[]' }] },
  '0x5ae401dc': { signature: '0x5ae401dc', name: 'multicall', inputs: [{ name: 'deadline', type: 'uint256' }, { name: 'data', type: 'bytes[]' }] },
  '0x1f0464d1': { signature: '0x1f0464d1', name: 'multicall', inputs: [{ name: 'previousBlockhash', type: 'bytes32' }, { name: 'data', type: 'bytes[]' }] },
  
  // Flash Loans
  '0xab9c4b5d': { signature: '0xab9c4b5d', name: 'flashLoan', inputs: [{ name: 'receiverAddress', type: 'address' }, { name: 'assets', type: 'address[]' }, { name: 'amounts', type: 'uint256[]' }, { name: 'modes', type: 'uint256[]' }, { name: 'onBehalfOf', type: 'address' }, { name: 'params', type: 'bytes' }, { name: 'referralCode', type: 'uint16' }] },
  '0x5cffe9de': { signature: '0x5cffe9de', name: 'flashLoan', inputs: [{ name: 'receiver', type: 'address' }, { name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'data', type: 'bytes' }] },
  
  // Proxy Patterns
  '0x3659cfe6': { signature: '0x3659cfe6', name: 'upgradeTo', inputs: [{ name: 'newImplementation', type: 'address' }] },
  '0x4f1ef286': { signature: '0x4f1ef286', name: 'upgradeToAndCall', inputs: [{ name: 'newImplementation', type: 'address' }, { name: 'data', type: 'bytes' }] },
  '0x5c60da1b': { signature: '0x5c60da1b', name: 'implementation', inputs: [] },
  '0xf851a440': { signature: '0xf851a440', name: 'admin', inputs: [] },
  
  // Access Control
  '0x2f2ff15d': { signature: '0x2f2ff15d', name: 'grantRole', inputs: [{ name: 'role', type: 'bytes32' }, { name: 'account', type: 'address' }] },
  '0xd547741f': { signature: '0xd547741f', name: 'revokeRole', inputs: [{ name: 'role', type: 'bytes32' }, { name: 'account', type: 'address' }] },
  '0x91d14854': { signature: '0x91d14854', name: 'hasRole', inputs: [{ name: 'role', type: 'bytes32' }, { name: 'account', type: 'address' }] },
  '0x8da5cb5b': { signature: '0x8da5cb5b', name: 'owner', inputs: [] },
  '0xf2fde38b': { signature: '0xf2fde38b', name: 'transferOwnership', inputs: [{ name: 'newOwner', type: 'address' }] },
  '0x715018a6': { signature: '0x715018a6', name: 'renounceOwnership', inputs: [] },
  
  // Dangerous Functions
  '0x00000000': { signature: '0x00000000', name: 'FALLBACK/RECEIVE', inputs: [] },
  '0xff0a9e45': { signature: '0xff0a9e45', name: 'delegatecall', inputs: [{ name: 'target', type: 'address' }, { name: 'data', type: 'bytes' }] },
  '0xcbd4ece9': { signature: '0xcbd4ece9', name: 'execute', inputs: [{ name: 'target', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' }] },
};

// Additional DeFi & Bridge signatures
const DEFI_SIGNATURES: Record<string, SignatureInfo> = {
  // Aave
  '0xe8eda9df': { signature: '0xe8eda9df', name: 'deposit', inputs: [{ name: 'asset', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'onBehalfOf', type: 'address' }, { name: 'referralCode', type: 'uint16' }] },
  '0x69328dec': { signature: '0x69328dec', name: 'withdraw', inputs: [{ name: 'asset', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'to', type: 'address' }] },
  '0xa415bcad': { signature: '0xa415bcad', name: 'borrow', inputs: [{ name: 'asset', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'interestRateMode', type: 'uint256' }, { name: 'referralCode', type: 'uint16' }, { name: 'onBehalfOf', type: 'address' }] },
  '0x573ade81': { signature: '0x573ade81', name: 'repay', inputs: [{ name: 'asset', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'interestRateMode', type: 'uint256' }, { name: 'onBehalfOf', type: 'address' }] },
  
  // Compound
  '0xa0712d68': { signature: '0xa0712d68', name: 'mint', inputs: [{ name: 'mintAmount', type: 'uint256' }] },
  '0xdb006a75': { signature: '0xdb006a75', name: 'redeem', inputs: [{ name: 'redeemTokens', type: 'uint256' }] },
  '0xc5ebeaec': { signature: '0xc5ebeaec', name: 'borrow', inputs: [{ name: 'borrowAmount', type: 'uint256' }] },
  '0x0e752702': { signature: '0x0e752702', name: 'repayBorrow', inputs: [{ name: 'repayAmount', type: 'uint256' }] },
  
  // Curve
  '0x3df02124': { signature: '0x3df02124', name: 'exchange', inputs: [{ name: 'i', type: 'int128' }, { name: 'j', type: 'int128' }, { name: 'dx', type: 'uint256' }, { name: 'min_dy', type: 'uint256' }] },
  '0x0b4c7e4d': { signature: '0x0b4c7e4d', name: 'add_liquidity', inputs: [{ name: 'amounts', type: 'uint256[2]' }, { name: 'min_mint_amount', type: 'uint256' }] },
  '0x5b36389c': { signature: '0x5b36389c', name: 'remove_liquidity', inputs: [{ name: '_amount', type: 'uint256' }, { name: 'min_amounts', type: 'uint256[2]' }] },
  
  // Balancer
  '0x52bbbe29': { signature: '0x52bbbe29', name: 'swap', inputs: [{ name: 'singleSwap', type: 'tuple' }, { name: 'funds', type: 'tuple' }, { name: 'limit', type: 'uint256' }, { name: 'deadline', type: 'uint256' }] },
  '0x945bcec9': { signature: '0x945bcec9', name: 'batchSwap', inputs: [{ name: 'kind', type: 'uint8' }, { name: 'swaps', type: 'tuple[]' }, { name: 'assets', type: 'address[]' }, { name: 'funds', type: 'tuple' }, { name: 'limits', type: 'int256[]' }, { name: 'deadline', type: 'uint256' }] },
  
  // Bridge functions
  '0x0f5287b0': { signature: '0x0f5287b0', name: 'bridgeTokens', inputs: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }, { name: 'toChainId', type: 'uint256' }] },
  '0x4faa8a26': { signature: '0x4faa8a26', name: 'depositToVault', inputs: [{ name: 'token', type: 'address' }, { name: 'amount', type: 'uint256' }] },
  '0x1cff79cd': { signature: '0x1cff79cd', name: 'execute', inputs: [{ name: 'to', type: 'address' }, { name: 'data', type: 'bytes' }] },
  
  // Gnosis Safe / Multisig
  '0x6a761202': { signature: '0x6a761202', name: 'execTransaction', inputs: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' }, { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' }, { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' }, { name: 'refundReceiver', type: 'address' }, { name: 'signatures', type: 'bytes' }] },
  '0xd8d11f78': { signature: '0xd8d11f78', name: 'getTransactionHash', inputs: [{ name: 'to', type: 'address' }, { name: 'value', type: 'uint256' }, { name: 'data', type: 'bytes' }, { name: 'operation', type: 'uint8' }, { name: 'safeTxGas', type: 'uint256' }, { name: 'baseGas', type: 'uint256' }, { name: 'gasPrice', type: 'uint256' }, { name: 'gasToken', type: 'address' }, { name: 'refundReceiver', type: 'address' }, { name: '_nonce', type: 'uint256' }] },
  
  // EIP-2535 Diamond
  '0x1f931c1c': { signature: '0x1f931c1c', name: 'diamondCut', inputs: [{ name: '_diamondCut', type: 'tuple[]' }, { name: '_init', type: 'address' }, { name: '_calldata', type: 'bytes' }] },
  '0x7a0ed627': { signature: '0x7a0ed627', name: 'facets', inputs: [] },
  '0xcdffacc6': { signature: '0xcdffacc6', name: 'facetAddress', inputs: [{ name: '_functionSelector', type: 'bytes4' }] },
  
  // Permit2
  '0x2b67b570': { signature: '0x2b67b570', name: 'permit', inputs: [{ name: 'owner', type: 'address' }, { name: 'permitSingle', type: 'tuple' }, { name: 'signature', type: 'bytes' }] },
  '0x30f28b7a': { signature: '0x30f28b7a', name: 'permitTransferFrom', inputs: [{ name: 'permit', type: 'tuple' }, { name: 'transferDetails', type: 'tuple' }, { name: 'owner', type: 'address' }, { name: 'signature', type: 'bytes' }] },
};

// Merge all signatures
Object.assign(SIGNATURE_DATABASE, DEFI_SIGNATURES);

// Known dangerous patterns
const DANGEROUS_SIGNATURES = [
  '0xff0a9e45', // delegatecall
  '0xcbd4ece9', // execute
  '0x3659cfe6', // upgradeTo
  '0x4f1ef286', // upgradeToAndCall
  '0xf2fde38b', // transferOwnership
  '0x715018a6', // renounceOwnership
  '0x6a761202', // execTransaction (Gnosis Safe)
  '0x1cff79cd', // execute (generic)
  '0x1f931c1c', // diamondCut
];

// Proxy storage slots (EIP-1967)
const PROXY_SLOTS = {
  IMPLEMENTATION: '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
  ADMIN: '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
  BEACON: '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50',
  ROLLBACK: '0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143',
};

// ═══════════════════════════════════════════════════════════════════════════
// WEB3 ANALYZER CLASS
// ═══════════════════════════════════════════════════════════════════════════

class Web3Analyzer {
  private provider: ethers.JsonRpcProvider | null = null;
  private rpcCalls: RPCCall[] = [];

  setProvider(rpcUrl: string): void {
    try {
      this.provider = new ethers.JsonRpcProvider(rpcUrl);
    } catch (error) {
      console.error('[Web3Analyzer] Failed to set provider:', error);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TRANSACTION DECODER
  // ═══════════════════════════════════════════════════════════════════════════

  decodeTransaction(txData: {
    to?: string;
    from?: string;
    value?: string;
    data?: string;
    gasLimit?: string;
    gasPrice?: string;
    nonce?: number;
    chainId?: number;
  }): DecodedTransaction {
    const input = txData && typeof txData === 'object' ? txData : {};
    const warnings: string[] = [];
    const data = input.data || '0x';
    const value = input.value || '0';
    const to = input.to || '';

    // Check for contract creation
    const isContractCreation = !to || to === '0x' || to === '';

    // Parse value
    let valueEth = '0';
    try {
      const valueBigInt = BigInt(value);
      valueEth = ethers.formatEther(valueBigInt);
      if (valueBigInt > 0n) {
        warnings.push(`⚠️ Transaction sends ${valueEth} ETH`);
      }
    } catch {
      valueEth = value;
    }

    // Decode function call
    let functionName: string | undefined;
    let functionSignature: string | undefined;
    let decodedArgs: DecodedArg[] | undefined;

    if (data && data.length >= 10) {
      functionSignature = data.slice(0, 10).toLowerCase();
      const sigInfo = SIGNATURE_DATABASE[functionSignature];

      if (sigInfo) {
        functionName = sigInfo.name;
        
        // Check for dangerous functions
        if (DANGEROUS_SIGNATURES.includes(functionSignature)) {
          warnings.push(`🚨 DANGEROUS: ${functionName} function detected`);
        }

        // Try to decode arguments
        if (sigInfo.inputs.length > 0) {
          try {
            const abiCoder = new ethers.AbiCoder();
            const types = sigInfo.inputs.map(i => i.type);
            const decoded = abiCoder.decode(types, '0x' + data.slice(10));
            
            decodedArgs = sigInfo.inputs.map((input, i) => ({
              name: input.name,
              type: input.type,
              value: this.formatValue(decoded[i], input.type),
            }));

            // Check for specific dangerous patterns
            this.checkDangerousPatterns(functionName, decodedArgs, warnings);
          } catch (e) {
            // Decoding failed, leave args undefined
          }
        }
      } else {
        functionName = 'Unknown Function';
        warnings.push(`❓ Unknown function signature: ${functionSignature}`);
      }
    }

    if (isContractCreation) {
      warnings.push('📝 Contract creation transaction');
    }

    return {
      to,
      from: input.from,
      value,
      valueEth,
      data,
      functionName,
      functionSignature,
      decodedArgs,
      isContractCreation,
      gasLimit: input.gasLimit,
      gasPrice: input.gasPrice,
      nonce: input.nonce,
      chainId: input.chainId,
      warnings,
    };
  }

  private formatValue(value: any, type: string): string {
    if (value == null) return String(value);
    if (type === 'address') {
      return value.toString();
    }
    if (type.startsWith('uint') || type.startsWith('int')) {
      const bigVal = BigInt(value);
      // Format large numbers nicely
      if (bigVal > 10n ** 15n) {
        try {
          return `${ethers.formatEther(bigVal)} (${bigVal.toString()})`;
        } catch {
          return bigVal.toString();
        }
      }
      return bigVal.toString();
    }
    if (type === 'bytes32') {
      return value.toString();
    }
    if (type === 'bool') {
      return value ? 'true' : 'false';
    }
    if (type.endsWith('[]')) {
      if (Array.isArray(value)) {
        return JSON.stringify(value.map(v => v.toString()));
      }
    }
    return value.toString();
  }

  private checkDangerousPatterns(functionName: string, args: DecodedArg[], warnings: string[]): void {
    // Check for unlimited approval
    if (functionName === 'approve') {
      const amountArg = args.find(a => a.name === 'amount' || a.name === 'value');
      if (amountArg) {
        const amount = BigInt(amountArg.value.split(' ')[0].replace(/[^0-9]/g, '') || '0');
        const maxUint = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
        if (amount >= maxUint / 2n) {
          warnings.push('🚨 CRITICAL: Unlimited token approval detected!');
        }
      }
    }

    // Check for suspicious recipient
    if (functionName === 'transfer' || functionName === 'transferFrom') {
      const toArg = args.find(a => a.name === 'to' || a.name === 'recipient');
      if (toArg && toArg.value === '0x0000000000000000000000000000000000000000') {
        warnings.push('🚨 CRITICAL: Transfer to zero address (burn)!');
      }
    }

    // Check for flash loan
    if (functionName === 'flashLoan') {
      warnings.push('⚠️ Flash loan detected - check for reentrancy');
    }

    // Check for ownership transfer
    if (functionName === 'transferOwnership') {
      warnings.push('⚠️ Ownership transfer - verify new owner');
    }

    // Check for setApprovalForAll
    if (functionName === 'setApprovalForAll') {
      const approvedArg = args.find(a => a.name === 'approved');
      if (approvedArg && approvedArg.value === 'true') {
        warnings.push('⚠️ Setting approval for ALL tokens to operator');
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // EIP-712 SIGNATURE ANALYZER
  // ═══════════════════════════════════════════════════════════════════════════

  analyzeEIP712Message(typedData: any): EIP712Message {
    const warnings: string[] = [];
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';

    try {
      const domain = typedData.domain || {};
      const primaryType = typedData.primaryType || 'Unknown';
      const types = typedData.types || {};
      const message = typedData.message || {};

      // Check domain
      if (!domain.verifyingContract) {
        warnings.push('⚠️ No verifying contract specified');
        riskLevel = 'MEDIUM';
      }

      if (!domain.chainId) {
        warnings.push('⚠️ No chainId in domain - signature may be replayed on other chains');
        riskLevel = 'HIGH';
      }

      // Analyze by primary type
      if (primaryType === 'Permit' || primaryType.includes('Permit')) {
        warnings.push('📝 Permit signature - grants token spending approval');
        
        // Check for unlimited permit
        if (message.value) {
          const maxUint = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
          try {
            const permitValue = BigInt(message.value);
            if (permitValue >= maxUint / 2n) {
              warnings.push('🚨 CRITICAL: Unlimited permit approval!');
              riskLevel = 'CRITICAL';
            }
          } catch {}
        }

        // Check deadline
        if (message.deadline) {
          const deadline = Number(message.deadline);
          const now = Math.floor(Date.now() / 1000);
          const oneYear = 365 * 24 * 60 * 60;
          if (deadline - now > oneYear) {
            warnings.push('⚠️ Very long permit deadline (> 1 year)');
            if (riskLevel !== 'CRITICAL') riskLevel = 'HIGH';
          }
        }
      }

      // Check for dangerous message fields
      const dangerousFields = ['execute', 'delegatecall', 'upgrade', 'transferOwnership'];
      for (const field of Object.keys(message)) {
        if (dangerousFields.some(d => field.toLowerCase().includes(d))) {
          warnings.push(`🚨 Potentially dangerous field: ${field}`);
          if (riskLevel !== 'CRITICAL') riskLevel = 'HIGH';
        }
      }

      // Check for approval/allowance patterns
      if (message.spender || message.operator) {
        warnings.push('📝 This signature grants spending/operator rights');
        if (riskLevel === 'LOW') riskLevel = 'MEDIUM';
      }

      return {
        domain,
        primaryType,
        types,
        message,
        warnings,
        riskLevel,
      };
    } catch (error) {
      return {
        domain: {},
        primaryType: 'Unknown',
        types: {},
        message: typedData,
        warnings: ['❌ Failed to parse EIP-712 message'],
        riskLevel: 'HIGH',
      };
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CONTRACT INSPECTOR
  // ═══════════════════════════════════════════════════════════════════════════

  async inspectContract(address: string, rpcUrl?: string): Promise<ContractInfo> {
    if (address == null || typeof address !== 'string' || !address.trim()) {
      throw new Error('Invalid contract address');
    }
    const provider = rpcUrl ? new ethers.JsonRpcProvider(rpcUrl) : this.provider;

    if (!provider) {
      throw new Error('No RPC provider configured. Call setProvider(rpcUrl) or pass rpcUrl.');
    }

    const result: ContractInfo = {
      address,
      isContract: false,
      isProxy: false,
    };

    try {
      // Check if address is a contract
      const code = await provider.getCode(address);
      result.isContract = code !== '0x' && code.length > 2;
      result.bytecodeHash = ethers.keccak256(code);

      if (!result.isContract) {
        return result;
      }

      // Check for proxy patterns by reading storage slots
      const [implSlot, adminSlot, beaconSlot] = await Promise.all([
        provider.getStorage(address, PROXY_SLOTS.IMPLEMENTATION),
        provider.getStorage(address, PROXY_SLOTS.ADMIN),
        provider.getStorage(address, PROXY_SLOTS.BEACON),
      ]);

      // Check EIP-1967 implementation slot
      if (implSlot !== '0x0000000000000000000000000000000000000000000000000000000000000000') {
        result.isProxy = true;
        result.implementation = '0x' + implSlot.slice(26);
        result.proxyType = 'EIP-1967';
      }

      // Check admin slot
      if (adminSlot !== '0x0000000000000000000000000000000000000000000000000000000000000000') {
        result.admin = '0x' + adminSlot.slice(26);
        if (result.isProxy && !result.proxyType) {
          result.proxyType = 'Transparent';
        }
      }

      // Check beacon slot
      if (beaconSlot !== '0x0000000000000000000000000000000000000000000000000000000000000000') {
        result.beacon = '0x' + beaconSlot.slice(26);
        result.isProxy = true;
        result.proxyType = 'Beacon';
      }

      return result;
    } catch (error) {
      console.error('[Web3Analyzer] Contract inspection error:', error);
      throw error;
    }
  }

  async readStorageSlot(address: string, slot: string, rpcUrl?: string): Promise<StorageSlot> {
    const provider = rpcUrl ? new ethers.JsonRpcProvider(rpcUrl) : this.provider;
    
    if (!provider) {
      throw new Error('No RPC provider configured');
    }

    const value = await provider.getStorage(address, slot);
    
    // Try to decode the value
    let decoded: string | undefined;
    let label: string | undefined;

    // Check if it's a known slot
    for (const [name, knownSlot] of Object.entries(PROXY_SLOTS)) {
      if (slot.toLowerCase() === knownSlot.toLowerCase()) {
        label = name;
        if (value !== '0x0000000000000000000000000000000000000000000000000000000000000000') {
          decoded = '0x' + value.slice(26); // Extract address
        }
        break;
      }
    }

    // Try to decode as address if not already decoded
    if (!decoded && value.length === 66) {
      const potentialAddr = '0x' + value.slice(26);
      if (potentialAddr !== '0x0000000000000000000000000000000000000000') {
        decoded = potentialAddr;
      }
    }

    return { slot, value, decoded, label };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RPC CALL ANALYZER
  // ═══════════════════════════════════════════════════════════════════════════

  analyzeRPCCall(method: string, params: any[], result?: any): RPCCall {
    const warnings: string[] = [];
    let decoded: { type: string; details: Record<string, any> } | undefined;

    const rpcCall: RPCCall = {
      id: `rpc-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      timestamp: Date.now(),
      method,
      params,
      result,
      warnings,
    };

    // Analyze based on method
    switch (method) {
      case 'eth_sendTransaction':
      case 'eth_sendRawTransaction':
        warnings.push('⚠️ Transaction being sent');
        if (params[0]) {
          const txDecoded = this.decodeTransaction(params[0]);
          decoded = { type: 'transaction', details: txDecoded };
          warnings.push(...txDecoded.warnings);
        }
        break;

      case 'eth_signTypedData':
      case 'eth_signTypedData_v3':
      case 'eth_signTypedData_v4':
        warnings.push('⚠️ Signature request (EIP-712)');
        if (params[1]) {
          try {
            const typedData = typeof params[1] === 'string' ? JSON.parse(params[1]) : params[1];
            const analyzed = this.analyzeEIP712Message(typedData);
            decoded = { type: 'eip712', details: analyzed };
            warnings.push(...analyzed.warnings);
          } catch {}
        }
        break;

      case 'eth_sign':
      case 'personal_sign':
        warnings.push('⚠️ Personal message signature request');
        decoded = {
          type: 'personalSign',
          details: {
            message: params[0],
            signer: params[1],
          },
        };
        break;

      case 'wallet_addEthereumChain':
        warnings.push('🔗 Request to add new chain');
        if (params[0]) {
          decoded = {
            type: 'addChain',
            details: params[0],
          };
        }
        break;

      case 'wallet_switchEthereumChain':
        warnings.push('🔗 Request to switch chain');
        decoded = {
          type: 'switchChain',
          details: { chainId: params[0]?.chainId },
        };
        break;

      case 'eth_requestAccounts':
      case 'wallet_requestPermissions':
        warnings.push('🔐 Wallet connection request');
        break;

      case 'eth_call':
        // This is a read-only call, generally safe
        if (params[0]?.data) {
          const callDecoded = this.decodeTransaction(params[0]);
          decoded = { type: 'eth_call', details: callDecoded };
        }
        break;
    }

    rpcCall.decoded = decoded;
    this.rpcCalls.push(rpcCall);

    return rpcCall;
  }

  getRPCCalls(): RPCCall[] {
    return this.rpcCalls;
  }

  clearRPCCalls(): void {
    this.rpcCalls = [];
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SIGNATURE LOOKUP
  // ═══════════════════════════════════════════════════════════════════════════

  lookupSignature(signature: string): SignatureInfo | null {
    if (signature == null || typeof signature !== 'string') return null;
    const s = signature.trim();
    if (!s) return null;
    const normalized = s.toLowerCase().startsWith('0x')
      ? s.toLowerCase().slice(0, 10)
      : '0x' + s.toLowerCase().slice(0, 8);
    return SIGNATURE_DATABASE[normalized] || null;
  }

  getAllSignatures(): SignatureInfo[] {
    return Object.values(SIGNATURE_DATABASE);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ENCODING / DECODING UTILITIES
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Encode data using ABI encoding
   */
  abiEncode(types: string[], values: any[]): string {
    try {
      const abiCoder = new ethers.AbiCoder();
      return abiCoder.encode(types, values);
    } catch (error) {
      throw new Error(`ABI encode failed: ${(error as Error).message}`);
    }
  }

  /**
   * Decode ABI encoded data
   */
  abiDecode(types: string[], data: string): any[] {
    try {
      const abiCoder = new ethers.AbiCoder();
      const decoded = abiCoder.decode(types, data);
      return decoded.map((v: any) => {
        if (typeof v === 'bigint') return v.toString();
        if (typeof v === 'object' && v !== null) return JSON.stringify(v);
        return v;
      });
    } catch (error) {
      throw new Error(`ABI decode failed: ${(error as Error).message}`);
    }
  }

  /**
   * Encode a function call
   */
  encodeFunctionCall(signature: string, args: any[]): string {
    try {
      const iface = new ethers.Interface([`function ${signature}`]);
      const funcName = signature.split('(')[0];
      return iface.encodeFunctionData(funcName, args);
    } catch (error) {
      throw new Error(`Function encode failed: ${(error as Error).message}`);
    }
  }

  /**
   * Decode a function call
   */
  decodeFunctionCall(abi: string[], data: string): { name: string; args: any[] } {
    try {
      const iface = new ethers.Interface(abi);
      const decoded = iface.parseTransaction({ data });
      if (!decoded) throw new Error('Could not decode function call');
      return {
        name: decoded.name,
        args: decoded.args.map((v: any) => {
          if (typeof v === 'bigint') return v.toString();
          return v;
        }),
      };
    } catch (error) {
      throw new Error(`Function decode failed: ${(error as Error).message}`);
    }
  }

  /**
   * Calculate keccak256 hash
   */
  keccak256(data: string): string {
    try {
      // Handle both hex and UTF-8 strings
      if (data.startsWith('0x')) {
        return ethers.keccak256(data);
      } else {
        return ethers.keccak256(ethers.toUtf8Bytes(data));
      }
    } catch (error) {
      throw new Error(`Keccak256 failed: ${(error as Error).message}`);
    }
  }

  /**
   * Get function selector from signature
   */
  getFunctionSelector(signature: string): string {
    try {
      const hash = ethers.keccak256(ethers.toUtf8Bytes(signature));
      return hash.slice(0, 10);
    } catch (error) {
      throw new Error(`Selector calculation failed: ${(error as Error).message}`);
    }
  }

  /**
   * Validate and checksum an address
   */
  checksumAddress(address: string): { valid: boolean; checksummed?: string; error?: string } {
    try {
      if (!address.match(/^0x[a-fA-F0-9]{40}$/)) {
        return { valid: false, error: 'Invalid address format' };
      }
      const checksummed = ethers.getAddress(address);
      return { valid: true, checksummed };
    } catch (error) {
      return { valid: false, error: (error as Error).message };
    }
  }

  /**
   * Convert hex to UTF-8 string
   */
  hexToUtf8(hex: string): string {
    try {
      const cleanHex = hex.startsWith('0x') ? hex : '0x' + hex;
      return ethers.toUtf8String(cleanHex);
    } catch (error) {
      throw new Error(`Hex to UTF-8 failed: ${(error as Error).message}`);
    }
  }

  /**
   * Convert UTF-8 string to hex
   */
  utf8ToHex(text: string): string {
    try {
      return ethers.hexlify(ethers.toUtf8Bytes(text));
    } catch (error) {
      throw new Error(`UTF-8 to hex failed: ${(error as Error).message}`);
    }
  }

  /**
   * Convert number to hex (with optional padding)
   */
  numberToHex(num: string | number | bigint, padBytes?: number): string {
    try {
      const bn = BigInt(num);
      let hex = bn.toString(16);
      if (padBytes) {
        hex = hex.padStart(padBytes * 2, '0');
      }
      return '0x' + hex;
    } catch (error) {
      throw new Error(`Number to hex failed: ${(error as Error).message}`);
    }
  }

  /**
   * Convert hex to number
   */
  hexToNumber(hex: string): string {
    try {
      const cleanHex = hex.startsWith('0x') ? hex : '0x' + hex;
      return BigInt(cleanHex).toString();
    } catch (error) {
      throw new Error(`Hex to number failed: ${(error as Error).message}`);
    }
  }

  /**
   * Format units (wei to ether, etc.)
   */
  formatUnits(value: string, decimals: number = 18): string {
    try {
      return ethers.formatUnits(value, decimals);
    } catch (error) {
      throw new Error(`Format units failed: ${(error as Error).message}`);
    }
  }

  /**
   * Parse units (ether to wei, etc.)
   */
  parseUnits(value: string, decimals: number = 18): string {
    try {
      return ethers.parseUnits(value, decimals).toString();
    } catch (error) {
      throw new Error(`Parse units failed: ${(error as Error).message}`);
    }
  }

  /**
   * Pad hex to 32 bytes
   */
  padBytes32(value: string): string {
    try {
      const cleanHex = value.startsWith('0x') ? value.slice(2) : value;
      if (cleanHex.length > 64) {
        throw new Error('Value too large for bytes32');
      }
      return '0x' + cleanHex.padStart(64, '0');
    } catch (error) {
      throw new Error(`Pad bytes32 failed: ${(error as Error).message}`);
    }
  }

  /**
   * Decode packed data
   */
  solidityPack(types: string[], values: any[]): string {
    try {
      return ethers.solidityPacked(types, values);
    } catch (error) {
      throw new Error(`Solidity pack failed: ${(error as Error).message}`);
    }
  }

  /**
   * Compute CREATE2 address
   */
  computeCreate2Address(deployer: string, salt: string, initCodeHash: string): string {
    try {
      return ethers.getCreate2Address(deployer, salt, initCodeHash);
    } catch (error) {
      throw new Error(`CREATE2 address failed: ${(error as Error).message}`);
    }
  }

  /**
   * Recover signer from signature
   */
  recoverAddress(message: string, signature: string): string {
    try {
      // Hash the message if it's not already hashed
      const messageHash = message.startsWith('0x') && message.length === 66
        ? message
        : ethers.hashMessage(message);
      return ethers.recoverAddress(messageHash, signature);
    } catch (error) {
      throw new Error(`Recover address failed: ${(error as Error).message}`);
    }
  }
}

// Export singleton instance
export const web3Analyzer = new Web3Analyzer();

// ═══════════════════════════════════════════════════════════════════════════
// ENCODING/DECODING EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

export interface EncodingResult {
  success: boolean;
  result?: string;
  error?: string;
}

export interface DecodingResult {
  success: boolean;
  result?: any;
  error?: string;
}

export function abiEncode(types: string[], values: any[]): EncodingResult {
  try {
    return { success: true, result: web3Analyzer.abiEncode(types, values) };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
}

export function abiDecode(types: string[], data: string): DecodingResult {
  try {
    return { success: true, result: web3Analyzer.abiDecode(types, data) };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
}

export function keccak256(data: string): EncodingResult {
  try {
    return { success: true, result: web3Analyzer.keccak256(data) };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
}

export function getFunctionSelector(signature: string): EncodingResult {
  try {
    return { success: true, result: web3Analyzer.getFunctionSelector(signature) };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
}

export function checksumAddress(address: string): { valid: boolean; checksummed?: string; error?: string } {
  return web3Analyzer.checksumAddress(address);
}

export function hexToUtf8(hex: string): DecodingResult {
  try {
    return { success: true, result: web3Analyzer.hexToUtf8(hex) };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
}

export function utf8ToHex(text: string): EncodingResult {
  try {
    return { success: true, result: web3Analyzer.utf8ToHex(text) };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
}

export function numberToHex(num: string, padBytes?: number): EncodingResult {
  try {
    return { success: true, result: web3Analyzer.numberToHex(num, padBytes) };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
}

export function hexToNumber(hex: string): DecodingResult {
  try {
    return { success: true, result: web3Analyzer.hexToNumber(hex) };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
}

export function formatUnits(value: string, decimals?: number): DecodingResult {
  try {
    return { success: true, result: web3Analyzer.formatUnits(value, decimals) };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
}

export function parseUnits(value: string, decimals?: number): EncodingResult {
  try {
    return { success: true, result: web3Analyzer.parseUnits(value, decimals) };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
}

// Export for IPC handlers
export function decodeTransaction(txData: any): DecodedTransaction {
  return web3Analyzer.decodeTransaction(txData);
}

export function analyzeEIP712(typedData: any): EIP712Message {
  return web3Analyzer.analyzeEIP712Message(typedData);
}

export async function inspectContract(address: string, rpcUrl?: string): Promise<ContractInfo> {
  return web3Analyzer.inspectContract(address, rpcUrl);
}

export async function readStorageSlot(address: string, slot: string, rpcUrl?: string): Promise<StorageSlot> {
  return web3Analyzer.readStorageSlot(address, slot, rpcUrl);
}

export function analyzeRPCCall(method: string, params: any[], result?: any): RPCCall {
  return web3Analyzer.analyzeRPCCall(method, params, result);
}

export function lookupSignature(signature: string): SignatureInfo | null {
  return web3Analyzer.lookupSignature(signature);
}
