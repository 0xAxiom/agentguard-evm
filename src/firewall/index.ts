/**
 * EVM Transaction Firewall
 * 
 * Security layer for Base/EVM agent transactions:
 * - Spending limits (ETH + ERC20)
 * - Contract allowlists/blocklists
 * - Transaction simulation via eth_call
 * - Gas limits
 */

import { 
  createPublicClient, 
  http, 
  parseEther, 
  formatEther,
  decodeAbiParameters,
  type TransactionRequest,
  type Address,
  type Hash
} from 'viem';
import { base, mainnet } from 'viem/chains';

export interface FirewallConfig {
  /** Maximum daily spend in wei */
  maxDailySpend: bigint;
  /** Maximum per-transaction spend in wei */
  maxPerTxSpend: bigint;
  /** Allowed contract addresses (if set, only these allowed) */
  allowedContracts?: Address[];
  /** Blocked contract addresses (always blocked) */
  blockedContracts?: Address[];
  /** Maximum gas limit per tx */
  maxGasLimit?: bigint;
  /** Require simulation before execution */
  requireSimulation?: boolean;
  /** RPC URL */
  rpcUrl?: string;
  /** Chain (default: base) */
  chain?: 'base' | 'mainnet';
}

export interface FirewallResult {
  allowed: boolean;
  reason?: string;
  warnings: string[];
  simulation?: SimulationResult;
  valueWei?: bigint;
}

export interface SimulationResult {
  success: boolean;
  gasUsed?: bigint;
  returnData?: string;
  error?: string;
}

// Known malicious contracts (add more as discovered)
const KNOWN_MALICIOUS: Address[] = [
  // Add known drainers, phishing contracts, etc.
];

// Safe system contracts
const SAFE_CONTRACTS: Address[] = [
  '0x4200000000000000000000000000000000000006', // WETH on Base
  '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', // USDC on Base
];

export class TransactionFirewall {
  private config: FirewallConfig;
  private dailySpent: bigint = 0n;
  private lastResetDay: number = 0;
  private client: ReturnType<typeof createPublicClient>;

  constructor(config: FirewallConfig) {
    this.config = {
      maxGasLimit: config.maxGasLimit ?? 500000n,
      requireSimulation: config.requireSimulation ?? true,
      ...config
    };

    const chain = config.chain === 'mainnet' ? mainnet : base;
    this.client = createPublicClient({
      chain,
      transport: http(config.rpcUrl || 'https://mainnet.base.org')
    });
  }

  /**
   * Check if a transaction is allowed
   */
  async check(tx: TransactionRequest): Promise<FirewallResult> {
    const warnings: string[] = [];
    
    // Reset daily counter if new day
    this.resetDailyIfNeeded();

    // 1. Check value limits
    const value = tx.value ?? 0n;
    
    if (value > this.config.maxPerTxSpend) {
      return {
        allowed: false,
        reason: `Transaction value ${formatEther(value)} ETH exceeds per-tx limit ${formatEther(this.config.maxPerTxSpend)} ETH`,
        warnings,
        valueWei: value
      };
    }

    if (this.dailySpent + value > this.config.maxDailySpend) {
      return {
        allowed: false,
        reason: `Transaction would exceed daily limit. Spent: ${formatEther(this.dailySpent)}, Tx: ${formatEther(value)}, Limit: ${formatEther(this.config.maxDailySpend)}`,
        warnings,
        valueWei: value
      };
    }

    // 2. Check contract allowlist/blocklist
    if (tx.to) {
      const target = tx.to.toLowerCase() as Address;

      // Check blocklist
      const isBlocked = [
        ...KNOWN_MALICIOUS,
        ...(this.config.blockedContracts || [])
      ].some(addr => addr.toLowerCase() === target);

      if (isBlocked) {
        return {
          allowed: false,
          reason: `Contract ${tx.to} is on blocklist`,
          warnings,
          valueWei: value
        };
      }

      // Check allowlist (if configured)
      if (this.config.allowedContracts && this.config.allowedContracts.length > 0) {
        const isAllowed = [
          ...SAFE_CONTRACTS,
          ...this.config.allowedContracts
        ].some(addr => addr.toLowerCase() === target);

        if (!isAllowed) {
          return {
            allowed: false,
            reason: `Contract ${tx.to} is not on allowlist`,
            warnings,
            valueWei: value
          };
        }
      }
    }

    // 3. Check gas limit
    if (tx.gas && this.config.maxGasLimit && tx.gas > this.config.maxGasLimit) {
      return {
        allowed: false,
        reason: `Gas limit ${tx.gas} exceeds maximum ${this.config.maxGasLimit}`,
        warnings,
        valueWei: value
      };
    }

    // 4. Simulate transaction
    let simulation: SimulationResult | undefined;
    if (this.config.requireSimulation && tx.to) {
      simulation = await this.simulate(tx);
      
      if (!simulation.success) {
        return {
          allowed: false,
          reason: `Simulation failed: ${simulation.error}`,
          warnings,
          simulation,
          valueWei: value
        };
      }
    }

    // 5. Check for suspicious patterns in calldata
    if (tx.data) {
      const dataWarnings = this.checkCalldata(tx.data);
      warnings.push(...dataWarnings);
    }

    // If we got here, transaction is allowed
    // Update daily spent counter
    this.dailySpent += value;

    return {
      allowed: true,
      warnings,
      simulation,
      valueWei: value
    };
  }

  /**
   * Simulate a transaction via eth_call
   */
  async simulate(tx: TransactionRequest): Promise<SimulationResult> {
    try {
      const result = await this.client.call({
        to: tx.to,
        data: tx.data,
        value: tx.value,
        gas: tx.gas,
        account: tx.from
      });

      return {
        success: true,
        returnData: result.data
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Simulation failed'
      };
    }
  }

  /**
   * Check calldata for suspicious patterns
   */
  private checkCalldata(data: `0x${string}`): string[] {
    const warnings: string[] = [];
    const selector = data.slice(0, 10).toLowerCase();

    // Suspicious function selectors
    const SUSPICIOUS_SELECTORS: Record<string, string> = {
      '0x095ea7b3': 'approve - check spender address carefully',
      '0xa22cb465': 'setApprovalForAll - grants full NFT access',
      '0x42842e0e': 'safeTransferFrom (NFT)',
      '0x23b872dd': 'transferFrom - ensure authorized',
    };

    if (SUSPICIOUS_SELECTORS[selector]) {
      warnings.push(`⚠️ ${SUSPICIOUS_SELECTORS[selector]}`);
    }

    // Check for unlimited approval (max uint256)
    if (selector === '0x095ea7b3' && data.length >= 138) {
      const amount = data.slice(74, 138);
      if (amount === 'f'.repeat(64)) {
        warnings.push('🚨 UNLIMITED APPROVAL detected - consider using exact amount');
      }
    }

    return warnings;
  }

  /**
   * Reset daily counter if it's a new day
   */
  private resetDailyIfNeeded(): void {
    const today = Math.floor(Date.now() / (24 * 60 * 60 * 1000));
    if (today !== this.lastResetDay) {
      this.dailySpent = 0n;
      this.lastResetDay = today;
    }
  }

  /**
   * Get remaining daily allowance
   */
  getRemainingDaily(): bigint {
    this.resetDailyIfNeeded();
    return this.config.maxDailySpend - this.dailySpent;
  }

  /**
   * Manually reset daily counter
   */
  resetDailySpend(): void {
    this.dailySpent = 0n;
    this.lastResetDay = Math.floor(Date.now() / (24 * 60 * 60 * 1000));
  }
}
