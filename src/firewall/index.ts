/**
 * EVM Transaction Firewall - Core security layer for EVM agent transactions
 * 
 * Features:
 * - Daily/per-tx spending limits
 * - Contract allowlist/blocklist  
 * - Transaction simulation before execution
 * - Detailed rejection reasons
 */

import type { TransactionRequest, Address } from 'viem';
import { SpendingLimits, SpendingLimitConfig } from './limits';
import { ContractAllowlist, AllowlistConfig, ContractCheckResult } from './allowlist';
import { TransactionSimulator, SimulationResult, SimulatorConfig } from './simulator';

export interface FirewallConfig {
  maxDailySpend: bigint;        // wei
  maxPerTxSpend: bigint;        // wei
  allowedContracts?: Address[]; // if set, only these allowed
  blockedContracts?: Address[]; // always blocked
  requireSimulation?: boolean;  // simulate before allowing
  rpcUrl?: string;
  chain?: 'base' | 'mainnet';
  payerAddress?: Address;       // for spend estimation
}

export interface FirewallResult {
  allowed: boolean;
  reason?: string;
  warnings?: string[];
  simulationResult?: SimulationResult;
  contractsChecked?: ContractCheckResult[];
  estimatedSpend?: bigint;
}

export interface FirewallStatus {
  spending: {
    dailySpend: bigint;
    dailyLimit: bigint;
    perTxLimit: bigint;
    remainingDaily: bigint;
  };
  contracts: {
    mode: 'allowlist' | 'blocklist_only';
    allowlistSize: number | null;
    blocklistSize: number;
  };
  requireSimulation: boolean;
}

export class TransactionFirewall {
  private readonly limits: SpendingLimits;
  private readonly allowlist: ContractAllowlist;
  private readonly simulator: TransactionSimulator;
  private readonly requireSimulation: boolean;
  private readonly payerAddress?: Address;

  constructor(config: FirewallConfig) {
    // Initialize spending limits
    this.limits = new SpendingLimits({
      maxDailySpend: config.maxDailySpend,
      maxPerTxSpend: config.maxPerTxSpend,
    });

    // Initialize contract allowlist
    this.allowlist = new ContractAllowlist({
      allowedContracts: config.allowedContracts,
      blockedContracts: config.blockedContracts,
    });

    // Initialize simulator
    this.simulator = new TransactionSimulator({
      rpcUrl: config.rpcUrl,
      chain: config.chain,
    });

    this.requireSimulation = config.requireSimulation ?? true;
    this.payerAddress = config.payerAddress;
  }

  /**
   * Check if a transaction is allowed through the firewall
   */
  async check(tx: TransactionRequest): Promise<FirewallResult> {
    const warnings: string[] = [];
    let simulationResult: SimulationResult | undefined;
    let estimatedSpend: bigint | undefined;

    // Step 1: Check contracts against allowlist/blocklist
    const contractAddresses = this.simulator.extractContractAddresses(tx);
    const contractChecks = this.allowlist.checkAll(contractAddresses);
    
    const blockedContract = contractChecks.find(c => !c.allowed);
    if (blockedContract) {
      return {
        allowed: false,
        reason: blockedContract.reason,
        contractsChecked: contractChecks,
        warnings,
      };
    }

    // Step 2: Estimate spending
    if (this.payerAddress) {
      const spendEstimate = await this.simulator.estimateSpend(tx, this.payerAddress);
      estimatedSpend = spendEstimate.estimatedSpend;
      warnings.push(...spendEstimate.warnings);

      // Check against spending limits
      const limitCheck = this.limits.check(estimatedSpend);
      if (!limitCheck.allowed) {
        return {
          allowed: false,
          reason: limitCheck.reason,
          contractsChecked: contractChecks,
          estimatedSpend,
          warnings,
        };
      }
    } else {
      // No payer address - can't estimate spend, warn but continue
      warnings.push('No payer address provided - spending limits not enforced');
    }

    // Step 3: Simulate transaction (if required)
    if (this.requireSimulation) {
      simulationResult = await this.simulate(tx);
      
      if (!simulationResult.success) {
        return {
          allowed: false,
          reason: `Simulation failed: ${simulationResult.error}`,
          simulationResult,
          contractsChecked: contractChecks,
          estimatedSpend,
          warnings: [...warnings, ...simulationResult.warnings],
        };
      }
      
      warnings.push(...simulationResult.warnings);
    }

    // Step 4: Check for suspicious patterns in calldata
    if (tx.data) {
      const dataWarnings = this.checkCalldata(tx.data);
      warnings.push(...dataWarnings);
    }

    // All checks passed
    return {
      allowed: true,
      simulationResult,
      contractsChecked: contractChecks,
      estimatedSpend,
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  }

  /**
   * Simulate a transaction without full firewall checks
   */
  async simulate(tx: TransactionRequest): Promise<SimulationResult> {
    return this.simulator.simulate(tx, this.payerAddress);
  }

  /**
   * Record a successful transaction's spend
   * Call this after transaction is confirmed
   */
  recordSpend(amountWei: bigint): void {
    this.limits.recordSpend(amountWei);
  }

  /**
   * Reset daily spending limit counter
   */
  resetDailySpend(): void {
    this.limits.resetDailySpend();
  }

  /**
   * Get current firewall status
   */
  getStatus(): FirewallStatus {
    const spendStatus = this.limits.getStatus();
    const contractStatus = this.allowlist.getStatus();

    return {
      spending: {
        dailySpend: spendStatus.dailySpend,
        dailyLimit: spendStatus.dailyLimit,
        perTxLimit: spendStatus.perTxLimit,
        remainingDaily: spendStatus.dailyLimit - spendStatus.dailySpend,
      },
      contracts: contractStatus,
      requireSimulation: this.requireSimulation,
    };
  }

  /**
   * Get remaining daily allowance
   */
  getRemainingDaily(): bigint {
    const status = this.limits.getStatus();
    return status.dailyLimit - status.dailySpend;
  }

  /**
   * Add a contract to the blocklist at runtime
   */
  blockContract(contractAddress: Address): void {
    this.allowlist.addToBlocklist(contractAddress);
  }

  /**
   * Add a contract to the allowlist at runtime (if in allowlist mode)
   */
  allowContract(contractAddress: Address): boolean {
    return this.allowlist.addToAllowlist(contractAddress);
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
}

// Re-export types and utilities
export { SpendingLimits, SpendingLimitConfig } from './limits';
export { ContractAllowlist, AllowlistConfig, ContractCheckResult, SAFE_SYSTEM_CONTRACTS, KNOWN_MALICIOUS_CONTRACTS } from './allowlist';
export { TransactionSimulator, SimulationResult, SimulatorConfig, BalanceChange } from './simulator';
