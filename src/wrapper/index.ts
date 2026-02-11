/**
 * EVM Agent Wrapper
 * 
 * Drop-in security wrapper for EVM-based agents (Base, Ethereum, etc.).
 * Intercepts all transactions and adds AgentGuard protection.
 * 
 * Usage:
 *   import { createGuardedAgent } from '@0xaxiom/agentguard-evm/wrapper';
 *   const agent = await createGuardedAgent(wallet, rpcUrl, { maxDailySpendEth: 1 });
 *   // Now all agent actions are protected!
 */

import { 
  createWalletClient,
  createPublicClient,
  http,
  parseEther,
  formatEther,
  type WalletClient,
  type PublicClient,
  type TransactionRequest,
  type Hash,
  type Address,
  type Account
} from 'viem';
import { base, mainnet } from 'viem/chains';
import { AgentGuard, AgentGuardConfig, GuardResult } from '../guard';

export interface GuardedAgentConfig extends AgentGuardConfig {
  /** Called when a transaction is blocked */
  onBlocked?: (action: string, reason: string, result: GuardResult) => void;
  /** Called when input contains injection attempts */
  onInjection?: (input: string, threats: number) => void;
  /** Called when secrets are detected in output */
  onSecretLeak?: (redactedCount: number) => void;
  /** Allow blocked actions to proceed anyway (for testing) */
  dryRun?: boolean;
  /** Chain to use (default: base) */
  chain?: 'base' | 'mainnet';
}

export interface GuardedAction<T> {
  success: boolean;
  result?: T;
  blocked?: boolean;
  reason?: string;
  warnings: string[];
  auditId?: string;
}

/**
 * GuardedEVMAgent - Security-wrapped EVM Agent
 */
export class GuardedEVMAgent {
  public readonly walletClient: WalletClient;
  public readonly publicClient: PublicClient;
  public readonly guard: AgentGuard;
  private config: GuardedAgentConfig;

  constructor(
    walletClient: WalletClient, 
    publicClient: PublicClient,
    guard: AgentGuard, 
    config: GuardedAgentConfig = {}
  ) {
    this.walletClient = walletClient;
    this.publicClient = publicClient;
    this.guard = guard;
    this.config = config;
  }

  /**
   * Execute a guarded action with full security checks
   */
  async execute<T>(
    action: string,
    fn: () => Promise<T>,
    options: { 
      skipFirewall?: boolean;
      customCheck?: () => Promise<{ allowed: boolean; reason?: string }>;
    } = {}
  ): Promise<GuardedAction<T>> {
    const warnings: string[] = [];
    let auditId: string | undefined;

    try {
      // Custom security check if provided
      if (options.customCheck) {
        const check = await options.customCheck();
        if (!check.allowed) {
          this.config.onBlocked?.(action, check.reason || 'Custom check failed', {
            allowed: false,
            reason: check.reason,
            warnings: [],
            firewall: { allowed: false, reason: check.reason, warnings: [] }
          });

          if (!this.config.dryRun) {
            return {
              success: false,
              blocked: true,
              reason: check.reason,
              warnings
            };
          }
          warnings.push(`[DRY RUN] Would block: ${check.reason}`);
        }
      }

      // Execute the action
      const result = await fn();

      // Log successful action
      auditId = await this.guard.audit.log({
        action,
        details: { result: 'success' }
      });

      return {
        success: true,
        result,
        warnings,
        auditId
      };

    } catch (error) {
      // Log failed action
      auditId = await this.guard.audit.log({
        action,
        details: { result: 'error', error: error instanceof Error ? error.message : String(error) }
      });

      return {
        success: false,
        reason: error instanceof Error ? error.message : String(error),
        warnings,
        auditId
      };
    }
  }

  /**
   * Guard a transaction before signing/sending
   */
  async guardTransaction(
    tx: TransactionRequest,
    action: string = 'transaction'
  ): Promise<GuardResult> {
    const result = await this.guard.checkTransaction(tx, action);

    if (!result.allowed) {
      this.config.onBlocked?.(action, result.reason || 'Blocked', result);
    }

    return result;
  }

  /**
   * Sanitize user input before processing
   */
  async sanitizeInput(input: string): Promise<string> {
    const result = await this.guard.sanitizeInput(input);
    
    if (result.threats > 0) {
      this.config.onInjection?.(input, result.threats);
    }

    return result.clean;
  }

  /**
   * Redact secrets from output
   */
  async redactOutput(output: string): Promise<string> {
    const result = await this.guard.redactOutput(output);

    if (result.secretsRedacted > 0) {
      this.config.onSecretLeak?.(result.secretsRedacted);
    }

    return result.clean;
  }

  // ============================================================
  // Guarded Transaction Methods
  // ============================================================

  /**
   * Guarded ETH transfer
   */
  async transfer(to: Address, ethAmount: number): Promise<GuardedAction<Hash>> {
    return this.execute('transfer', async () => {
      const value = parseEther(ethAmount.toString());
      
      const tx: TransactionRequest = {
        to,
        value,
        account: this.walletClient.account!,
      };

      // Guard the transaction
      const guardResult = await this.guardTransaction(tx, 'transfer');
      if (!guardResult.allowed && !this.config.dryRun) {
        throw new Error(guardResult.reason);
      }

      // Estimate gas
      const gas = await this.publicClient.estimateGas(tx);
      tx.gas = gas;

      // Send transaction
      const hash = await this.walletClient.sendTransaction(tx);
      
      // Record spend for limits
      this.guard.firewall.recordSpend(value);
      
      return hash;
    });
  }

  /**
   * Guarded contract interaction
   */
  async callContract(
    contractAddress: Address,
    data: `0x${string}`,
    ethValue: number = 0
  ): Promise<GuardedAction<Hash>> {
    return this.execute('contract_call', async () => {
      const value = ethValue > 0 ? parseEther(ethValue.toString()) : 0n;
      
      const tx: TransactionRequest = {
        to: contractAddress,
        data,
        value,
        account: this.walletClient.account!,
      };

      // Guard the transaction
      const guardResult = await this.guardTransaction(tx, 'contract_call');
      if (!guardResult.allowed && !this.config.dryRun) {
        throw new Error(guardResult.reason);
      }

      // Estimate gas
      const gas = await this.publicClient.estimateGas(tx);
      tx.gas = gas;

      // Send transaction
      const hash = await this.walletClient.sendTransaction(tx);
      
      // Record spend for limits
      if (value > 0n) {
        this.guard.firewall.recordSpend(value);
      }
      
      return hash;
    });
  }

  /**
   * Guarded ERC-20 token approve
   */
  async approveToken(
    tokenAddress: Address,
    spenderAddress: Address,
    amount: bigint
  ): Promise<GuardedAction<Hash>> {
    return this.execute('token_approve', async () => {
      // ERC-20 approve function selector and data
      const data = `0x095ea7b3${spenderAddress.slice(2).padStart(64, '0')}${amount.toString(16).padStart(64, '0')}` as `0x${string}`;
      
      const tx: TransactionRequest = {
        to: tokenAddress,
        data,
        account: this.walletClient.account!,
      };

      // Guard the transaction (will warn about unlimited approvals)
      const guardResult = await this.guardTransaction(tx, 'token_approve');
      if (!guardResult.allowed && !this.config.dryRun) {
        throw new Error(guardResult.reason);
      }

      // Estimate gas
      const gas = await this.publicClient.estimateGas(tx);
      tx.gas = gas;

      // Send transaction
      const hash = await this.walletClient.sendTransaction(tx);
      
      return hash;
    });
  }

  /**
   * Guarded ERC-20 token transfer
   */
  async transferToken(
    tokenAddress: Address,
    to: Address,
    amount: bigint
  ): Promise<GuardedAction<Hash>> {
    return this.execute('token_transfer', async () => {
      // ERC-20 transfer function selector and data
      const data = `0xa9059cbb${to.slice(2).padStart(64, '0')}${amount.toString(16).padStart(64, '0')}` as `0x${string}`;
      
      const tx: TransactionRequest = {
        to: tokenAddress,
        data,
        account: this.walletClient.account!,
      };

      // Guard the transaction
      const guardResult = await this.guardTransaction(tx, 'token_transfer');
      if (!guardResult.allowed && !this.config.dryRun) {
        throw new Error(guardResult.reason);
      }

      // Estimate gas
      const gas = await this.publicClient.estimateGas(tx);
      tx.gas = gas;

      // Send transaction
      const hash = await this.walletClient.sendTransaction(tx);
      
      return hash;
    });
  }

  /**
   * Get ETH balance (read-only, no guard needed but logged)
   */
  async getBalance(address?: Address): Promise<GuardedAction<bigint>> {
    return this.execute('get_balance', async () => {
      const addr = address || this.walletClient.account!.address;
      return await this.publicClient.getBalance({ address: addr });
    });
  }

  /**
   * Get ERC-20 token balance (read-only)
   */
  async getTokenBalance(tokenAddress: Address, address?: Address): Promise<GuardedAction<bigint>> {
    return this.execute('get_token_balance', async () => {
      const addr = address || this.walletClient.account!.address;
      
      // ERC-20 balanceOf function call
      const data = `0x70a08231${addr.slice(2).padStart(64, '0')}` as `0x${string}`;
      
      const result = await this.publicClient.call({
        to: tokenAddress,
        data,
      });

      if (!result.data) {
        throw new Error('Failed to read token balance');
      }

      return BigInt(result.data);
    });
  }

  // ============================================================
  // Audit & Stats
  // ============================================================

  async getAuditStats() {
    return this.guard.getStats();
  }

  async exportAuditLog(): Promise<string> {
    return this.guard.exportAuditLog();
  }

  /**
   * Get current firewall status
   */
  getFirewallStatus() {
    return {
      remainingDaily: this.guard.firewall.getRemainingDaily(),
    };
  }
}

/**
 * Create a security-wrapped EVM agent
 */
export async function createGuardedAgent(
  account: Account,
  rpcUrl?: string,
  config: GuardedAgentConfig = {}
): Promise<GuardedEVMAgent> {
  const chain = config.chain === 'mainnet' ? mainnet : base;
  
  // Create viem clients
  const walletClient = createWalletClient({
    account,
    chain,
    transport: http(rpcUrl || (config.chain === 'mainnet' 
      ? 'https://eth.llamarpc.com' 
      : 'https://mainnet.base.org')),
  });

  const publicClient = createPublicClient({
    chain,
    transport: http(rpcUrl || (config.chain === 'mainnet' 
      ? 'https://eth.llamarpc.com' 
      : 'https://mainnet.base.org')),
  });

  // Create AgentGuard with merged config
  const guard = new AgentGuard({
    ...config,
    rpcUrl,
    chain: config.chain || 'base'
  });

  return new GuardedEVMAgent(walletClient, publicClient, guard, config);
}

export default { createGuardedAgent, GuardedEVMAgent };