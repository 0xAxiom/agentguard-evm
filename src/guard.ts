/**
 * AgentGuard EVM - Main security middleware for Base/EVM agents
 */

import type { TransactionRequest, Address } from 'viem';
import { parseEther } from 'viem';
import { TransactionFirewall, FirewallConfig, FirewallResult } from './firewall';
import { PromptSanitizer, SanitizerConfig, SanitizeResult } from './sanitizer';
import { SecretIsolator, IsolatorConfig, RedactResult } from './isolator';
import { AuditLogger, AuditConfig } from './audit';

export interface AgentGuardConfig {
  firewall?: FirewallConfig;
  sanitizer?: SanitizerConfig;
  isolator?: IsolatorConfig;
  audit?: AuditConfig;
  
  // Convenience options
  maxDailySpendEth?: number;
  maxPerTxSpendEth?: number;
  allowedContracts?: Address[];
  blockedContracts?: Address[];
  strictMode?: boolean;
  rpcUrl?: string;
  chain?: 'base' | 'mainnet';
}

export interface GuardResult {
  allowed: boolean;
  reason?: string;
  warnings: string[];
  firewall: FirewallResult;
  auditId?: string;
}

export class AgentGuard {
  public readonly firewall: TransactionFirewall;
  public readonly sanitizer: PromptSanitizer;
  public readonly isolator: SecretIsolator;
  public readonly audit: AuditLogger;

  constructor(config: AgentGuardConfig = {}) {
    // Convert ETH to wei for firewall config
    const maxDailySpend = config.maxDailySpendEth 
      ? parseEther(config.maxDailySpendEth.toString())
      : parseEther('1'); // 1 ETH default
    
    const maxPerTxSpend = config.maxPerTxSpendEth
      ? parseEther(config.maxPerTxSpendEth.toString())
      : parseEther('0.1'); // 0.1 ETH default

    this.firewall = new TransactionFirewall({
      maxDailySpend,
      maxPerTxSpend,
      allowedContracts: config.allowedContracts,
      blockedContracts: config.blockedContracts,
      requireSimulation: config.firewall?.requireSimulation ?? true,
      rpcUrl: config.rpcUrl,
      chain: config.chain ?? 'base'
    });

    this.sanitizer = new PromptSanitizer({
      strictMode: config.strictMode ?? false,
      ...config.sanitizer
    });

    this.isolator = new SecretIsolator(config.isolator);

    this.audit = new AuditLogger({
      storage: config.audit?.storage ?? 'memory',
      ...config.audit
    });
  }

  /**
   * Check a transaction through all security layers
   */
  async checkTransaction(
    tx: TransactionRequest,
    action: string = 'transaction'
  ): Promise<GuardResult> {
    const warnings: string[] = [];
    
    const firewallResult = await this.firewall.check(tx);
    
    if (firewallResult.warnings) {
      warnings.push(...firewallResult.warnings);
    }

    const auditId = await this.audit.logTransactionCheck(
      action,
      { 
        to: tx.to,
        value: tx.value?.toString(),
        allowed: firewallResult.allowed
      },
      {
        allowed: firewallResult.allowed,
        reason: firewallResult.reason
      }
    );

    return {
      allowed: firewallResult.allowed,
      reason: firewallResult.reason,
      warnings,
      firewall: firewallResult,
      auditId
    };
  }

  /**
   * Sanitize input before sending to LLM
   */
  async sanitizeInput(text: string) {
    const result = this.sanitizer.sanitize(text);
    
    await this.audit.logSanitization(
      text.slice(0, 100),
      result.threats.length,
      result.modified
    );

    return {
      clean: result.clean,
      threats: result.threats.length,
      modified: result.modified
    };
  }

  /**
   * Redact secrets from output
   */
  async redactOutput(text: string) {
    const result = this.isolator.redact(text);
    
    if (result.redacted) {
      await this.audit.logRedaction(
        result.matches.length,
        result.matches.map(m => m.type)
      );
    }

    return {
      clean: result.clean,
      secretsRedacted: result.matches.length
    };
  }

  /**
   * Get audit statistics
   */
  async getStats() {
    return this.audit.getStats();
  }

  // Presets
  static strict(rpcUrl?: string): AgentGuard {
    return new AgentGuard({
      strictMode: true,
      maxDailySpendEth: 0.5,
      maxPerTxSpendEth: 0.05,
      rpcUrl,
      audit: { storage: 'file', filePath: './agentguard-evm-audit.json' }
    });
  }

  static standard(rpcUrl?: string): AgentGuard {
    return new AgentGuard({
      strictMode: false,
      maxDailySpendEth: 1,
      maxPerTxSpendEth: 0.1,
      rpcUrl,
      audit: { storage: 'memory' }
    });
  }
}

export default AgentGuard;
