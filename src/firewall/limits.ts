/**
 * Spending limit tracker for EVM transaction firewall
 */

import { formatEther } from 'viem';

export interface SpendingLimitConfig {
  maxDailySpend: bigint;   // wei
  maxPerTxSpend: bigint;   // wei
}

export interface SpendingCheckResult {
  allowed: boolean;
  reason?: string;
  currentDailySpend: bigint;
  remainingDaily: bigint;
}

export class SpendingLimits {
  private dailySpend: bigint = 0n;
  private lastResetDate: string;
  private readonly maxDaily: bigint;
  private readonly maxPerTx: bigint;

  constructor(config: SpendingLimitConfig) {
    this.maxDaily = config.maxDailySpend;
    this.maxPerTx = config.maxPerTxSpend;
    this.lastResetDate = this.getTodayDate();
  }

  /**
   * Check if a transaction amount is within limits
   */
  check(amountWei: bigint): SpendingCheckResult {
    this.maybeResetDaily();

    // Check per-transaction limit
    if (amountWei > this.maxPerTx) {
      return {
        allowed: false,
        reason: `Transaction amount ${this.formatWei(amountWei)} exceeds per-tx limit of ${this.formatWei(this.maxPerTx)}`,
        currentDailySpend: this.dailySpend,
        remainingDaily: this.maxDaily > this.dailySpend ? this.maxDaily - this.dailySpend : 0n,
      };
    }

    // Check daily limit
    const projectedDaily = this.dailySpend + amountWei;
    if (projectedDaily > this.maxDaily) {
      return {
        allowed: false,
        reason: `Transaction would exceed daily limit. Current: ${this.formatWei(this.dailySpend)}, Tx: ${this.formatWei(amountWei)}, Limit: ${this.formatWei(this.maxDaily)}`,
        currentDailySpend: this.dailySpend,
        remainingDaily: this.maxDaily > this.dailySpend ? this.maxDaily - this.dailySpend : 0n,
      };
    }

    return {
      allowed: true,
      currentDailySpend: this.dailySpend,
      remainingDaily: this.maxDaily - projectedDaily,
    };
  }

  /**
   * Record a spend (call after transaction succeeds)
   */
  recordSpend(amountWei: bigint): void {
    this.maybeResetDaily();
    this.dailySpend += amountWei;
  }

  /**
   * Manually reset daily spend counter
   */
  resetDailySpend(): void {
    this.dailySpend = 0n;
    this.lastResetDate = this.getTodayDate();
  }

  /**
   * Get current spending status
   */
  getStatus(): { dailySpend: bigint; dailyLimit: bigint; perTxLimit: bigint } {
    this.maybeResetDaily();
    return {
      dailySpend: this.dailySpend,
      dailyLimit: this.maxDaily,
      perTxLimit: this.maxPerTx,
    };
  }

  private maybeResetDaily(): void {
    const today = this.getTodayDate();
    if (today !== this.lastResetDate) {
      this.dailySpend = 0n;
      this.lastResetDate = today;
    }
  }

  private getTodayDate(): string {
    return new Date().toISOString().split('T')[0];
  }

  private formatWei(wei: bigint): string {
    const eth = Number(formatEther(wei));
    if (eth >= 0.001) {
      return `${eth.toFixed(4)} ETH`;
    }
    return `${wei.toString()} wei`;
  }
}