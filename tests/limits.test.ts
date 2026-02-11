/**
 * Tests for SpendingLimits
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SpendingLimits } from '../src/firewall/limits';
import { parseEther } from 'viem';

describe('SpendingLimits', () => {
  let limits: SpendingLimits;
  const dailyLimit = parseEther('10'); // 10 ETH
  const perTxLimit = parseEther('1');   // 1 ETH

  beforeEach(() => {
    limits = new SpendingLimits({
      maxDailySpend: dailyLimit,
      maxPerTxSpend: perTxLimit
    });
    vi.clearAllMocks();
  });

  describe('per-transaction limits', () => {
    it('allows transactions within per-tx limit', () => {
      const amount = parseEther('0.5'); // 0.5 ETH
      const result = limits.check(amount);
      
      expect(result.allowed).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('blocks transactions exceeding per-tx limit', () => {
      const amount = parseEther('1.5'); // 1.5 ETH > 1 ETH limit
      const result = limits.check(amount);
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('per-tx limit');
      expect(result.reason).toContain('1.5000 ETH');
      expect(result.reason).toContain('1.0000 ETH');
    });

    it('allows transactions exactly at per-tx limit', () => {
      const amount = parseEther('1'); // Exactly 1 ETH
      const result = limits.check(amount);
      
      expect(result.allowed).toBe(true);
    });

    it('handles zero-value transactions', () => {
      const result = limits.check(0n);
      expect(result.allowed).toBe(true);
    });
  });

  describe('daily spending limits', () => {
    it('allows transactions within daily limit', () => {
      limits.recordSpend(parseEther('5')); // Spend 5 ETH
      
      const amount = parseEther('0.5'); // Try to spend 0.5 ETH more
      const result = limits.check(amount);
      
      expect(result.allowed).toBe(true);
      expect(result.currentDailySpend).toBe(parseEther('5'));
      expect(result.remainingDaily).toBe(parseEther('4.5'));
    });

    it('blocks transactions that would exceed daily limit', () => {
      limits.recordSpend(parseEther('9.5')); // Spend 9.5 ETH
      
      const amount = parseEther('1'); // Try to spend 1 ETH more (total 10.5)
      const result = limits.check(amount);
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('daily limit');
      expect(result.reason).toContain('9.5000 ETH');
      expect(result.reason).toContain('1.0000 ETH');
      expect(result.reason).toContain('10.0000 ETH');
    });

    it('allows transactions up to daily limit', () => {
      limits.recordSpend(parseEther('9')); // Spend 9 ETH
      
      const amount = parseEther('1'); // Spend exactly the remaining 1 ETH
      const result = limits.check(amount);
      
      expect(result.allowed).toBe(true);
      expect(result.remainingDaily).toBe(0n);
    });

    it('tracks cumulative spending', () => {
      limits.recordSpend(parseEther('2'));
      limits.recordSpend(parseEther('3'));
      
      const status = limits.getStatus();
      expect(status.dailySpend).toBe(parseEther('5'));
    });
  });

  describe('daily reset functionality', () => {
    beforeEach(() => {
      // Mock Date.now to control time
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('resets daily spend on new day', () => {
      // Spend some amount today
      limits.recordSpend(parseEther('5'));
      expect(limits.getStatus().dailySpend).toBe(parseEther('5'));
      
      // Move to next day
      vi.setSystemTime(new Date('2024-01-02T12:00:00Z'));
      
      // Check should reset daily spend
      const result = limits.check(parseEther('1'));
      expect(result.allowed).toBe(true);
      expect(result.currentDailySpend).toBe(0n);
    });

    it('handles manual daily reset', () => {
      limits.recordSpend(parseEther('8'));
      expect(limits.getStatus().dailySpend).toBe(parseEther('8'));
      
      limits.resetDailySpend();
      expect(limits.getStatus().dailySpend).toBe(0n);
    });

    it('preserves spending within same day', () => {
      limits.recordSpend(parseEther('3'));
      
      // Move forward a few hours (same day)
      vi.setSystemTime(new Date('2024-01-01T18:00:00Z'));
      
      const status = limits.getStatus();
      expect(status.dailySpend).toBe(parseEther('3'));
    });
  });

  describe('status reporting', () => {
    it('reports correct status with no spending', () => {
      const status = limits.getStatus();
      
      expect(status.dailySpend).toBe(0n);
      expect(status.dailyLimit).toBe(dailyLimit);
      expect(status.perTxLimit).toBe(perTxLimit);
    });

    it('reports correct status with partial spending', () => {
      limits.recordSpend(parseEther('3.5'));
      
      const status = limits.getStatus();
      expect(status.dailySpend).toBe(parseEther('3.5'));
      expect(status.dailyLimit).toBe(parseEther('10'));
      expect(status.perTxLimit).toBe(parseEther('1'));
    });

    it('reports remaining daily allowance correctly', () => {
      limits.recordSpend(parseEther('7'));
      
      const result = limits.check(parseEther('0.5'));
      expect(result.remainingDaily).toBe(parseEther('2.5')); // 10 - 7 - 0.5
    });
  });

  describe('wei amount handling', () => {
    it('handles small wei amounts', () => {
      const oneWei = 1n;
      const result = limits.check(oneWei);
      expect(result.allowed).toBe(true);
    });

    it('formats wei amounts correctly in errors', () => {
      const smallAmount = 1000000n; // 1 million wei
      const limits = new SpendingLimits({
        maxDailySpend: parseEther('1'),
        maxPerTxSpend: smallAmount - 1n // Just under 1 million wei
      });

      const result = limits.check(smallAmount);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('wei'); // Should show wei for small amounts
    });

    it('formats ETH amounts correctly for larger values', () => {
      const largeAmount = parseEther('1.5');
      const result = limits.check(largeAmount);
      
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('1.5000 ETH');
    });
  });

  describe('edge cases', () => {
    it('handles zero limits', () => {
      const zeroLimits = new SpendingLimits({
        maxDailySpend: 0n,
        maxPerTxSpend: 0n
      });

      const result = zeroLimits.check(1n);
      expect(result.allowed).toBe(false);
    });

    it('handles very large limits', () => {
      const hugeLimits = new SpendingLimits({
        maxDailySpend: parseEther('1000000'),
        maxPerTxSpend: parseEther('100000')
      });

      const result = hugeLimits.check(parseEther('1000'));
      expect(result.allowed).toBe(true);
    });

    it('handles negative spending (should not happen but be safe)', () => {
      // This shouldn't happen in normal usage, but ensure it doesn't break
      expect(() => limits.recordSpend(-1n)).not.toThrow();
    });

    it('handles maximum BigInt values', () => {
      const maxValue = 2n ** 256n - 1n; // Max uint256
      const result = limits.check(maxValue);
      expect(result.allowed).toBe(false); // Should exceed limits
    });
  });

  describe('concurrent access simulation', () => {
    it('handles rapid sequential checks', () => {
      const amount = parseEther('0.1');
      
      // Simulate rapid checks
      for (let i = 0; i < 10; i++) {
        const result = limits.check(amount);
        expect(result.allowed).toBe(true);
        limits.recordSpend(amount);
      }
      
      // Should have spent 1 ETH total
      expect(limits.getStatus().dailySpend).toBe(parseEther('1'));
    });

    it('correctly calculates remaining after multiple transactions', () => {
      const amounts = [
        parseEther('1'),    // 1 ETH
        parseEther('2.5'),  // 2.5 ETH  
        parseEther('3'),    // 3 ETH
        parseEther('2')     // 2 ETH
      ];

      for (const amount of amounts) {
        if (amount <= perTxLimit) { // Only if within per-tx limit
          const result = limits.check(amount);
          if (result.allowed) {
            limits.recordSpend(amount);
          }
        }
      }

      // Should have spent 1 + 3 + 2 = 6 ETH (2.5 rejected for per-tx limit)
      expect(limits.getStatus().dailySpend).toBe(parseEther('6'));
    });
  });
});