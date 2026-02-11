/**
 * Tests for TransactionFirewall (EVM)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TransactionFirewall, FirewallConfig } from '../src/firewall';
import { parseEther, type TransactionRequest, type Address } from 'viem';

// Mock viem clients
vi.mock('viem', async () => {
  const actual = await vi.importActual('viem');
  return {
    ...actual,
    createPublicClient: vi.fn().mockReturnValue({
      call: vi.fn().mockResolvedValue({
        data: '0x0000000000000000000000000000000000000000000000000000000000000001'
      }),
      estimateGas: vi.fn().mockResolvedValue(21000n),
      getGasPrice: vi.fn().mockResolvedValue(1000000000n), // 1 gwei
    })
  };
});

describe('TransactionFirewall', () => {
  let firewall: TransactionFirewall;
  const mockAddress: Address = '0x742d35Cc6634C0532925a3b8D23C5d3ce87CDD4b';
  const mockContract: Address = '0x1234567890123456789012345678901234567890';
  const maliciousContract: Address = '0x0000000000000000000000000000000000000000';

  beforeEach(() => {
    firewall = new TransactionFirewall({
      maxDailySpend: parseEther('10'),  // 10 ETH daily limit
      maxPerTxSpend: parseEther('1'),   // 1 ETH per tx limit
      requireSimulation: false,         // Skip simulation for unit tests
      payerAddress: mockAddress,
      chain: 'base'
    });
  });

  describe('spending limits', () => {
    it('allows transactions within per-tx limit', async () => {
      const tx: TransactionRequest = {
        to: mockAddress,
        value: parseEther('0.5'), // 0.5 ETH - within 1 ETH limit
        from: mockAddress
      };

      const result = await firewall.check(tx);
      expect(result.allowed).toBe(true);
    });

    it('blocks transactions exceeding per-tx limit', async () => {
      const tx: TransactionRequest = {
        to: mockAddress,
        value: parseEther('2'), // 2 ETH - exceeds 1 ETH limit
        from: mockAddress
      };

      const result = await firewall.check(tx);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('per-tx limit');
    });

    it('blocks transactions exceeding daily limit', async () => {
      // First transaction uses up most of the daily limit
      const tx1: TransactionRequest = {
        to: mockAddress,
        value: parseEther('9.5'), // 9.5 ETH
        from: mockAddress
      };

      let result = await firewall.check(tx1);
      expect(result.allowed).toBe(true);

      // Second transaction would exceed daily limit
      const tx2: TransactionRequest = {
        to: mockAddress,
        value: parseEther('1'), // 1 ETH - would total 10.5 ETH
        from: mockAddress
      };

      result = await firewall.check(tx2);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('daily limit');
    });

    it('tracks spending correctly', async () => {
      const tx: TransactionRequest = {
        to: mockAddress,
        value: parseEther('1'),
        from: mockAddress
      };

      await firewall.check(tx);
      
      // Manual record spend
      firewall.recordSpend(parseEther('1'));
      
      const remaining = firewall.getRemainingDaily();
      expect(remaining).toBe(parseEther('9')); // 10 - 1 = 9 ETH
    });

    it('resets daily spend counter', async () => {
      firewall.recordSpend(parseEther('5'));
      expect(firewall.getRemainingDaily()).toBe(parseEther('5'));

      firewall.resetDailySpend();
      expect(firewall.getRemainingDaily()).toBe(parseEther('10'));
    });
  });

  describe('contract allowlist/blocklist', () => {
    it('allows any contract by default', async () => {
      const tx: TransactionRequest = {
        to: mockContract,
        value: parseEther('0.1'),
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await firewall.check(tx);
      expect(result.allowed).toBe(true);
    });

    it('blocks contracts in blocklist', async () => {
      const firewallWithBlocklist = new TransactionFirewall({
        maxDailySpend: parseEther('10'),
        maxPerTxSpend: parseEther('1'),
        blockedContracts: [maliciousContract],
        requireSimulation: false,
        payerAddress: mockAddress
      });

      const tx: TransactionRequest = {
        to: maliciousContract,
        value: parseEther('0.1'),
        from: mockAddress
      };

      const result = await firewallWithBlocklist.check(tx);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('blocklist');
    });

    it('only allows allowlisted contracts when set', async () => {
      const firewallWithAllowlist = new TransactionFirewall({
        maxDailySpend: parseEther('10'),
        maxPerTxSpend: parseEther('1'),
        allowedContracts: [mockContract],
        requireSimulation: false,
        payerAddress: mockAddress
      });

      // Allowed contract should work
      const tx1: TransactionRequest = {
        to: mockContract,
        value: parseEther('0.1'),
        from: mockAddress
      };

      let result = await firewallWithAllowlist.check(tx1);
      expect(result.allowed).toBe(true);

      // Non-allowlisted contract should be blocked
      const randomContract: Address = '0x1111111111111111111111111111111111111111';
      const tx2: TransactionRequest = {
        to: randomContract,
        value: parseEther('0.1'),
        from: mockAddress
      };

      result = await firewallWithAllowlist.check(tx2);
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('allowlist');
    });

    it('allows system contracts by default', async () => {
      const wethContract: Address = '0x4200000000000000000000000000000000000006'; // WETH on Base
      
      const firewallWithAllowlist = new TransactionFirewall({
        maxDailySpend: parseEther('10'),
        maxPerTxSpend: parseEther('1'),
        allowedContracts: [], // Empty allowlist, but system contracts should still work
        requireSimulation: false,
        payerAddress: mockAddress
      });

      const tx: TransactionRequest = {
        to: wethContract,
        value: parseEther('0.1'),
        from: mockAddress
      };

      const result = await firewallWithAllowlist.check(tx);
      expect(result.allowed).toBe(true);
    });
  });

  describe('calldata analysis', () => {
    it('warns about unlimited approvals', async () => {
      // ERC-20 approve with max uint256
      const approveData = '0x095ea7b3' + // approve selector
        '000000000000000000000000742d35Cc6634C0532925a3b8D23C5d3ce87CDD4b' + // spender
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'; // max uint256

      const tx: TransactionRequest = {
        to: mockContract,
        data: approveData as `0x${string}`,
        from: mockAddress
      };

      const result = await firewall.check(tx);
      expect(result.allowed).toBe(true);
      expect(result.warnings).toContain('🚨 UNLIMITED APPROVAL detected - consider using exact amount');
    });

    it('warns about suspicious function calls', async () => {
      const setApprovalData = '0xa22cb465' + // setApprovalForAll selector
        '000000000000000000000000742d35Cc6634C0532925a3b8D23C5d3ce87CDD4b' + // operator
        '0000000000000000000000000000000000000000000000000000000000000001'; // approved=true

      const tx: TransactionRequest = {
        to: mockContract,
        data: setApprovalData as `0x${string}`,
        from: mockAddress
      };

      const result = await firewall.check(tx);
      expect(result.allowed).toBe(true);
      expect(result.warnings?.some(w => w.includes('setApprovalForAll'))).toBe(true);
    });
  });

  describe('simulation', () => {
    it('simulates transactions when enabled', async () => {
      const firewallWithSim = new TransactionFirewall({
        maxDailySpend: parseEther('10'),
        maxPerTxSpend: parseEther('1'),
        requireSimulation: true,
        payerAddress: mockAddress
      });

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        value: parseEther('0.1'),
        from: mockAddress
      };

      const result = await firewallWithSim.check(tx);
      expect(result.allowed).toBe(true);
      expect(result.simulationResult).toBeDefined();
      expect(result.simulationResult?.success).toBe(true);
    });

    it('can be disabled for performance', async () => {
      const tx: TransactionRequest = {
        to: mockContract,
        value: parseEther('0.1'),
        from: mockAddress
      };

      const result = await firewall.check(tx);
      expect(result.allowed).toBe(true);
      expect(result.simulationResult).toBeUndefined();
    });
  });

  describe('runtime modifications', () => {
    it('allows adding contracts to blocklist', () => {
      const newMalicious: Address = '0x2222222222222222222222222222222222222222';
      firewall.blockContract(newMalicious);
      
      // Should now block this contract
      const tx: TransactionRequest = {
        to: newMalicious,
        value: parseEther('0.1'),
        from: mockAddress
      };

      return expect(firewall.check(tx)).resolves.toMatchObject({
        allowed: false,
        reason: expect.stringContaining('blocklist')
      });
    });

    it('allows adding contracts to allowlist in allowlist mode', () => {
      const firewallWithAllowlist = new TransactionFirewall({
        maxDailySpend: parseEther('10'),
        maxPerTxSpend: parseEther('1'),
        allowedContracts: [],
        requireSimulation: false,
        payerAddress: mockAddress
      });

      const newAllowed: Address = '0x3333333333333333333333333333333333333333';
      const success = firewallWithAllowlist.allowContract(newAllowed);
      expect(success).toBe(true);
    });

    it('cannot add to allowlist when not in allowlist mode', () => {
      const newContract: Address = '0x4444444444444444444444444444444444444444';
      const success = firewall.allowContract(newContract);
      expect(success).toBe(false);
    });
  });

  describe('status reporting', () => {
    it('reports spending status', () => {
      firewall.recordSpend(parseEther('3'));
      
      const status = firewall.getStatus();
      expect(status.spending.dailySpend).toBe(parseEther('3'));
      expect(status.spending.dailyLimit).toBe(parseEther('10'));
      expect(status.spending.perTxLimit).toBe(parseEther('1'));
      expect(status.spending.remainingDaily).toBe(parseEther('7'));
    });

    it('reports contract allowlist status', () => {
      const status = firewall.getStatus();
      expect(status.contracts.mode).toBe('blocklist_only');
      expect(status.contracts.allowlistSize).toBe(null);
      expect(status.contracts.blocklistSize).toBeGreaterThan(0);
    });
  });

  describe('edge cases', () => {
    it('handles zero value transactions', async () => {
      const tx: TransactionRequest = {
        to: mockContract,
        value: 0n,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await firewall.check(tx);
      expect(result.allowed).toBe(true);
    });

    it('handles transactions without data', async () => {
      const tx: TransactionRequest = {
        to: mockAddress,
        value: parseEther('0.1'),
        from: mockAddress
      };

      const result = await firewall.check(tx);
      expect(result.allowed).toBe(true);
    });

    it('warns when no payer provided for spending estimation', async () => {
      const firewallNoPayer = new TransactionFirewall({
        maxDailySpend: parseEther('10'),
        maxPerTxSpend: parseEther('1'),
        requireSimulation: false
      });

      const tx: TransactionRequest = {
        to: mockAddress,
        value: parseEther('0.1'),
        from: mockAddress
      };

      const result = await firewallNoPayer.check(tx);
      expect(result.allowed).toBe(true);
      expect(result.warnings?.some(w => w.includes('No payer address'))).toBe(true);
    });
  });
});