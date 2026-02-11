/**
 * Tests for TransactionSimulator
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TransactionSimulator } from '../src/firewall/simulator';
import { parseEther, type TransactionRequest, type Address } from 'viem';

// Mock viem
vi.mock('viem', async () => {
  const actual = await vi.importActual('viem');
  return {
    ...actual,
    createPublicClient: vi.fn().mockReturnValue({
      call: vi.fn(),
      estimateGas: vi.fn(),
      getGasPrice: vi.fn().mockResolvedValue(1000000000n), // 1 gwei
    })
  };
});

describe('TransactionSimulator', () => {
  let simulator: TransactionSimulator;
  let mockClient: any;
  const mockAddress: Address = '0x742d35Cc6634C0532925a3b8D23C5d3ce87CDD4b';
  const mockContract: Address = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

  beforeEach(() => {
    const { createPublicClient } = vi.hoisted(() => ({
      createPublicClient: vi.fn()
    }));
    
    mockClient = {
      call: vi.fn().mockResolvedValue({
        data: '0x0000000000000000000000000000000000000000000000000000000000000001'
      }),
      estimateGas: vi.fn().mockResolvedValue(21000n),
      getGasPrice: vi.fn().mockResolvedValue(1000000000n),
    };
    
    createPublicClient.mockReturnValue(mockClient);

    simulator = new TransactionSimulator({
      chain: 'base',
      rpcUrl: 'https://mainnet.base.org'
    });
  });

  describe('transaction simulation', () => {
    it('simulates successful transactions', async () => {
      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3', // approve
        value: parseEther('0.1'),
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      
      expect(result.success).toBe(true);
      expect(result.returnData).toBeDefined();
      expect(result.warnings).toBeDefined();
      expect(mockClient.call).toHaveBeenCalledWith({
        to: tx.to,
        data: tx.data,
        value: tx.value,
        gas: tx.gas,
        account: tx.from
      });
    });

    it('handles simulation failures', async () => {
      mockClient.call.mockRejectedValue(new Error('execution reverted'));

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('execution reverted');
      expect(result.warnings).toBeDefined();
    });

    it('handles insufficient funds error', async () => {
      mockClient.call.mockRejectedValue(new Error('insufficient funds for gas * price + value'));

      const tx: TransactionRequest = {
        to: mockAddress,
        value: parseEther('1000'),
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('insufficient funds');
      expect(result.warnings.some(w => w.includes('Check ETH balance'))).toBe(true);
    });

    it('handles revert errors', async () => {
      mockClient.call.mockRejectedValue(new Error('execution reverted: ERC20: insufficient allowance'));

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x23b872dd', // transferFrom
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('revert');
      expect(result.warnings.some(w => w.includes('Contract execution would fail'))).toBe(true);
    });

    it('estimates gas when not provided', async () => {
      mockClient.estimateGas.mockResolvedValue(50000n);

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      
      expect(result.success).toBe(true);
      expect(result.gasUsed).toBe(50000n);
      expect(mockClient.estimateGas).toHaveBeenCalled();
    });

    it('warns about high gas usage', async () => {
      mockClient.estimateGas.mockResolvedValue(1000000n); // 1M gas

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      
      expect(result.success).toBe(true);
      expect(result.warnings.some(w => w.includes('High gas usage'))).toBe(true);
    });
  });

  describe('spend estimation', () => {
    it('estimates transaction cost accurately', async () => {
      mockClient.getGasPrice.mockResolvedValue(2000000000n); // 2 gwei
      mockClient.estimateGas.mockResolvedValue(50000n);

      const tx: TransactionRequest = {
        to: mockAddress,
        value: parseEther('0.1'),
        from: mockAddress
      };

      const result = await simulator.estimateSpend(tx, mockAddress);
      
      // Expected: 0.1 ETH (value) + 0.0001 ETH (gas: 50000 * 2 gwei)
      const expectedGasCost = 50000n * 2000000000n; // 0.0001 ETH
      const expectedTotal = parseEther('0.1') + expectedGasCost;
      
      expect(result.estimatedSpend).toBe(expectedTotal);
      expect(result.gasPrice).toBe(2000000000n);
      expect(result.warnings).toBeDefined();
    });

    it('handles gas estimation failures', async () => {
      mockClient.estimateGas.mockRejectedValue(new Error('Gas estimation failed'));

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.estimateSpend(tx, mockAddress);
      
      expect(result.warnings.some(w => w.includes('Could not estimate gas'))).toBe(true);
      expect(result.estimatedSpend).toBeGreaterThan(0n); // Should use fallback
    });

    it('uses different gas defaults for contract interactions', async () => {
      mockClient.estimateGas.mockRejectedValue(new Error('Estimation failed'));

      // Simple transfer
      const transferTx: TransactionRequest = {
        to: mockAddress,
        value: parseEther('0.1'),
        from: mockAddress
      };

      const transferResult = await simulator.estimateSpend(transferTx, mockAddress);

      // Contract interaction
      const contractTx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const contractResult = await simulator.estimateSpend(contractTx, mockAddress);
      
      // Contract interaction should estimate higher gas
      expect(contractResult.estimatedSpend).toBeGreaterThan(transferResult.estimatedSpend);
    });

    it('warns about high-risk transactions', async () => {
      const approveAllData = '0xa22cb465' + // setApprovalForAll
        '000000000000000000000000742d35Cc6634C0532925a3b8D23C5d3ce87CDD4b' + // operator
        '0000000000000000000000000000000000000000000000000000000000000001'; // approved=true

      const tx: TransactionRequest = {
        to: mockContract,
        data: approveAllData as `0x${string}`,
        from: mockAddress
      };

      const result = await simulator.estimateSpend(tx, mockAddress);
      
      expect(result.warnings.some(w => w.includes('high-risk function'))).toBe(true);
    });

    it('warns about zero value contract interactions', async () => {
      const tx: TransactionRequest = {
        to: mockContract,
        value: 0n,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.estimateSpend(tx, mockAddress);
      
      expect(result.warnings.some(w => w.includes('token approvals'))).toBe(true);
    });

    it('warns about high gas estimates', async () => {
      mockClient.estimateGas.mockResolvedValue(800000n); // 800k gas

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.estimateSpend(tx, mockAddress);
      
      expect(result.warnings.some(w => w.includes('High gas estimate'))).toBe(true);
    });
  });

  describe('return data analysis', () => {
    it('analyzes return data for warnings', async () => {
      // Simulate revert reason
      mockClient.call.mockResolvedValue({
        data: '0x08c379a0' + '0'.repeat(56) // Revert reason signature
      });

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      
      expect(result.success).toBe(true);
      expect(result.warnings.some(w => w.includes('revert reason'))).toBe(true);
    });

    it('detects panic codes', async () => {
      // Simulate panic code
      mockClient.call.mockResolvedValue({
        data: '0x4e487b71' + '0'.repeat(56) // Panic signature
      });

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      
      expect(result.success).toBe(true);
      expect(result.warnings.some(w => w.includes('panic'))).toBe(true);
    });
  });

  describe('contract address extraction', () => {
    it('extracts contract addresses from transactions', () => {
      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const addresses = simulator.extractContractAddresses(tx);
      
      expect(addresses).toContain(mockContract);
      expect(addresses).toHaveLength(1);
    });

    it('handles transactions without contract addresses', () => {
      const tx: TransactionRequest = {
        to: undefined,
        value: parseEther('0.1'),
        from: mockAddress
      };

      const addresses = simulator.extractContractAddresses(tx);
      
      expect(addresses).toHaveLength(0);
    });
  });

  describe('retry mechanism', () => {
    it('retries failed simulations', async () => {
      let callCount = 0;
      mockClient.call.mockImplementation(() => {
        callCount++;
        if (callCount < 2) {
          return Promise.reject(new Error('Network error'));
        }
        return Promise.resolve({ data: '0x1' });
      });

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      
      expect(result.success).toBe(true);
      expect(mockClient.call).toHaveBeenCalledTimes(2);
    });

    it('gives up after max retries', async () => {
      mockClient.call.mockRejectedValue(new Error('Persistent error'));

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Persistent error');
      expect(mockClient.call).toHaveBeenCalledTimes(2); // Default max retries
    });
  });

  describe('configuration', () => {
    it('uses correct chain configuration', () => {
      const mainnetSimulator = new TransactionSimulator({
        chain: 'mainnet',
        rpcUrl: 'https://eth.llamarpc.com'
      });

      expect(mainnetSimulator).toBeInstanceOf(TransactionSimulator);
    });

    it('uses default Base configuration', () => {
      const defaultSimulator = new TransactionSimulator({});
      expect(defaultSimulator).toBeInstanceOf(TransactionSimulator);
    });

    it('respects custom retry settings', () => {
      const customSimulator = new TransactionSimulator({
        maxRetries: 5
      });
      expect(customSimulator).toBeInstanceOf(TransactionSimulator);
    });
  });

  describe('edge cases', () => {
    it('handles empty transaction data', async () => {
      const tx: TransactionRequest = {
        to: mockAddress,
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      expect(result.success).toBe(true);
    });

    it('handles very large gas estimates', async () => {
      mockClient.estimateGas.mockResolvedValue(10000000n); // 10M gas

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.estimateSpend(tx, mockAddress);
      expect(result.warnings.some(w => w.includes('High gas'))).toBe(true);
    });

    it('handles gas price fetch failures', async () => {
      mockClient.getGasPrice.mockRejectedValue(new Error('Gas price unavailable'));

      const tx: TransactionRequest = {
        to: mockAddress,
        value: parseEther('0.1'),
        from: mockAddress
      };

      const result = await simulator.estimateSpend(tx, mockAddress);
      
      expect(result.warnings.some(w => w.includes('gas price'))).toBe(true);
      expect(result.gasPrice).toBe(1000000000n); // Should use default
    });

    it('handles null return data', async () => {
      mockClient.call.mockResolvedValue({ data: null });

      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const result = await simulator.simulate(tx);
      expect(result.success).toBe(true);
      expect(result.returnData).toBeNull();
    });
  });

  describe('performance', () => {
    it('completes simulation within reasonable time', async () => {
      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const start = Date.now();
      await simulator.simulate(tx);
      const duration = Date.now() - start;
      
      expect(duration).toBeLessThan(1000); // Should be fast
    });

    it('handles concurrent simulations', async () => {
      const tx: TransactionRequest = {
        to: mockContract,
        data: '0x095ea7b3',
        from: mockAddress
      };

      const promises = Array.from({ length: 10 }, () => simulator.simulate(tx));
      const results = await Promise.all(promises);
      
      expect(results).toHaveLength(10);
      expect(results.every(r => r.success)).toBe(true);
    });
  });
});