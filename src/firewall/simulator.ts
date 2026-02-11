/**
 * Transaction simulator for EVM pre-flight validation
 */

import { 
  createPublicClient, 
  http, 
  formatEther, 
  type TransactionRequest, 
  type Address, 
  type PublicClient 
} from 'viem';
import { base, mainnet } from 'viem/chains';

export interface SimulationResult {
  success: boolean;
  error?: string;
  gasUsed?: bigint;
  returnData?: string;
  warnings: string[];
}

export interface BalanceChange {
  account: Address;
  preBalance: bigint;
  postBalance: bigint;
  change: bigint;
}

export interface SimulatorConfig {
  rpcUrl?: string;
  chain?: 'base' | 'mainnet';
  maxRetries?: number;
}

export class TransactionSimulator {
  private readonly client: PublicClient;
  private readonly chain: 'base' | 'mainnet';
  private readonly maxRetries: number;

  constructor(config: SimulatorConfig) {
    this.chain = config.chain || 'base';
    this.maxRetries = config.maxRetries || 2;

    const chainConfig = this.chain === 'mainnet' ? mainnet : base;
    this.client = createPublicClient({
      chain: chainConfig,
      transport: http(config.rpcUrl || (this.chain === 'mainnet' 
        ? 'https://eth.llamarpc.com' 
        : 'https://mainnet.base.org'
      )),
    });
  }

  /**
   * Simulate a transaction and return detailed results
   */
  async simulate(
    tx: TransactionRequest,
    _signerAddress?: Address
  ): Promise<SimulationResult> {
    const warnings: string[] = [];

    try {
      // Use eth_call to simulate the transaction
      const simulationResult = await this.simulateWithRetry(async () => {
        return await this.client.call({
          to: tx.to,
          data: tx.data,
          value: tx.value,
          gas: tx.gas,
          account: tx.from,
        });
      });

      // Analyze the result
      if (simulationResult.data) {
        // Check for common error patterns in return data
        const errorWarnings = this.analyzeReturnDataForWarnings(simulationResult.data);
        warnings.push(...errorWarnings);
      }

      // Estimate gas if not provided
      if (!tx.gas && tx.to && tx.from) {
        try {
          const gasEstimate = await this.client.estimateGas({
            to: tx.to,
            data: tx.data,
            value: tx.value,
            account: tx.from,
          });

          if (gasEstimate > 500000n) {
            warnings.push(`High gas usage estimated: ${gasEstimate.toLocaleString()} gas`);
          }

          return {
            success: true,
            returnData: simulationResult.data,
            gasUsed: gasEstimate,
            warnings,
          };
        } catch {
          warnings.push('Could not estimate gas usage');
        }
      }

      return {
        success: true,
        returnData: simulationResult.data,
        warnings,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown simulation error';
      
      // Check for specific error types
      if (errorMessage.toLowerCase().includes('insufficient funds')) {
        return {
          success: false,
          error: 'Transaction would fail: insufficient funds',
          warnings: [...warnings, 'Check ETH balance and gas requirements'],
        };
      }

      if (errorMessage.toLowerCase().includes('revert')) {
        return {
          success: false,
          error: 'Transaction would revert',
          warnings: [...warnings, 'Contract execution would fail'],
        };
      }

      return {
        success: false,
        error: `Simulation failed: ${errorMessage}`,
        warnings,
      };
    }
  }

  /**
   * Get estimated ETH spend from a transaction
   * This is a basic estimation - actual spend may differ
   */
  async estimateSpend(
    tx: TransactionRequest,
    _payerAddress: Address
  ): Promise<{ estimatedSpend: bigint; gasPrice: bigint; warnings: string[] }> {
    const warnings: string[] = [];

    try {
      // Get current gas price
      let gasPrice = 1000000000n; // 1 gwei default
      
      try {
        gasPrice = await this.client.getGasPrice();
      } catch {
        warnings.push('Could not fetch gas price, using default 1 gwei');
      }

      // Estimate gas if not provided
      let gasEstimate = tx.gas || 21000n; // Default for simple transfer
      
      if (!tx.gas && tx.to && tx.from) {
        try {
          gasEstimate = await this.client.estimateGas({
            to: tx.to,
            data: tx.data,
            value: tx.value,
            account: tx.from,
          });
        } catch {
          warnings.push('Could not estimate gas, using default');
          gasEstimate = tx.data && tx.data !== '0x' ? 100000n : 21000n;
        }
      }

      // Calculate total estimated spend (value + gas cost)
      const gasCost = gasPrice * gasEstimate;
      const value = tx.value || 0n;
      const estimatedSpend = value + gasCost;

      // Check for concerning patterns
      if (tx.data && this.isHighRiskTransaction(tx.data)) {
        warnings.push('Transaction contains high-risk function calls');
      }

      if (gasEstimate > 500000n) {
        warnings.push(`High gas estimate: ${gasEstimate.toLocaleString()} gas`);
      }

      if (value === 0n && tx.data && tx.data !== '0x') {
        warnings.push('Contract interaction with no ETH value - check token approvals');
      }

      return { estimatedSpend, gasPrice, warnings };
    } catch (error) {
      warnings.push(`Spend estimation failed: ${error instanceof Error ? error.message : 'unknown'}`);
      return { estimatedSpend: 100000000000000000n, gasPrice: 1000000000n, warnings }; // 0.1 ETH fallback
    }
  }

  /**
   * Extract contract addresses from a transaction
   */
  extractContractAddresses(tx: TransactionRequest): Address[] {
    const addresses: Address[] = [];
    
    if (tx.to) {
      addresses.push(tx.to);
    }

    // Could add more sophisticated address extraction from calldata here
    
    return addresses;
  }

  private isHighRiskTransaction(data: `0x${string}`): boolean {
    const selector = data.slice(0, 10).toLowerCase();
    
    // High-risk function selectors
    const HIGH_RISK_SELECTORS = [
      '0x095ea7b3', // approve
      '0xa22cb465', // setApprovalForAll
      '0x2e1a7d4d', // withdraw
      '0x3ccfd60b', // withdraw
    ];

    return HIGH_RISK_SELECTORS.includes(selector);
  }

  private analyzeReturnDataForWarnings(returnData: `0x${string}`): string[] {
    const warnings: string[] = [];
    
    // Check for common error signatures or patterns
    if (returnData.length > 2) {
      // Check for revert reasons (if present)
      if (returnData.startsWith('0x08c379a0')) {
        warnings.push('Transaction includes revert reason - check contract state');
      }
      
      // Check for panic codes
      if (returnData.startsWith('0x4e487b71')) {
        warnings.push('Transaction would trigger panic (overflow, div by zero, etc.)');
      }
    }
    
    return warnings;
  }

  private async simulateWithRetry<T>(fn: () => Promise<T>): Promise<T> {
    let lastError: Error | null = null;
    
    for (let i = 0; i < this.maxRetries; i++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error instanceof Error ? error : new Error('Unknown error');
        if (i < this.maxRetries - 1) {
          await this.sleep(100 * (i + 1)); // Exponential backoff
        }
      }
    }
    
    throw lastError;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}