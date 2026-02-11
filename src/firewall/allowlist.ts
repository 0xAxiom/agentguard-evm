/**
 * Contract allowlist/blocklist management for EVM transaction firewall
 */

import type { Address } from 'viem';

// Known malicious contracts (maintained blocklist)
export const KNOWN_MALICIOUS_CONTRACTS: Address[] = [
  // Add known malicious contract addresses here
  // These are always blocked regardless of user config
  '0x0000000000000000000000000000000000000000' as Address, // Example placeholder
];

// Common safe system contracts on Base
export const SAFE_SYSTEM_CONTRACTS: Address[] = [
  '0x4200000000000000000000000000000000000006' as Address, // WETH on Base
  '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' as Address, // USDC on Base
  '0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA' as Address, // USDbC on Base
  '0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb' as Address, // DAI on Base
  '0x2Ae3F1Ec7F1F5012CFEab0185bfc7aa3cf0DEc22' as Address, // cbETH on Base
  '0x940181a94A35A4569E4529A3CDfB74e38FD98631' as Address, // AERO on Base
];

export interface ContractCheckResult {
  allowed: boolean;
  reason?: string;
  contractAddress: Address;
  status: 'allowed' | 'blocked' | 'not_in_allowlist' | 'system_safe';
}

export interface AllowlistConfig {
  allowedContracts?: Address[];   // If set, ONLY these contracts are allowed (whitelist mode)
  blockedContracts?: Address[];   // Always blocked (added to built-in blocklist)
  allowSystemContracts?: boolean; // Allow common Base system contracts (default: true)
}

export class ContractAllowlist {
  private readonly allowlist: Set<string> | null; // null = no whitelist, allow all except blocked
  private readonly blocklist: Set<string>;
  private readonly systemContracts: Set<string>;
  private readonly allowSystemContracts: boolean;

  constructor(config: AllowlistConfig) {
    // Allowlist mode: if provided, ONLY these contracts are allowed
    this.allowlist = config.allowedContracts 
      ? new Set(config.allowedContracts.map(addr => addr.toLowerCase()))
      : null;

    // Blocklist: user-provided + known malicious
    this.blocklist = new Set([
      ...KNOWN_MALICIOUS_CONTRACTS,
      ...(config.blockedContracts || []),
    ].map(addr => addr.toLowerCase()));

    // System contracts (safe by default)
    this.systemContracts = new Set(SAFE_SYSTEM_CONTRACTS.map(addr => addr.toLowerCase()));
    this.allowSystemContracts = config.allowSystemContracts ?? true;
  }

  /**
   * Check if a contract is allowed
   */
  check(contractAddress: Address): ContractCheckResult {
    const addrLower = contractAddress.toLowerCase();

    // Always check blocklist first
    if (this.blocklist.has(addrLower)) {
      return {
        allowed: false,
        reason: `Contract ${contractAddress} is blocked (malicious or user-blocked)`,
        contractAddress,
        status: 'blocked',
      };
    }

    // System contracts are safe by default
    if (this.allowSystemContracts && this.systemContracts.has(addrLower)) {
      return {
        allowed: true,
        contractAddress,
        status: 'system_safe',
      };
    }

    // If allowlist mode is on, check against it
    if (this.allowlist !== null) {
      if (this.allowlist.has(addrLower)) {
        return {
          allowed: true,
          contractAddress,
          status: 'allowed',
        };
      }
      return {
        allowed: false,
        reason: `Contract ${contractAddress} is not in allowlist`,
        contractAddress,
        status: 'not_in_allowlist',
      };
    }

    // No allowlist mode = allow all (except blocked)
    return {
      allowed: true,
      contractAddress,
      status: 'allowed',
    };
  }

  /**
   * Check multiple contracts at once
   */
  checkAll(contractAddresses: Address[]): ContractCheckResult[] {
    return contractAddresses.map(addr => this.check(addr));
  }

  /**
   * Add a contract to the blocklist at runtime
   */
  addToBlocklist(contractAddress: Address): void {
    this.blocklist.add(contractAddress.toLowerCase());
  }

  /**
   * Add a contract to the allowlist at runtime (if in allowlist mode)
   */
  addToAllowlist(contractAddress: Address): boolean {
    if (this.allowlist === null) {
      return false; // Not in allowlist mode
    }
    this.allowlist.add(contractAddress.toLowerCase());
    return true;
  }

  /**
   * Get current allowlist/blocklist status
   */
  getStatus(): {
    mode: 'allowlist' | 'blocklist_only';
    allowlistSize: number | null;
    blocklistSize: number;
  } {
    return {
      mode: this.allowlist !== null ? 'allowlist' : 'blocklist_only',
      allowlistSize: this.allowlist?.size ?? null,
      blocklistSize: this.blocklist.size,
    };
  }
}