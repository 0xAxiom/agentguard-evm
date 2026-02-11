/**
 * Tests for ContractAllowlist
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ContractAllowlist, SAFE_SYSTEM_CONTRACTS, KNOWN_MALICIOUS_CONTRACTS } from '../src/firewall/allowlist';
import type { Address } from 'viem';

describe('ContractAllowlist', () => {
  let allowlist: ContractAllowlist;
  
  const testContract: Address = '0x742d35Cc6634C0532925a3b8D23C5d3ce87CDD4b';
  const maliciousContract: Address = '0x1111111111111111111111111111111111111111';
  const unknownContract: Address = '0x2222222222222222222222222222222222222222';

  beforeEach(() => {
    allowlist = new ContractAllowlist({});
  });

  describe('blocklist mode (default)', () => {
    it('allows unknown contracts by default', () => {
      const result = allowlist.check(testContract);
      
      expect(result.allowed).toBe(true);
      expect(result.status).toBe('allowed');
      expect(result.contractAddress).toBe(testContract);
    });

    it('allows system contracts', () => {
      const wethContract = SAFE_SYSTEM_CONTRACTS[0] as Address;
      const result = allowlist.check(wethContract);
      
      expect(result.allowed).toBe(true);
      expect(result.status).toBe('system_safe');
    });

    it('blocks contracts in user blocklist', () => {
      const blocklistAllowlist = new ContractAllowlist({
        blockedContracts: [maliciousContract]
      });

      const result = blocklistAllowlist.check(maliciousContract);
      
      expect(result.allowed).toBe(false);
      expect(result.status).toBe('blocked');
      expect(result.reason).toContain('blocked');
      expect(result.reason).toContain(maliciousContract);
    });

    it('blocks known malicious contracts', () => {
      // Mock a known malicious contract by directly testing the pattern
      const testMalicious: Address = '0x0000000000000000000000000000000000000000';
      
      const maliciousAllowlist = new ContractAllowlist({
        blockedContracts: [testMalicious]
      });

      const result = maliciousAllowlist.check(testMalicious);
      expect(result.allowed).toBe(false);
      expect(result.status).toBe('blocked');
    });

    it('handles case-insensitive address comparison', () => {
      const lowerCaseContract = testContract.toLowerCase() as Address;
      const upperCaseContract = testContract.toUpperCase() as Address;

      const caseAllowlist = new ContractAllowlist({
        blockedContracts: [lowerCaseContract]
      });

      // Should block both cases
      expect(caseAllowlist.check(lowerCaseContract).allowed).toBe(false);
      expect(caseAllowlist.check(upperCaseContract).allowed).toBe(false);
      expect(caseAllowlist.check(testContract).allowed).toBe(false);
    });
  });

  describe('allowlist mode', () => {
    it('only allows contracts in allowlist', () => {
      const allowlistMode = new ContractAllowlist({
        allowedContracts: [testContract]
      });

      // Allowed contract should pass
      const allowedResult = allowlistMode.check(testContract);
      expect(allowedResult.allowed).toBe(true);
      expect(allowedResult.status).toBe('allowed');

      // Unknown contract should fail
      const unknownResult = allowlistMode.check(unknownContract);
      expect(unknownResult.allowed).toBe(false);
      expect(unknownResult.status).toBe('not_in_allowlist');
      expect(unknownResult.reason).toContain('not in allowlist');
    });

    it('allows system contracts even in allowlist mode', () => {
      const strictAllowlist = new ContractAllowlist({
        allowedContracts: [testContract], // Only one contract allowed
        allowSystemContracts: true
      });

      const systemContract = SAFE_SYSTEM_CONTRACTS[0] as Address;
      const result = strictAllowlist.check(systemContract);
      
      expect(result.allowed).toBe(true);
      expect(result.status).toBe('system_safe');
    });

    it('can disable system contracts', () => {
      const noSystemAllowlist = new ContractAllowlist({
        allowedContracts: [testContract],
        allowSystemContracts: false
      });

      const systemContract = SAFE_SYSTEM_CONTRACTS[0] as Address;
      const result = noSystemAllowlist.check(systemContract);
      
      expect(result.allowed).toBe(false);
      expect(result.status).toBe('not_in_allowlist');
    });

    it('still respects blocklist in allowlist mode', () => {
      const strictAllowlist = new ContractAllowlist({
        allowedContracts: [testContract, maliciousContract],
        blockedContracts: [maliciousContract]
      });

      // Allowed contract should work
      expect(strictAllowlist.check(testContract).allowed).toBe(true);

      // Blocked contract should fail even if in allowlist
      const result = strictAllowlist.check(maliciousContract);
      expect(result.allowed).toBe(false);
      expect(result.status).toBe('blocked');
    });
  });

  describe('batch operations', () => {
    it('checks multiple contracts at once', () => {
      const contracts = [testContract, unknownContract];
      const results = allowlist.checkAll(contracts);
      
      expect(results).toHaveLength(2);
      expect(results[0].contractAddress).toBe(testContract);
      expect(results[1].contractAddress).toBe(unknownContract);
      expect(results.every(r => r.allowed)).toBe(true);
    });

    it('reports failures in batch operations', () => {
      const blocklistAllowlist = new ContractAllowlist({
        blockedContracts: [maliciousContract]
      });

      const contracts = [testContract, maliciousContract, unknownContract];
      const results = blocklistAllowlist.checkAll(contracts);
      
      expect(results).toHaveLength(3);
      expect(results[0].allowed).toBe(true);  // testContract
      expect(results[1].allowed).toBe(false); // maliciousContract
      expect(results[2].allowed).toBe(true);  // unknownContract
    });

    it('handles empty contract list', () => {
      const results = allowlist.checkAll([]);
      expect(results).toHaveLength(0);
    });
  });

  describe('runtime modifications', () => {
    it('allows adding contracts to blocklist at runtime', () => {
      // Initially allowed
      expect(allowlist.check(testContract).allowed).toBe(true);

      // Add to blocklist
      allowlist.addToBlocklist(testContract);

      // Now blocked
      expect(allowlist.check(testContract).allowed).toBe(false);
    });

    it('allows adding contracts to allowlist in allowlist mode', () => {
      const allowlistMode = new ContractAllowlist({
        allowedContracts: [testContract]
      });

      // Initially not allowed
      expect(allowlistMode.check(unknownContract).allowed).toBe(false);

      // Add to allowlist
      const success = allowlistMode.addToAllowlist(unknownContract);
      expect(success).toBe(true);

      // Now allowed
      expect(allowlistMode.check(unknownContract).allowed).toBe(true);
    });

    it('cannot add to allowlist when not in allowlist mode', () => {
      const success = allowlist.addToAllowlist(testContract);
      expect(success).toBe(false);
    });

    it('preserves case insensitivity for runtime additions', () => {
      const upperCase = testContract.toUpperCase() as Address;
      const lowerCase = testContract.toLowerCase() as Address;

      allowlist.addToBlocklist(upperCase);

      // Both cases should be blocked
      expect(allowlist.check(lowerCase).allowed).toBe(false);
      expect(allowlist.check(testContract).allowed).toBe(false);
    });
  });

  describe('status reporting', () => {
    it('reports blocklist-only mode correctly', () => {
      const status = allowlist.getStatus();
      
      expect(status.mode).toBe('blocklist_only');
      expect(status.allowlistSize).toBe(null);
      expect(status.blocklistSize).toBeGreaterThanOrEqual(0);
    });

    it('reports allowlist mode correctly', () => {
      const allowlistMode = new ContractAllowlist({
        allowedContracts: [testContract, unknownContract]
      });

      const status = allowlistMode.getStatus();
      
      expect(status.mode).toBe('allowlist');
      expect(status.allowlistSize).toBe(2);
      expect(status.blocklistSize).toBeGreaterThanOrEqual(0);
    });

    it('tracks blocklist size changes', () => {
      const initialStatus = allowlist.getStatus();
      const initialSize = initialStatus.blocklistSize;

      allowlist.addToBlocklist(testContract);

      const updatedStatus = allowlist.getStatus();
      expect(updatedStatus.blocklistSize).toBe(initialSize + 1);
    });

    it('tracks allowlist size changes', () => {
      const allowlistMode = new ContractAllowlist({
        allowedContracts: [testContract]
      });

      const initialStatus = allowlistMode.getStatus();
      expect(initialStatus.allowlistSize).toBe(1);

      allowlistMode.addToAllowlist(unknownContract);

      const updatedStatus = allowlistMode.getStatus();
      expect(updatedStatus.allowlistSize).toBe(2);
    });
  });

  describe('system contract handling', () => {
    it('recognizes all system contracts', () => {
      SAFE_SYSTEM_CONTRACTS.forEach(contract => {
        const result = allowlist.check(contract);
        expect(result.allowed).toBe(true);
        expect(result.status).toBe('system_safe');
      });
    });

    it('allows disabling system contract recognition', () => {
      const noSystemAllowlist = new ContractAllowlist({
        allowSystemContracts: false
      });

      const systemContract = SAFE_SYSTEM_CONTRACTS[0] as Address;
      const result = noSystemAllowlist.check(systemContract);
      
      expect(result.allowed).toBe(true); // Still allowed in blocklist-only mode
      expect(result.status).toBe('allowed'); // But not as system_safe
    });
  });

  describe('edge cases and error handling', () => {
    it('handles invalid addresses gracefully', () => {
      const invalidAddresses = [
        '0x123', // Too short
        '0x' + 'g'.repeat(40), // Invalid hex
        '', // Empty
        'not-an-address' // Completely invalid
      ];

      invalidAddresses.forEach(addr => {
        expect(() => {
          allowlist.check(addr as Address);
        }).not.toThrow();
      });
    });

    it('handles null/undefined input', () => {
      expect(() => {
        // @ts-expect-error Testing invalid input
        allowlist.check(null);
      }).not.toThrow();

      expect(() => {
        // @ts-expect-error Testing invalid input
        allowlist.check(undefined);
      }).not.toThrow();
    });

    it('handles very long address strings', () => {
      const longAddress = ('0x' + 'a'.repeat(100)) as Address;
      const result = allowlist.check(longAddress);
      
      expect(result).toBeDefined();
      expect(result.contractAddress).toBe(longAddress);
    });

    it('handles empty allowlist/blocklist configs', () => {
      const emptyAllowlist = new ContractAllowlist({
        allowedContracts: [],
        blockedContracts: []
      });

      expect(emptyAllowlist.getStatus().allowlistSize).toBe(0);
      expect(emptyAllowlist.getStatus().blocklistSize).toBeGreaterThanOrEqual(0); // May have known malicious
    });
  });

  describe('configuration combinations', () => {
    it('handles allowlist and blocklist together', () => {
      const combined = new ContractAllowlist({
        allowedContracts: [testContract, maliciousContract],
        blockedContracts: [maliciousContract]
      });

      expect(combined.check(testContract).allowed).toBe(true);
      expect(combined.check(maliciousContract).allowed).toBe(false); // Blocklist wins
      expect(combined.check(unknownContract).allowed).toBe(false); // Not in allowlist
    });

    it('prioritizes blocklist over allowlist', () => {
      const conflicted = new ContractAllowlist({
        allowedContracts: [testContract],
        blockedContracts: [testContract] // Same contract in both
      });

      const result = conflicted.check(testContract);
      expect(result.allowed).toBe(false);
      expect(result.status).toBe('blocked');
    });

    it('prioritizes blocklist over system contracts', () => {
      const systemContract = SAFE_SYSTEM_CONTRACTS[0] as Address;
      const blockedSystem = new ContractAllowlist({
        blockedContracts: [systemContract]
      });

      const result = blockedSystem.check(systemContract);
      expect(result.allowed).toBe(false);
      expect(result.status).toBe('blocked');
    });
  });

  describe('performance', () => {
    it('handles large allowlists efficiently', () => {
      const largeAllowlist = Array.from({ length: 1000 }, (_, i) => 
        `0x${'a'.repeat(39)}${i.toString().padStart(1, '0')}` as Address
      );

      const allowlistMode = new ContractAllowlist({
        allowedContracts: largeAllowlist
      });

      const start = Date.now();
      const result = allowlistMode.check(largeAllowlist[500]);
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(100); // Should be fast
      expect(result.allowed).toBe(true);
    });

    it('handles large batch operations efficiently', () => {
      const manyContracts = Array.from({ length: 100 }, (_, i) => 
        `0x${'b'.repeat(39)}${i.toString().padStart(1, '0')}` as Address
      );

      const start = Date.now();
      const results = allowlist.checkAll(manyContracts);
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(100);
      expect(results).toHaveLength(100);
    });
  });
});