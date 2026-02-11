# Architecture

## Design Philosophy

AgentGuard EVM follows the **middleware pattern**: it sits between your AI agent and the EVM blockchain (Base, Ethereum, etc.), intercepting all operations. The goal is defense-in-depth — multiple independent layers that each catch different attack vectors.

```
User Input → [Prompt Sanitizer] → LLM → [Secret Isolator] → Agent Action
                                           ↓
                                   [Transaction Firewall] → EVM
                                           ↓
                                   [Audit Logger] → Memory / File
```

## Modules

### Transaction Firewall (`src/firewall/`)

Three sub-components:

- **SpendingLimits** (`limits.ts`) — Tracks cumulative daily spend and per-transaction maximums. Resets on 24-hour boundaries. All values in wei (ETH).
- **ContractAllowlist** (`allowlist.ts`) — Allowlist/blocklist for EVM contract addresses. Ships with known-safe system contracts (WETH, USDC on Base) and known-malicious contracts. Supports runtime modifications.
- **TransactionSimulator** (`simulator.ts`) — Simulates transactions via `eth_call` before signing. Estimates gas usage and ETH balance changes, catching failures early.

The firewall runs all three checks in sequence: contracts → spending → simulation. First failure short-circuits.

### Prompt Sanitizer (`src/sanitizer/`)

- **Patterns** (`patterns.ts`) — 30+ regex patterns for detecting prompt injection: system prompt overrides, role impersonation, delimiter injection, encoding attacks, unicode homoglyphs.
- **Cleaner** (`cleaner.ts`) — Strips or neutralizes detected threats. Optional strict mode strips all markdown/formatting.

Designed for on-chain data (NFT metadata, token names, transaction memo fields) that gets fed to an LLM.

### Secret Isolator (`src/isolator/`)

Detects and redacts:
- EVM private keys (0x-prefixed 64-character hex strings)
- Seed phrases (BIP39 12/24 word sequences)
- Environment variable patterns (`PRIVATE_KEY=...`)
- API keys and tokens

Configurable: allows EVM addresses (42 chars) through by default but blocks private keys (66 chars).

### Audit Logger (`src/audit/`)

Two storage backends:
- **Memory** — In-process `Map`, fastest, lost on restart
- **File** — JSON on disk, survives restarts

Every security decision is logged: what was checked, what was allowed/blocked, and why.

### EVM Agent Wrapper (`src/wrapper/`)

Drop-in wrapper for EVM agents. Intercepts common actions (transfer, swap, approve, contract calls) and routes through all security layers automatically. Supports:

- Callbacks: `onBlocked`, `onInjection`, `onSecretLeak`
- Dry-run mode for testing
- Custom security checks per action
- Base and Ethereum mainnet support

## Guard Class (`src/guard.ts`)

The main entry point. Composes all modules and provides a unified API:

```typescript
const guard = AgentGuard.strict();      // Conservative defaults (Base)
const guard = AgentGuard.standard();    // Balanced
```

Factory presets configure spending limits, audit storage, and strict mode simultaneously.

## Testing Strategy

200+ tests across 8+ test files:
- Unit tests for each module in isolation
- Integration tests through the Guard class
- End-to-end security flow tests
- Mock EVM interactions (no network dependencies)

All tests run via `vitest` with no network dependencies (RPC calls are mocked).

## Security Model

**Threat model:** A compromised or manipulated LLM trying to:
1. Drain the agent's wallet (→ Firewall: spending limits)
2. Interact with malicious contracts (→ Firewall: allowlist)
3. Inject prompts via on-chain data (→ Sanitizer)
4. Exfiltrate private keys in responses (→ Isolator)
5. Act without accountability (→ Audit Logger)

**Not in scope:** Key management (use hardware wallets or secure enclaves), RPC endpoint security, or LLM model safety.

## EVM-Specific Considerations

### Base Network Support

Primary focus on Base (Coinbase's L2) with Ethereum mainnet support:

- **Base Chain ID:** 8453
- **Safe System Contracts:** WETH, USDC, DAI, AERO tokens
- **Default RPC:** `https://mainnet.base.org`
- **Gas Estimation:** Optimized for Base's lower fees

### Viem Integration

Built on [viem](https://viem.sh) for type safety and modern EVM interaction:

- Type-safe contract addresses (`Address` type)
- BigInt for precise wei calculations
- Built-in gas estimation and simulation
- Support for EIP-1559 transactions

### Contract Security

- **System Contract Allowlist:** Known-safe DeFi protocols on Base
- **Function Call Analysis:** Detects unlimited approvals (`approve(spender, type(uint256).max)`)
- **Simulation-First:** All transactions simulated before execution
- **Gas Limit Protection:** Prevents excessive gas usage

### Token Operations

Special handling for ERC-20 token operations:

- **Approval Warnings:** Flags unlimited token approvals
- **Balance Checks:** Verifies sufficient token balances
- **Transfer Validation:** Ensures valid recipient addresses
- **Decimal Handling:** Proper formatting for 6-decimal (USDC) vs 18-decimal tokens

## Deployment Patterns

### Standalone Agent

```typescript
import { AgentGuard } from '@0xaxiom/agentguard-evm';

const guard = AgentGuard.standard();
const result = await guard.checkTransaction(tx);
```

### Wrapped Agent

```typescript
import { createGuardedAgent } from '@0xaxiom/agentguard-evm/wrapper';

const agent = await createGuardedAgent(account, rpcUrl, {
  maxDailySpendEth: 1.0,
  allowedContracts: [UNISWAP_ROUTER, USDC_CONTRACT]
});

await agent.transfer('0x...', 0.1); // Automatically protected
```

### Custom Integration

```typescript
// Apply only specific protections
const sanitized = await guard.sanitizeInput(userInput);
const secrets = await guard.redactOutput(agentResponse);
```

## Performance Characteristics

- **Transaction Checks:** ~50-100ms (including simulation)
- **Input Sanitization:** ~10-20ms for typical input
- **Secret Redaction:** ~5-10ms for typical output
- **Memory Usage:** ~10MB for audit logs (configurable)
- **Network Calls:** 1-2 RPC calls per transaction check

## Configuration

Environment variables and config options:

```typescript
interface AgentGuardConfig {
  maxDailySpendEth?: number;     // ETH, not wei
  maxPerTxSpendEth?: number;     // ETH, not wei
  allowedContracts?: Address[];  // Contract whitelist
  blockedContracts?: Address[];  // Contract blacklist
  strictMode?: boolean;          // Reject any threats
  rpcUrl?: string;               // Custom RPC endpoint
  chain?: 'base' | 'mainnet';    // Target network
}
```

## Extension Points

- **Custom Patterns:** Add domain-specific injection patterns
- **Custom Contracts:** Extend system contract allowlist
- **Custom Checks:** Add application-specific security rules
- **Custom Storage:** Implement alternative audit backends
- **Custom Callbacks:** React to security events in real-time