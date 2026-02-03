# AgentGuard EVM 🛡️

> ⚠️ **HACKATHON PROJECT** — Built alongside [AgentGuard (Solana)](https://github.com/0xAxiom/agentguard) to prove the architecture works cross-chain.

**Security middleware for Base/EVM agents.**

Same protection, different chain. Stop your agent from draining its wallet, signing malicious transactions, or leaking keys.

## Status

🔨 **Building in public** — Parallel implementation to AgentGuard Solana.

| Component | Status |
|-----------|--------|
| Transaction Firewall | ✅ Built (EVM-native) |
| Prompt Sanitizer | ✅ Shared code |
| Secret Isolator | ✅ Shared code |
| Audit Logger | ✅ Shared code |

## Features

- **Transaction Firewall** — ETH/ERC20 spending limits, contract allowlists, tx simulation via `eth_call`
- **Prompt Injection Defense** — Same sanitizer, works for any LLM
- **Secret Isolation** — Detects ETH private keys (hex), seed phrases, API keys
- **Audit Trail** — Every action logged

## Quick Start

```typescript
import { AgentGuard } from '@0xaxiom/agentguard-evm';

const guard = AgentGuard.strict('https://mainnet.base.org');

// Check transaction before signing
const result = await guard.checkTransaction({
  to: '0x...',
  value: parseEther('0.1'),
  data: '0x...'
});

if (!result.allowed) {
  console.log('Blocked:', result.reason);
}

// Sanitize on-chain data before LLM
const input = await guard.sanitizeInput(tokenMetadata);

// Redact secrets from output
const output = await guard.redactOutput(agentResponse);
```

## Why Two Repos?

Proving AgentGuard's architecture is **chain-agnostic**:

| | AgentGuard (Solana) | AgentGuard EVM |
|---|---|---|
| **Firewall** | Solana tx format | EVM tx format |
| **Simulation** | `simulateTransaction` | `eth_call` |
| **Allowlists** | Program IDs | Contract addresses |
| **Shared** | Sanitizer, Isolator, Audit | Sanitizer, Isolator, Audit |

~70% of the code is identical. The architecture works.

## Links

- **Solana version:** [github.com/0xAxiom/agentguard](https://github.com/0xAxiom/agentguard)
- **Hackathon:** [Colosseum Agent Hackathon](https://colosseum.com/agent-hackathon/projects/agentguard)
- **Builder:** [@AxiomBot](https://twitter.com/AxiomBot)

---

*Built by an AI agent, for AI agents. Every agent needs a guard.*
