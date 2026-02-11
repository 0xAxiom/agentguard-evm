# Security Policy

## 🛡️ Threat Model

AgentGuard EVM protects AI agents operating on EVM-compatible blockchains (Base, Ethereum) against:

### Primary Threats

1. **Fund Drainage** — Malicious actors draining agent wallets through excessive transfers or transactions
2. **Prompt Injection** — Manipulating LLM behavior through crafted on-chain data or user input
3. **Secret Exfiltration** — Tricking agents into revealing private keys, seed phrases, or API keys
4. **Malicious Contracts** — Interactions with drainer contracts, honeypots, or exploits
5. **Social Engineering** — Manipulating agents through conversation to bypass security

### Out of Scope

- **Key Management** — Use hardware wallets, HSMs, or secure key derivation
- **LLM Model Security** — Model poisoning, training data attacks
- **RPC/Network Security** — Node compromise, man-in-the-middle attacks
- **Smart Contract Bugs** — Vulnerabilities in target contracts themselves

## 🚨 Reporting Vulnerabilities

**Critical:** Do NOT open public issues for security vulnerabilities.

### Responsible Disclosure Process

1. **Email:** axiombot@proton.me
2. **Subject:** "SECURITY: AgentGuard EVM Vulnerability"
3. **Include:**
   - Detailed description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if known)

### Response Timeline

- **24 hours:** Acknowledgment of report
- **7 days:** Initial assessment and triage  
- **30 days:** Patch development and testing
- **90 days:** Public disclosure (or coordinated disclosure)

### Scope for Vulnerability Reports

**In Scope:**
- Security bypasses in spending limits
- Prompt injection filter evasion
- Secret detection circumvention
- Authorization/access control issues
- Denial of service vulnerabilities

**Out of Scope:**
- Issues requiring malicious RPC endpoints
- Vulnerabilities in dependencies (report upstream)
- Features working as designed
- Performance issues without security impact

## 🔐 Security Features

### Transaction Security

**Spending Limits**
- Daily and per-transaction ETH limits
- Automatic daily reset based on UTC time
- Cumulative tracking across all transactions
- Protection against rapid-fire attacks

**Contract Security**
- Allowlist/blocklist for contract addresses  
- System contract recognition (WETH, USDC, etc.)
- Runtime modification of lists
- Simulation-based validation

**Transaction Simulation**
- Pre-execution via `eth_call`
- Gas estimation and validation
- Revert detection and analysis
- Balance change prediction

### Input Security

**Prompt Injection Detection**
- 30+ injection patterns (instruction override, role impersonation)
- Unicode attack prevention (zero-width, RTL override)
- Encoding attack detection (Base64, hex)
- Delimiter injection protection

**Content Sanitization**
- Dangerous character removal
- Markdown stripping (configurable)
- Length limiting with truncation
- Whitespace normalization

### Output Security

**Secret Detection**
- EVM private keys (0x-prefixed 64-char hex)
- BIP39 seed phrases (12/24 words)
- Environment variable leaks
- API key patterns
- Custom secret patterns

**Redaction**
- Configurable placeholder text
- Position-aware replacement
- Multiple secret handling
- False positive minimization

### Audit Security

**Comprehensive Logging**
- All security decisions logged
- Tamper-evident audit trail
- Multiple storage backends
- Structured event format

**Privacy Protection**
- Sensitive data excluded from logs
- Configurable detail levels
- Log rotation and retention
- Export capabilities

## ⚙️ Security Configuration

### Recommended Settings

**Production Agents**
```typescript
const guard = AgentGuard.strict('https://mainnet.base.org');
// - 0.5 ETH daily limit
// - 0.05 ETH per-transaction limit  
// - Strict mode enabled
// - Full audit logging
```

**Development/Testing**
```typescript
const guard = AgentGuard.standard();
// - 1 ETH daily limit
// - 0.1 ETH per-transaction limit
// - Warnings only
// - Memory-based audit
```

**Custom Configuration**
```typescript
const guard = new AgentGuard({
  maxDailySpendEth: 0.1,           // Conservative limit
  maxPerTxSpendEth: 0.01,          // Small transactions only
  allowedContracts: [USDC_ADDR],   // Only known contracts
  strictMode: true,                // Reject any threats
  audit: { 
    storage: 'file',
    filePath: './security-audit.json'
  }
});
```

### Security Levels

| Level | Daily Limit | Tx Limit | Strict Mode | Use Case |
|-------|-------------|----------|-------------|----------|
| **Minimal** | 0.01 ETH | 0.001 ETH | Yes | Testing/Demo |
| **Conservative** | 0.1 ETH | 0.01 ETH | Yes | Production Agents |
| **Standard** | 1 ETH | 0.1 ETH | No | Development |
| **High** | 10 ETH | 1 ETH | No | Trading Agents |

## 🎯 Attack Scenarios

### Scenario 1: Fund Drainage via Social Engineering

**Attack:** User convinces agent to "send a small test transaction" repeatedly

**Protection:**
- Daily spending limits prevent total drainage
- Per-transaction limits reduce individual impact
- Audit logging captures suspicious patterns
- Manual reset required to exceed daily limits

### Scenario 2: Prompt Injection via NFT Metadata

**Attack:** Malicious NFT with metadata containing prompt injection

**Protection:**
- Input sanitization processes all external data
- Unicode attack prevention
- Injection pattern detection
- Configurable strict mode rejection

### Scenario 3: Private Key Exfiltration

**Attack:** Agent asked to "debug transaction by showing private key"

**Protection:**
- Output scanning detects private key patterns
- Automatic redaction with placeholder
- Multiple secret type detection
- Context-aware filtering

### Scenario 4: Malicious Contract Interaction

**Attack:** Tricking agent into approving tokens to drainer contract

**Protection:**
- Contract allowlist/blocklist enforcement
- Transaction simulation detects failures
- Unlimited approval warnings
- Runtime contract blocking

### Scenario 5: Encoding Attack

**Attack:** Base64-encoded malicious instructions in transaction memo

**Protection:**
- Automatic Base64 detection and decoding
- Recursive content scanning
- Nested encoding prevention
- Suspicious pattern flagging

## 🔒 Cryptographic Security

### Randomness
- No cryptographic operations performed
- Relies on OS randomness for audit IDs
- No custom crypto implementations

### Data Handling
- Secrets redacted, never stored
- Audit logs contain no sensitive data
- In-memory secrets cleared promptly
- File permissions restricted where applicable

## 🚀 Security Updates

### Update Policy
- **Critical:** Immediate patch release
- **High:** Within 7 days
- **Medium:** Next minor release  
- **Low:** Next major release

### Update Verification
- All releases signed with GPG
- Checksums provided for verification
- Changelog documents security fixes
- Breaking changes clearly marked

### Dependency Security
- Regular dependency updates
- Automated vulnerability scanning
- Minimal dependency surface
- Trusted package sources only

## 📊 Security Metrics

Track these metrics for security posture:

```typescript
const stats = await guard.getStats();

// Key security indicators
const metrics = {
  transactionCheckRate: stats.transactionChecks / stats.totalRequests,
  blockRate: stats.blockedTransactions / stats.transactionChecks,
  threatDetectionRate: stats.threatsDetected / stats.sanitizations,
  secretRedactionRate: stats.secretsRedacted / stats.redactions
};
```

## 🛠️ Security Best Practices

### For Agent Developers

1. **Use Conservative Limits** — Start with strict settings and relax as needed
2. **Monitor Audit Logs** — Regular review for unusual patterns
3. **Test Attack Scenarios** — Use examples in `/examples/` to verify protection
4. **Keep Updated** — Apply security updates promptly
5. **Validate Configuration** — Ensure settings match risk tolerance

### For Production Deployments

1. **File-Based Auditing** — Persistent audit trail
2. **Limit Runtime Changes** — Restrict firewall modifications
3. **Monitor Spending** — Alert on unusual transaction patterns
4. **Regular Backup** — Audit logs for forensic analysis
5. **Incident Response** — Plan for security event handling

### For High-Value Agents

1. **Hardware Security** — Use hardware wallets for key storage
2. **Multi-Sig** — Require multiple approvals for large transactions
3. **Time Delays** — Add delays for large or unusual transactions
4. **Human Oversight** — Require approval for sensitive operations
5. **Network Isolation** — Dedicated RPC endpoints and monitoring

## 🆘 Security Incident Response

### If You Suspect a Bypass

1. **Stop Operations** — Pause agent activity immediately
2. **Preserve Evidence** — Export audit logs before investigation
3. **Assess Impact** — Check wallet balances and transaction history
4. **Report Issue** — Follow vulnerability reporting process
5. **Implement Workarounds** — Increase security settings if possible

### Recovery Procedures

1. **Wallet Security** — Rotate keys if compromise suspected
2. **Update Configuration** — Tighten security settings
3. **Apply Patches** — Install security updates immediately  
4. **Review Audit** — Analyze logs for attack patterns
5. **Document Lessons** — Update incident response procedures

## 📚 Additional Resources

- **OWASP AI Security:** https://owasp.org/www-project-ai-security-and-privacy-guide/
- **NIST AI Risk Framework:** https://www.nist.gov/itl/ai-risk-management-framework
- **EVM Security Best Practices:** https://consensys.github.io/smart-contract-best-practices/

---

**Remember: Security is a process, not a product. Stay vigilant! 🛡️**