# Contributing to AgentGuard EVM

Thank you for your interest in contributing to AgentGuard EVM! This document provides guidelines for contributing to this security-focused library.

## 🛡️ Security First

AgentGuard EVM is a **security library**. All contributions must be thoroughly reviewed with security in mind:

- **No security regressions** — New features cannot weaken existing protections
- **Defense in depth** — Multiple independent checks are better than one perfect check  
- **Fail secure** — When in doubt, block the operation
- **Audit everything** — All security decisions must be logged

## 📋 Development Setup

### Prerequisites

- Node.js 18+ and npm/yarn
- TypeScript 5.0+
- Basic understanding of EVM/Ethereum
- Familiarity with viem library

### Setup

```bash
# Clone and install
git clone https://github.com/0xAxiom/agentguard-evm.git
cd agentguard-evm
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Type checking
npm run type-check

# Linting
npm run lint
npm run lint:fix
```

### Project Structure

```
src/
├── guard.ts           # Main AgentGuard class
├── index.ts           # Public API exports
├── firewall/          # Transaction protection
│   ├── index.ts       # Main firewall class
│   ├── allowlist.ts   # Contract allowlist/blocklist
│   ├── limits.ts      # Spending limits
│   └── simulator.ts   # Transaction simulation
├── sanitizer/         # Input sanitization
│   ├── index.ts       # Main sanitizer class
│   ├── patterns.ts    # Threat detection patterns
│   └── cleaner.ts     # Text cleaning utilities
├── isolator/          # Secret protection
│   └── index.ts       # Secret detection and redaction
├── audit/             # Security logging
│   └── index.ts       # Audit logger
└── wrapper/           # Agent wrapper
    └── index.ts       # Guarded agent wrapper

tests/                 # Comprehensive test suite
examples/              # Usage examples
```

## 🧪 Testing Requirements

All contributions must include comprehensive tests:

### Test Coverage
- **Minimum 90% line coverage** for new code
- **100% coverage** for security-critical paths
- **Edge cases** and error conditions must be tested
- **Performance tests** for operations that might be slow

### Test Categories
1. **Unit Tests** — Test individual functions in isolation
2. **Integration Tests** — Test module interactions
3. **Security Tests** — Test attack scenarios and edge cases
4. **Performance Tests** — Ensure operations complete quickly

### Running Tests

```bash
# All tests
npm test

# Specific test file
npx vitest tests/firewall.test.ts

# Watch mode
npx vitest --watch

# Coverage report
npm run test:coverage
```

### Test Conventions

```typescript
describe('FeatureName', () => {
  describe('security scenarios', () => {
    it('blocks malicious input X', () => {
      // Test that threats are caught
    });
    
    it('allows legitimate input Y', () => {
      // Test that normal usage works
    });
  });
  
  describe('edge cases', () => {
    it('handles empty input gracefully', () => {
      // Test boundary conditions
    });
  });
});
```

## 🔒 Security Contributions

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities. Instead:

1. Email: axiombot@proton.me with subject "AgentGuard EVM Security"
2. Include detailed reproduction steps
3. Suggest a fix if possible
4. Allow 90 days for response and fix

### Security Features

When adding new security features:

1. **Threat Model** — Document what attacks this prevents
2. **False Positives** — Minimize interference with legitimate usage  
3. **Performance** — Security checks must be fast (<100ms typical)
4. **Bypass Resistance** — Consider how attackers might circumvent
5. **Configuration** — Allow tuning for different risk profiles

### Security Review Checklist

- [ ] Are all inputs validated?
- [ ] Are all outputs sanitized?
- [ ] Does this maintain existing security guarantees?
- [ ] Could this be bypassed by changing input encoding?
- [ ] Are error messages safe (no information leakage)?
- [ ] Is the performance impact acceptable?
- [ ] Are there adequate tests for attack scenarios?

## 📝 Code Style

### TypeScript Guidelines

```typescript
// Use strict types
interface StrictConfig {
  maxSpend: bigint;           // Use bigint for wei amounts
  contracts: Address[];       // Use Address type for addresses
  enabled: boolean;           // Explicit boolean
}

// Prefer immutable patterns
const config: StrictConfig = {
  ...userConfig,
  maxSpend: parseEther(userConfig.maxSpendEth.toString())
};

// Handle errors explicitly
try {
  const result = await riskyOperation();
  return { success: true, data: result };
} catch (error: any) {
  return { success: false, error: error.message };
}
```

### Naming Conventions

- **Functions:** `checkTransaction`, `sanitizeInput` (verb + noun)
- **Classes:** `TransactionFirewall`, `PromptSanitizer` (PascalCase)
- **Constants:** `SAFE_SYSTEM_CONTRACTS`, `MAX_GAS_LIMIT` (SCREAMING_SNAKE_CASE)
- **Files:** `allowlist.ts`, `simulator.ts` (kebab-case)

### Comments and Documentation

```typescript
/**
 * Check if a transaction is allowed through all security layers
 * 
 * @param tx - Transaction to validate
 * @param action - Human-readable action name for audit logs
 * @returns Security decision with detailed reasoning
 * 
 * @example
 * ```typescript
 * const result = await guard.checkTransaction(tx, 'token_swap');
 * if (!result.allowed) {
 *   console.log('Blocked:', result.reason);
 * }
 * ```
 */
async checkTransaction(tx: TransactionRequest, action?: string): Promise<GuardResult>
```

## 🚀 Feature Development

### Adding New Security Features

1. **Research** — Understand the threat and existing mitigations
2. **Design** — Plan the detection logic and integration points
3. **Implement** — Write code following security best practices  
4. **Test** — Comprehensive test coverage including attack scenarios
5. **Document** — Update README and architecture docs
6. **Review** — Security-focused code review process

### Adding EVM Chain Support

To add support for new EVM chains:

1. **Add chain config** in `src/firewall/simulator.ts`
2. **Update system contracts** in `src/firewall/allowlist.ts`
3. **Add RPC endpoints** and chain-specific optimizations
4. **Test with chain-specific scenarios**
5. **Document new chain support**

### Performance Guidelines

- **Transaction checks** should complete in <100ms
- **Input sanitization** should complete in <50ms  
- **Secret redaction** should complete in <50ms
- **Memory usage** should be reasonable (avoid large regexes)
- **Use lazy loading** for expensive operations

## 📖 Documentation

### README Updates

When adding features, update the main README:

- Add to feature list with security benefit explanation
- Update code examples if API changes
- Add new configuration options to table
- Update performance characteristics if changed

### Architecture Documentation

Major changes require `ARCHITECTURE.md` updates:

- New modules or significant refactoring
- Changes to security model or threat coverage
- New extension points or integration patterns
- Performance characteristics changes

## 🔄 Pull Request Process

### Before Opening a PR

1. **Issue Discussion** — For major features, open an issue first
2. **Branch Naming** — Use `feature/description` or `security/fix-name`
3. **Commits** — Clear, atomic commits with conventional commit format
4. **Tests** — All tests pass with adequate coverage
5. **Documentation** — Updated as needed

### PR Template

```markdown
## Description
Brief description of changes and motivation.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that changes existing API)
- [ ] Security improvement
- [ ] Documentation update

## Security Impact
Describe how this affects the security posture:
- What new threats does this address?
- Could this introduce new vulnerabilities?
- Are existing protections maintained?

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated  
- [ ] Security scenarios tested
- [ ] Performance impact measured

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Tests pass locally
- [ ] No security regressions
```

### Review Process

1. **Automated Checks** — CI must pass (tests, linting, type-checking)
2. **Security Review** — Focus on security implications
3. **Code Review** — Style, architecture, performance
4. **Testing Review** — Verify test coverage and quality
5. **Documentation Review** — Ensure docs are accurate and complete

## 🏆 Recognition

Contributors will be recognized in:

- `CONTRIBUTORS.md` file
- Release notes for significant contributions
- Special recognition for security improvements

## 💬 Community

- **Discussions:** Use GitHub Discussions for questions
- **Issues:** Bug reports and feature requests
- **Security:** Private disclosure for vulnerabilities

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for helping make EVM agents more secure! 🛡️**