/**
 * SecretIsolator - Prevents private keys from reaching LLM context
 */

export interface IsolatorConfig {
  redactPatterns?: RegExp[];
  allowPublicKeys?: boolean;
  placeholder?: string;
}

export interface SecretMatch {
  type: 'private_key' | 'seed_phrase' | 'api_key' | 'hex_key' | 'env_var';
  position: number;
  length: number;
  preview: string; // first/last 4 chars
}

export interface RedactResult {
  clean: string;
  redacted: boolean;
  matches: SecretMatch[];
}

// BIP39 wordlist (subset for detection)
const BIP39_COMMON = ['abandon', 'ability', 'able', 'abstract', 'absurd', 'abuse', 'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance', 'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent', 'agree', 'ahead', 'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol', 'alert', 'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter', 'always', 'amateur', 'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry', 'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique', 'anxiety', 'any', 'apart', 'apology', 'appear', 'apple', 'approve', 'april', 'arch', 'arctic', 'area', 'arena', 'argue', 'arm', 'armed', 'armor', 'army', 'around', 'arrange', 'arrest', 'arrive', 'arrow', 'art', 'artefact', 'artist', 'artwork', 'ask', 'aspect', 'assault', 'asset', 'assist', 'assume', 'asthma', 'athlete', 'atom', 'attack', 'attend', 'attitude', 'attract', 'auction', 'audit', 'august', 'aunt', 'author', 'auto', 'autumn', 'average', 'avocado', 'avoid', 'awake', 'aware', 'away', 'awesome', 'awful', 'awkward', 'axis'];

export class SecretIsolator {
  private config: Required<IsolatorConfig>;
  private patterns: RegExp[];

  constructor(config: IsolatorConfig = {}) {
    this.config = {
      redactPatterns: config.redactPatterns || [],
      allowPublicKeys: config.allowPublicKeys ?? true,
      placeholder: config.placeholder || '[REDACTED]'
    };

    // Build detection patterns
    this.patterns = [
      // EVM private key (64 hex chars)
      /\b0x[0-9a-fA-F]{64}\b/g,
      
      // Hex private key without 0x prefix (64 chars)
      /\b[0-9a-fA-F]{64}\b/g,
      
      // Seed phrases (12 or 24 words)
      new RegExp(`\\b(${BIP39_COMMON.join('|')})\\s+(${BIP39_COMMON.join('|')})(\\s+(${BIP39_COMMON.join('|')})){10,22}\\b`, 'gi'),
      
      // Common API key patterns (but shorter to avoid false positives)
      /\b[A-Za-z0-9_-]{32,64}\b/g,
      
      // Environment variable leaks
      /\b(PRIVATE_KEY|SECRET_KEY|API_KEY|AUTH_TOKEN|PASSWORD|MNEMONIC|SEED_PHRASE)\s*[=:]\s*['"]?[^\s'"]+['"]?/gi,
      
      // AWS-style keys
      /AKIA[0-9A-Z]{16}/g,
      
      // Generic long base64/hex patterns
      /[A-Za-z0-9+/]{40,}={0,2}/g,
      
      ...this.config.redactPatterns
    ];
  }

  /**
   * Check if a string looks like an EVM private key
   */
  private isLikelyPrivateKey(str: string): boolean {
    // Check if it's a 64-character hex string
    if (str.length === 64) {
      return /^[0-9a-fA-F]{64}$/.test(str);
    }
    
    // Check if it's a 0x-prefixed 64-char hex string  
    if (str.length === 66 && str.startsWith('0x')) {
      return /^0x[0-9a-fA-F]{64}$/.test(str);
    }
    
    return false;
  }

  /**
   * Check if a string looks like an EVM address (should be allowed)
   */
  private isLikelyAddress(str: string): boolean {
    // EVM addresses are 42 chars: 0x + 40 hex chars
    if (str.length === 42 && str.startsWith('0x')) {
      return /^0x[0-9a-fA-F]{40}$/.test(str);
    }
    return false;
  }

  /**
   * Redact any secrets from text
   */
  redact(text: string): RedactResult {
    const matches: SecretMatch[] = [];
    let clean = text;
    let redacted = false;

    // Check for seed phrases first (multi-word)
    const seedPhraseRegex = /\b([a-z]+\s+){11,23}[a-z]+\b/gi;
    let match;
    
    while ((match = seedPhraseRegex.exec(text)) !== null) {
      const words = match[0].toLowerCase().split(/\s+/);
      const bip39Matches = words.filter(w => BIP39_COMMON.includes(w));
      
      // If most words are BIP39, it's likely a seed phrase
      if (bip39Matches.length >= words.length * 0.8) {
        matches.push({
          type: 'seed_phrase',
          position: match.index,
          length: match[0].length,
          preview: `${words[0]}...${words[words.length - 1]}`
        });
        clean = clean.replace(match[0], this.config.placeholder);
        redacted = true;
      }
    }

    // Check for hex strings (potential keys or addresses)
    const hexRegex = /\b0x[0-9a-fA-F]{40,66}\b/g;
    while ((match = hexRegex.exec(text)) !== null) {
      const str = match[0];
      
      // Skip if it's an address and we allow those
      if (this.config.allowPublicKeys && this.isLikelyAddress(str)) {
        continue;
      }
      
      // Check if it's a private key
      if (this.isLikelyPrivateKey(str)) {
        matches.push({
          type: 'private_key',
          position: match.index,
          length: str.length,
          preview: `${str.slice(0, 6)}...${str.slice(-4)}`
        });
        clean = clean.replace(str, this.config.placeholder);
        redacted = true;
      }
    }

    // Check for bare hex keys (64 chars without 0x prefix)
    const hexKeyRegex = /\b[0-9a-fA-F]{64}\b/g;
    while ((match = hexKeyRegex.exec(text)) !== null) {
      const str = match[0];
      
      // Double-check it's likely a private key
      if (this.isLikelyPrivateKey(str)) {
        matches.push({
          type: 'hex_key',
          position: match.index,
          length: str.length,
          preview: `${str.slice(0, 4)}...${str.slice(-4)}`
        });
        clean = clean.replace(str, this.config.placeholder);
        redacted = true;
      }
    }

    // Check for env var leaks
    const envRegex = /\b(PRIVATE_KEY|SECRET_KEY|API_KEY|AUTH_TOKEN|PASSWORD|SEED_PHRASE)\s*[=:]\s*['"]?([^\s'"]+)['"]?/gi;
    while ((match = envRegex.exec(text)) !== null) {
      matches.push({
        type: 'env_var',
        position: match.index,
        length: match[0].length,
        preview: `${match[1]}=...`
      });
      clean = clean.replace(match[0], `${match[1]}=${this.config.placeholder}`);
      redacted = true;
    }

    return { clean, redacted, matches };
  }

  /**
   * Check if text contains secrets
   */
  containsSecrets(text: string): boolean {
    return this.redact(text).redacted;
  }

  /**
   * Wrap a function to auto-redact string outputs
   */
  wrapOutput<T>(fn: () => T): T {
    const result = fn();
    
    if (typeof result === 'string') {
      return this.redact(result).clean as T;
    }
    
    if (typeof result === 'object' && result !== null) {
      return JSON.parse(
        this.redact(JSON.stringify(result)).clean
      ) as T;
    }
    
    return result;
  }
}
