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

// Base58 alphabet for Solana keys
const BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

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
      // Solana private key (Base58, 88 chars) - starts with specific chars
      /[1-9A-HJ-NP-Za-km-z]{87,88}/g,
      
      // Hex private key (64 chars)
      /\b[0-9a-fA-F]{64}\b/g,
      
      // Seed phrases (12 or 24 words)
      new RegExp(`\\b(${BIP39_COMMON.join('|')})\\s+(${BIP39_COMMON.join('|')})(\\s+(${BIP39_COMMON.join('|')})){10,22}\\b`, 'gi'),
      
      // Common API key patterns
      /\b[A-Za-z0-9_-]{32,}\b/g,
      
      // Environment variable leaks
      /\b(PRIVATE_KEY|SECRET_KEY|API_KEY|AUTH_TOKEN|PASSWORD)\s*[=:]\s*['"]?[^\s'"]+['"]?/gi,
      
      // AWS-style keys
      /AKIA[0-9A-Z]{16}/g,
      
      // Generic long base64
      /[A-Za-z0-9+/]{40,}={0,2}/g,
      
      ...this.config.redactPatterns
    ];
  }

  /**
   * Check if a string looks like a Solana private key
   */
  private isLikelyPrivateKey(str: string): boolean {
    // Check length (Solana private keys are 88 chars in Base58)
    if (str.length !== 88 && str.length !== 87) return false;
    
    // Check all chars are Base58
    for (const char of str) {
      if (!BASE58_CHARS.includes(char)) return false;
    }
    
    return true;
  }

  /**
   * Check if a string looks like a public key (44 chars)
   */
  private isLikelyPublicKey(str: string): boolean {
    if (str.length !== 44 && str.length !== 43) return false;
    for (const char of str) {
      if (!BASE58_CHARS.includes(char)) return false;
    }
    return true;
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

    // Check for Base58 strings (potential keys)
    const base58Regex = /[1-9A-HJ-NP-Za-km-z]{40,90}/g;
    while ((match = base58Regex.exec(text)) !== null) {
      const str = match[0];
      
      // Skip if it's a public key and we allow those
      if (this.config.allowPublicKeys && this.isLikelyPublicKey(str)) {
        continue;
      }
      
      // Check if it's a private key
      if (this.isLikelyPrivateKey(str)) {
        matches.push({
          type: 'private_key',
          position: match.index,
          length: str.length,
          preview: `${str.slice(0, 4)}...${str.slice(-4)}`
        });
        clean = clean.replace(str, this.config.placeholder);
        redacted = true;
      }
    }

    // Check for hex keys
    const hexKeyRegex = /\b[0-9a-fA-F]{64}\b/g;
    while ((match = hexKeyRegex.exec(text)) !== null) {
      matches.push({
        type: 'hex_key',
        position: match.index,
        length: match[0].length,
        preview: `${match[0].slice(0, 4)}...${match[0].slice(-4)}`
      });
      clean = clean.replace(match[0], this.config.placeholder);
      redacted = true;
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
