/**
 * PromptSanitizer - Defense against prompt injection attacks
 * 
 * Designed for Solana agents that process on-chain data (token metadata,
 * NFT descriptions, memo fields) which can contain malicious prompts.
 */

import { 
  ALL_INJECTION_PATTERNS, 
  UNICODE_PATTERNS, 
  SUSPICIOUS_STRINGS,
  InjectionPattern 
} from './patterns';
import { 
  stripDangerousUnicode, 
  stripMarkdown, 
  normalizeWhitespace,
  truncate,
  looksLikeBase64,
  decodeBase64
} from './cleaner';

/**
 * Configuration options for the sanitizer
 */
export interface SanitizerConfig {
  /** Reject any content with detected threats (default: false) */
  strictMode?: boolean;
  /** Remove markdown formatting (default: false) */
  stripMarkdown?: boolean;
  /** Maximum length for input text (default: 10000) */
  maxLength?: number;
  /** Additional regex patterns to detect */
  customPatterns?: RegExp[];
  /** Minimum severity to report (default: 'low') */
  minSeverity?: 'low' | 'medium' | 'high';
  /** Decode and scan Base64 content (default: true) */
  scanBase64?: boolean;
}

/**
 * Information about a detected threat
 */
export interface ThreatDetection {
  type: 'injection' | 'unicode' | 'overflow' | 'encoding' | 'suspicious';
  pattern: string;
  position: number;
  severity: 'low' | 'medium' | 'high';
  description?: string;
  matched?: string;
}

/**
 * Result of sanitization
 */
export interface SanitizeResult {
  /** Sanitized output text */
  clean: string;
  /** Original input text */
  original: string;
  /** Detected threats */
  threats: ThreatDetection[];
  /** Whether the input was modified */
  modified: boolean;
  /** Whether the content is safe (no high-severity threats) */
  safe: boolean;
  /** Whether content was rejected in strict mode */
  rejected: boolean;
}

const SEVERITY_LEVELS = { low: 1, medium: 2, high: 3 };

/**
 * Main sanitizer class for defending against prompt injection
 */
export class PromptSanitizer {
  private config: Required<SanitizerConfig>;
  private customPatterns: InjectionPattern[];

  constructor(config: SanitizerConfig = {}) {
    this.config = {
      strictMode: config.strictMode ?? false,
      stripMarkdown: config.stripMarkdown ?? false,
      maxLength: config.maxLength ?? 10000,
      customPatterns: config.customPatterns ?? [],
      minSeverity: config.minSeverity ?? 'low',
      scanBase64: config.scanBase64 ?? true
    };

    // Convert custom RegExp patterns to InjectionPattern format
    this.customPatterns = this.config.customPatterns.map((pattern, i) => ({
      name: `custom_${i}`,
      pattern,
      severity: 'medium' as const,
      description: 'Custom pattern'
    }));
  }

  /**
   * Main sanitization method
   */
  sanitize(input: string): SanitizeResult {
    if (typeof input !== 'string') {
      throw new Error('Input must be a string');
    }

    const threats: ThreatDetection[] = [];
    let clean = input;

    // 1. Check for overflow (length-based attack)
    if (input.length > this.config.maxLength) {
      threats.push({
        type: 'overflow',
        pattern: 'length_exceeded',
        position: this.config.maxLength,
        severity: 'medium',
        description: `Input exceeds max length (${input.length} > ${this.config.maxLength})`
      });
      clean = truncate(clean, this.config.maxLength);
    }

    // 2. Detect dangerous unicode
    this.detectUnicode(input, threats);
    clean = stripDangerousUnicode(clean);

    // 3. Detect injection patterns
    this.detectInjectionPatterns(input, threats);

    // 4. Detect suspicious strings
    this.detectSuspiciousStrings(input, threats);

    // 5. Scan Base64 content if enabled
    if (this.config.scanBase64) {
      this.scanBase64Content(input, threats);
    }

    // 6. Strip markdown if configured
    if (this.config.stripMarkdown) {
      clean = stripMarkdown(clean);
    }

    // 7. Normalize whitespace
    clean = normalizeWhitespace(clean);

    // Filter threats by minimum severity
    const minLevel = SEVERITY_LEVELS[this.config.minSeverity];
    const filteredThreats = threats.filter(
      t => SEVERITY_LEVELS[t.severity] >= minLevel
    );

    // Determine safety
    const hasHighSeverity = filteredThreats.some(t => t.severity === 'high');
    const safe = !hasHighSeverity;
    
    // In strict mode, reject if any threats found
    const rejected = this.config.strictMode && filteredThreats.length > 0;

    return {
      clean: rejected ? '' : clean,
      original: input,
      threats: filteredThreats,
      modified: clean !== input,
      safe,
      rejected
    };
  }

  /**
   * Quick check if content is safe
   */
  isSafe(input: string): boolean {
    const result = this.sanitize(input);
    return result.safe;
  }

  /**
   * Get threats without sanitizing
   */
  analyze(input: string): ThreatDetection[] {
    const result = this.sanitize(input);
    return result.threats;
  }

  /**
   * Detect dangerous unicode sequences
   */
  private detectUnicode(text: string, threats: ThreatDetection[]): void {
    const unicodeChecks: Array<{
      pattern: RegExp;
      name: string;
      severity: 'low' | 'medium' | 'high';
    }> = [
      { pattern: UNICODE_PATTERNS.ZERO_WIDTH, name: 'zero_width_chars', severity: 'high' },
      { pattern: UNICODE_PATTERNS.RTL_OVERRIDE, name: 'rtl_override', severity: 'high' },
      { pattern: UNICODE_PATTERNS.CONTROL_CHARS, name: 'control_chars', severity: 'medium' },
      { pattern: UNICODE_PATTERNS.PRIVATE_USE, name: 'private_use_chars', severity: 'medium' },
      { pattern: UNICODE_PATTERNS.TAG_CHARS, name: 'tag_chars', severity: 'high' },
      { pattern: UNICODE_PATTERNS.COMBINING_ABUSE, name: 'combining_abuse', severity: 'low' }
    ];

    for (const check of unicodeChecks) {
      const matches = text.matchAll(new RegExp(check.pattern.source, check.pattern.flags));
      for (const match of matches) {
        threats.push({
          type: 'unicode',
          pattern: check.name,
          position: match.index ?? 0,
          severity: check.severity,
          description: `Dangerous unicode: ${check.name}`,
          matched: match[0].slice(0, 20)
        });
        // Only report first instance of each type
        break;
      }
    }
  }

  /**
   * Detect prompt injection patterns
   */
  private detectInjectionPatterns(text: string, threats: ThreatDetection[]): void {
    const allPatterns = [...ALL_INJECTION_PATTERNS, ...this.customPatterns];
    
    for (const { name, pattern, severity, description } of allPatterns) {
      // Reset regex state
      pattern.lastIndex = 0;
      
      const matches = text.matchAll(new RegExp(pattern.source, pattern.flags));
      for (const match of matches) {
        threats.push({
          type: 'injection',
          pattern: name,
          position: match.index ?? 0,
          severity,
          description,
          matched: match[0].slice(0, 50)
        });
        // Only report first match per pattern
        break;
      }
    }
  }

  /**
   * Detect suspicious string literals
   */
  private detectSuspiciousStrings(text: string, threats: ThreatDetection[]): void {
    const lowerText = text.toLowerCase();
    
    for (const suspicious of SUSPICIOUS_STRINGS) {
      const lowerSuspicious = suspicious.toLowerCase();
      const pos = lowerText.indexOf(lowerSuspicious);
      
      if (pos !== -1) {
        threats.push({
          type: 'suspicious',
          pattern: 'suspicious_string',
          position: pos,
          severity: 'high',
          description: 'Suspicious prompt structure string',
          matched: suspicious
        });
      }
    }
  }

  /**
   * Scan Base64 encoded content for hidden payloads
   */
  private scanBase64Content(text: string, threats: ThreatDetection[]): void {
    // Find potential Base64 strings
    const base64Regex = /(?:[A-Za-z0-9+\/]{4}){5,}(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?/g;
    const matches = text.matchAll(base64Regex);

    for (const match of matches) {
      const potential = match[0];
      
      if (looksLikeBase64(potential)) {
        const decoded = decodeBase64(potential);
        
        if (decoded) {
          // Recursively check decoded content for threats
          const decodedThreats: ThreatDetection[] = [];
          this.detectInjectionPatterns(decoded, decodedThreats);
          this.detectSuspiciousStrings(decoded, decodedThreats);
          
          if (decodedThreats.length > 0) {
            threats.push({
              type: 'encoding',
              pattern: 'base64_hidden_payload',
              position: match.index ?? 0,
              severity: 'high',
              description: `Base64 encoded injection attempt: ${decodedThreats[0].pattern}`,
              matched: decoded.slice(0, 50)
            });
          } else {
            // Still flag as suspicious even if no known patterns
            threats.push({
              type: 'encoding',
              pattern: 'base64_content',
              position: match.index ?? 0,
              severity: 'low',
              description: 'Base64 encoded content detected',
              matched: decoded.slice(0, 30)
            });
          }
        }
      }
    }
  }

  /**
   * Create a sanitizer with strict settings for high-security contexts
   */
  static strict(): PromptSanitizer {
    return new PromptSanitizer({
      strictMode: true,
      stripMarkdown: true,
      maxLength: 1000,
      minSeverity: 'low',
      scanBase64: true
    });
  }

  /**
   * Create a sanitizer with relaxed settings for lower-risk contexts
   */
  static relaxed(): PromptSanitizer {
    return new PromptSanitizer({
      strictMode: false,
      stripMarkdown: false,
      maxLength: 50000,
      minSeverity: 'high',
      scanBase64: false
    });
  }
}

// Export everything
export { 
  ALL_INJECTION_PATTERNS,
  INSTRUCTION_OVERRIDE_PATTERNS,
  PROMPT_LEAKAGE_PATTERNS,
  CRYPTO_INJECTION_PATTERNS,
  UNICODE_PATTERNS,
  ENCODING_PATTERNS,
  SUSPICIOUS_STRINGS,
  InjectionPattern
} from './patterns';

export {
  stripDangerousUnicode,
  stripMarkdown,
  stripZeroWidth,
  stripRTLOverride,
  normalizeWhitespace,
  truncate,
  looksLikeBase64,
  decodeBase64,
  containsEVMAddress,
  extractEVMAddresses,
  containsPrivateKey,
  fullClean
} from './cleaner';
